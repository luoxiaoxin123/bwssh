using System.Runtime.InteropServices;
using BwSshAgent.Core;
using BwSshAgent.Core.Approval;
using BwSshAgent.Core.Audit;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Settings;
using BwSshAgent.Core.Ssh;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace BwSshAgent.App.Services;

/// <summary>Owns all long-lived services. Lives on the UI thread; the window is created on demand.</summary>
public sealed class AppHost
{
    private MainWindow? _mainWindow;
    private Timer? _minuteTimer;
    private DateTimeOffset _lastSyncAttempt = DateTimeOffset.MinValue;
    private bool _exiting;

    private AppHost(DispatcherQueue dispatcher)
    {
        Dispatcher = dispatcher;
        Settings = AppSettings.Load();
        Session = new VaultSession();
        Accounts = new AccountManager(Session);
        Audit = new AuditLog();
        Agent = new AgentService(Session, () => Settings, Audit);
        Pipe = new AgentPipeServer(Agent, Settings.PipeName);
        Toasts = new ToastPresenter(this);
        Tray = new TrayIcon(this);
    }

    public static AppHost? Current { get; private set; }

    public DispatcherQueue Dispatcher { get; }
    public AppSettings Settings { get; }
    public VaultSession Session { get; }
    public AccountManager Accounts { get; }
    public AuditLog Audit { get; }
    public AgentService Agent { get; }
    public AgentPipeServer Pipe { get; }
    public ToastPresenter Toasts { get; }
    public TrayIcon Tray { get; }

    /// <summary>Raised on the UI thread whenever anything shown in the UI may have changed.</summary>
    public event Action? StateChanged;

    public static void Start(bool background)
    {
        var host = new AppHost(DispatcherQueue.GetForCurrentThread());
        Current = host;
        host.Initialize(background);
    }

    private void Initialize(bool background)
    {
        Log.Info($"Starting bwssh (background={background})");
        Session.Initialize();
        Audit.Cleanup();
        Agent.Presenter = Toasts;
        Toasts.Register();
        Tray.Create();

        Session.Changed += RaiseStateChanged;
        Session.Unlocked += OnUnlocked;
        Session.Pin.Changed += RaiseStateChanged;
        Session.Hello.Changed += RaiseStateChanged;
        Accounts.SyncStateChanged += RaiseStateChanged;
        Agent.GrantsChanged += RaiseStateChanged;
        Pipe.StateChanged += RaiseStateChanged;
        Tray.SessionLocked += () => LockIf(Settings.LockOnSystemLock, L.T("系统锁屏", "system lock"));
        Tray.Suspending += () => LockIf(Settings.LockOnSleep, L.T("系统睡眠", "system sleep"));

        Pipe.Start();
        try
        {
            AutoStart.RefreshPath();
        }
        catch (Exception ex)
        {
            Log.Error("Auto start refresh failed", ex);
        }

        _minuteTimer = new Timer(_ => Dispatcher.TryEnqueue(OnTimer), null, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(30));
        if (Session.State != VaultState.LoggedOut)
        {
            _ = SyncNowAsync();
        }

        if (background)
        {
            _ = TrimMemoryLaterAsync();
        }
        else
        {
            ShowMainWindow();
        }
    }

    public void OnRedirectedActivation() => Dispatcher.TryEnqueue(() => ShowMainWindow());

    public void ShowMainWindow()
    {
        if (_exiting)
        {
            return;
        }
        if (_mainWindow == null)
        {
            _mainWindow = new MainWindow(this);
            _mainWindow.Closed += (_, _) =>
            {
                _mainWindow = null;
                _ = TrimMemoryLaterAsync();
            };
        }
        _mainWindow.BringToFront();
    }

    public void SaveSettings()
    {
        try
        {
            Settings.Save();
        }
        catch (Exception ex)
        {
            Log.Error("Saving settings failed", ex);
        }
        RaiseStateChanged();
    }

    public async Task ApplyPipeNameAsync(string pipeName)
    {
        Settings.PipeName = pipeName;
        SaveSettings();
        await Pipe.RestartAsync(Settings.PipeName);
    }

    public async Task<bool> SyncNowAsync()
    {
        _lastSyncAttempt = DateTimeOffset.Now;
        return await Accounts.SyncAsync();
    }

    public void Lock(string reason) => Session.Lock(reason);

    private void LockIf(bool enabled, string reason)
    {
        if (enabled)
        {
            Session.Lock(reason);
        }
    }

    private void OnUnlocked()
    {
        RaiseStateChanged();
        if (DateTimeOffset.Now - _lastSyncAttempt > TimeSpan.FromMinutes(1))
        {
            Dispatcher.TryEnqueue(() => _ = SyncNowAsync());
        }
    }

    private void OnTimer()
    {
        if (Settings.LockAfterIdleMinutes > 0 && Session.State == VaultState.Unlocked &&
            IdleTime() >= TimeSpan.FromMinutes(Settings.LockAfterIdleMinutes))
        {
            Session.Lock(L.T($"空闲 {Settings.LockAfterIdleMinutes} 分钟", $"idle for {Settings.LockAfterIdleMinutes} min"));
        }

        if (Settings.SyncIntervalMinutes > 0 && Session.State != VaultState.LoggedOut && !Accounts.Syncing &&
            DateTimeOffset.Now - _lastSyncAttempt >= TimeSpan.FromMinutes(Settings.SyncIntervalMinutes))
        {
            _ = SyncNowAsync();
        }

        // Keeps grant countdowns fresh in the UI.
        if (_mainWindow != null && Agent.ActiveGrants.Count > 0)
        {
            RaiseStateChanged();
        }
    }

    private void RaiseStateChanged()
    {
        if (Dispatcher.HasThreadAccess)
        {
            Tray.Update();
            StateChanged?.Invoke();
        }
        else
        {
            Dispatcher.TryEnqueue(RaiseStateChanged);
        }
    }

    public async void Exit()
    {
        if (_exiting)
        {
            return;
        }
        _exiting = true;
        Log.Info("Exiting");
        _minuteTimer?.Dispose();
        _mainWindow?.Close();
        Session.Lock(L.T("退出", "Exit"));
        try
        {
            await Pipe.StopAsync().WaitAsync(TimeSpan.FromSeconds(3));
        }
        catch (Exception)
        {
        }
        Toasts.Unregister();
        Tray.Dispose();
        Application.Current.Exit();
    }

    private static async Task TrimMemoryLaterAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(5));
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        EmptyWorkingSet(GetCurrentProcess());
    }

    private static TimeSpan IdleTime()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref info))
        {
            return TimeSpan.Zero;
        }
        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.dwTime));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO info);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("psapi.dll")]
    private static extern bool EmptyWorkingSet(IntPtr process);
}
