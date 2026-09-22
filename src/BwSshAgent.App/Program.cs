using System.Runtime.InteropServices;
using BwSshAgent.App.Services;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;

namespace BwSshAgent.App;

public static class Program
{
    /// <summary>Held for the process lifetime so the installer can detect a running instance.</summary>
    private static Mutex? _runningMutex;

    [STAThread]
    private static int Main(string[] args)
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();

        if (args.Contains("--uninstall-cleanup", StringComparer.OrdinalIgnoreCase))
        {
            return UninstallCleanup(purge: args.Contains("--purge", StringComparer.OrdinalIgnoreCase));
        }

        var mainInstance = AppInstance.FindOrRegisterForKey("BwSshAgent.Main");
        if (!mainInstance.IsCurrent)
        {
            var activation = AppInstance.GetCurrent().GetActivatedEventArgs();
            AllowSetForegroundWindow(mainInstance.ProcessId);
            Task.Run(() => mainInstance.RedirectActivationToAsync(activation).AsTask()).Wait();
            return 0;
        }

        _runningMutex = new Mutex(false, "BwSshAgent-AppMutex");
        mainInstance.Activated += (_, _) => AppHost.Current?.OnRedirectedActivation();

        var launchedByToast = AppInstance.GetCurrent().GetActivatedEventArgs().Kind == ExtendedActivationKind.AppNotification;
        var background = args.Contains("--background", StringComparer.OrdinalIgnoreCase) && !launchedByToast;

        Application.Start(p =>
        {
            var context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
            SynchronizationContext.SetSynchronizationContext(context);
            _ = new App(background);
        });
        GC.KeepAlive(_runningMutex);
        return 0;
    }

    /// <summary>
    /// Called by the uninstaller: removes the toast registration and the autostart entry, and with --purge
    /// also deletes local data (cached vault, settings, audit log) and the Windows Hello credential.
    /// </summary>
    private static int UninstallCleanup(bool purge)
    {
        try
        {
            Microsoft.Windows.AppNotifications.AppNotificationManager.Default.UnregisterAll();
        }
        catch (Exception)
        {
        }
        try
        {
            BwSshAgent.Core.Settings.AutoStart.Set(false);
        }
        catch (Exception)
        {
        }
        if (purge)
        {
            try
            {
                new BwSshAgent.Core.Security.HelloProtector().DisableAsync().Wait(TimeSpan.FromSeconds(10));
            }
            catch (Exception)
            {
            }
            try
            {
                var root = BwSshAgent.Core.Storage.AppPaths.Root;
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (Exception)
            {
            }
        }
        return 0;
    }

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(uint processId);
}
