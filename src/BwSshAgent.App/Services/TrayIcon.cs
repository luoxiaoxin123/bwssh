using System.Runtime.InteropServices;
using BwSshAgent.Core;
using BwSshAgent.Core.Security;

namespace BwSshAgent.App.Services;

/// <summary>
/// Plain Win32 notification-area icon. Its hidden window also receives session-lock and power broadcasts.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private const int WM_APP_TRAY = 0x8001;
    private const int WM_POWERBROADCAST = 0x0218;
    private const int WM_WTSSESSION_CHANGE = 0x02B1;
    private const int WM_LBUTTONUP = 0x0202;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_RBUTTONUP = 0x0205;
    private const int WM_CONTEXTMENU = 0x007B;
    private const int PBT_APMSUSPEND = 0x0004;
    private const int WTS_SESSION_LOCK = 0x7;

    private const int CmdOpen = 1;
    private const int CmdLock = 2;
    private const int CmdUnlock = 3;
    private const int CmdSync = 4;
    private const int CmdRevoke = 5;
    private const int CmdExit = 9;

    private readonly AppHost _host;
    private readonly WndProc _wndProc;
    private IntPtr _hwnd;
    private IntPtr _iconUnlocked;
    private IntPtr _iconLocked;
    private uint _taskbarCreated;
    private bool _added;

    public TrayIcon(AppHost host)
    {
        _host = host;
        _wndProc = WindowProc;
    }

    public event Action? SessionLocked;
    public event Action? Suspending;

    public void Create()
    {
        var hInstance = GetModuleHandleW(null);
        var wc = new WNDCLASSEXW
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = hInstance,
            lpszClassName = "BwSshAgentTrayWindow",
        };
        RegisterClassExW(ref wc);
        _hwnd = CreateWindowExW(0, wc.lpszClassName, "bwssh", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);
        _taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
        WTSRegisterSessionNotification(_hwnd, 0);

        var dir = AppContext.BaseDirectory;
        _iconUnlocked = LoadIcon(Path.Combine(dir, "Assets", "app.ico"));
        _iconLocked = LoadIcon(Path.Combine(dir, "Assets", "app-locked.ico"));
        Update();
    }

    public void Update()
    {
        if (_hwnd == IntPtr.Zero)
        {
            return;
        }
        var session = _host.Session;
        var status = session.State switch
        {
            VaultState.Unlocked => L.T($"已解锁 · {session.PublicKeys.Count} 个密钥", $"Unlocked · {session.PublicKeys.Count} keys"),
            VaultState.Locked => L.T("已锁定", "Locked"),
            _ => L.T("未登录", "Signed out"),
        };
        if (_host.Pipe.State == Core.Ssh.PipeState.Busy)
        {
            status += L.T(" · 管道被占用", " · pipe in use");
        }
        var data = NewData();
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.hIcon = session.State == VaultState.Unlocked ? _iconUnlocked : _iconLocked;
        data.szTip = Truncate("bwssh · " + status, 127);
        if (!_added)
        {
            _added = Shell_NotifyIconW(NIM_ADD, ref data);
        }
        else if (!Shell_NotifyIconW(NIM_MODIFY, ref data))
        {
            _added = Shell_NotifyIconW(NIM_ADD, ref data);
        }
    }

    private NOTIFYICONDATAW NewData() => new()
    {
        cbSize = Marshal.SizeOf<NOTIFYICONDATAW>(),
        hWnd = _hwnd,
        uID = 1,
        uCallbackMessage = WM_APP_TRAY,
        szTip = "",
        szInfo = "",
        szInfoTitle = "",
    };

    private IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            if (msg == WM_APP_TRAY)
            {
                var mouse = (int)(lParam.ToInt64() & 0xFFFF);
                if (mouse is WM_LBUTTONUP or WM_LBUTTONDBLCLK)
                {
                    _host.ShowMainWindow();
                }
                else if (mouse is WM_RBUTTONUP or WM_CONTEXTMENU)
                {
                    ShowMenu();
                }
                return IntPtr.Zero;
            }
            if (msg == _taskbarCreated && _taskbarCreated != 0)
            {
                _added = false;
                Update();
                return IntPtr.Zero;
            }
            if (msg == WM_WTSSESSION_CHANGE && wParam.ToInt32() == WTS_SESSION_LOCK)
            {
                SessionLocked?.Invoke();
            }
            else if (msg == WM_POWERBROADCAST && wParam.ToInt32() == PBT_APMSUSPEND)
            {
                Suspending?.Invoke();
            }
        }
        catch (Exception ex)
        {
            Log.Error("Tray window message failed", ex);
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    private void ShowMenu()
    {
        var session = _host.Session;
        var menu = CreatePopupMenu();
        try
        {
            AppendMenuW(menu, MF_STRING, CmdOpen, L.T("打开 bwssh", "Open bwssh"));
            AppendMenuW(menu, MF_SEPARATOR, 0, null);
            if (session.State == VaultState.Unlocked)
            {
                AppendMenuW(menu, MF_STRING, CmdLock, L.T("立即锁定", "Lock now"));
            }
            else if (session.State == VaultState.Locked)
            {
                AppendMenuW(menu, MF_STRING, CmdUnlock, session.Hello.IsEnrolled ? L.T("使用 Windows Hello 解锁", "Unlock with Windows Hello") : L.T("解锁…", "Unlock…"));
            }
            AppendMenuW(menu, session.State == VaultState.LoggedOut ? MF_STRING | MF_GRAYED : MF_STRING, CmdSync, L.T("立即同步", "Sync now"));
            AppendMenuW(menu, _host.Agent.ActiveGrants.Count > 0 ? MF_STRING : MF_STRING | MF_GRAYED, CmdRevoke, L.T("撤销所有临时授权", "Revoke all temporary approvals"));
            AppendMenuW(menu, MF_SEPARATOR, 0, null);
            AppendMenuW(menu, MF_STRING, CmdExit, L.T("退出", "Exit"));

            GetCursorPos(out var pt);
            SetForegroundWindow(_hwnd);
            var cmd = TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.X, pt.Y, _hwnd, IntPtr.Zero);
            PostMessageW(_hwnd, 0, IntPtr.Zero, IntPtr.Zero);
            switch (cmd)
            {
                case CmdOpen:
                    _host.ShowMainWindow();
                    break;
                case CmdLock:
                    _host.Lock(L.T("手动锁定", "manual lock"));
                    break;
                case CmdUnlock:
                    if (session.Hello.IsEnrolled)
                    {
                        _ = UnlockWithHelloAsync();
                    }
                    else
                    {
                        _host.ShowMainWindow();
                    }
                    break;
                case CmdSync:
                    _ = _host.SyncNowAsync();
                    break;
                case CmdRevoke:
                    _host.Agent.RevokeAllGrants();
                    break;
                case CmdExit:
                    _host.Exit();
                    break;
            }
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    private async Task UnlockWithHelloAsync()
    {
        try
        {
            await _host.Session.UnlockWithHelloAsync();
        }
        catch (UnlockException ex)
        {
            Log.Warn("Tray Hello unlock failed: " + ex.Message);
            _host.ShowMainWindow();
        }
    }

    public void Dispose()
    {
        if (_added)
        {
            var data = NewData();
            Shell_NotifyIconW(NIM_DELETE, ref data);
            _added = false;
        }
        if (_hwnd != IntPtr.Zero)
        {
            WTSUnRegisterSessionNotification(_hwnd);
            DestroyWindow(_hwnd);
            _hwnd = IntPtr.Zero;
        }
    }

    private static IntPtr LoadIcon(string path)
    {
        var size = GetSystemMetrics(SM_CXSMICON);
        return LoadImageW(IntPtr.Zero, path, IMAGE_ICON, size, size, LR_LOADFROMFILE);
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    private delegate IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    private const int NIM_ADD = 0;
    private const int NIM_MODIFY = 1;
    private const int NIM_DELETE = 2;
    private const int NIF_MESSAGE = 0x1;
    private const int NIF_ICON = 0x2;
    private const int NIF_TIP = 0x4;
    private const uint MF_STRING = 0x0;
    private const uint MF_GRAYED = 0x1;
    private const uint MF_SEPARATOR = 0x800;
    private const uint TPM_RIGHTBUTTON = 0x2;
    private const uint TPM_RETURNCMD = 0x100;
    private const uint IMAGE_ICON = 1;
    private const uint LR_LOADFROMFILE = 0x10;
    private const int SM_CXSMICON = 49;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public int uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? name);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowExW(int exStyle, string className, string windowName, int style, int x, int y,
        int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessageW(string name);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIconW(int message, ref NOTIFYICONDATAW data);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImageW(IntPtr instance, string name, uint type, int cx, int cy, uint load);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool AppendMenuW(IntPtr menu, uint flags, int id, string? text);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr menu);

    [DllImport("user32.dll")]
    private static extern int TrackPopupMenuEx(IntPtr menu, uint flags, int x, int y, IntPtr hwnd, IntPtr tpm);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT point);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("wtsapi32.dll")]
    private static extern bool WTSRegisterSessionNotification(IntPtr hwnd, int flags);

    [DllImport("wtsapi32.dll")]
    private static extern bool WTSUnRegisterSessionNotification(IntPtr hwnd);
}
