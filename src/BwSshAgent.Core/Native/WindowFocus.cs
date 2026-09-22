using System.Runtime.InteropServices;

namespace BwSshAgent.Core.Native;

/// <summary>
/// Foreground helpers using the common AttachThreadInput / foreground-lock-timeout technique, so the
/// Windows Hello dialog and approval windows are not left behind other windows.
/// </summary>
public static class WindowFocus
{
    /// <summary>While <paramref name="ct"/> is not cancelled, keeps pulling the Windows Hello dialog to the front.</summary>
    public static void FocusSecurityPromptWhile(CancellationToken ct)
    {
        AllowSetForegroundWindow(ASFW_ANY);
        var thread = new Thread(() =>
        {
            while (!ct.IsCancellationRequested)
            {
                var hwnd = FindWindowW("Credential Dialog Xaml Host", null);
                if (hwnd != IntPtr.Zero && GetForegroundWindow() != hwnd)
                {
                    ForceForeground(hwnd);
                }
                ct.WaitHandle.WaitOne(500);
            }
        })
        {
            IsBackground = true,
            Name = "HelloFocus",
        };
        thread.Start();
    }

    /// <summary>Brings a window to the foreground even when the calling process is not in the foreground.</summary>
    public static void ForceForeground(IntPtr hwnd)
    {
        uint oldTimeout = 0;
        SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, ref oldTimeout, 0);
        SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, IntPtr.Zero, SPIF_SENDCHANGE);
        try
        {
            var current = GetCurrentThreadId();
            var foreground = GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero);
            var attached = foreground != current && AttachThreadInput(current, foreground, true);
            try
            {
                ShowWindow(hwnd, SW_SHOW);
                SetForegroundWindow(hwnd);
                SetFocus(hwnd);
                SetActiveWindow(hwnd);
                BringWindowToTop(hwnd);
                SwitchToThisWindow(hwnd, true);
            }
            finally
            {
                if (attached)
                {
                    AttachThreadInput(current, foreground, false);
                }
            }
        }
        finally
        {
            SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, (IntPtr)oldTimeout, SPIF_SENDCHANGE);
        }
    }

    public static IntPtr Foreground() => GetForegroundWindow();

    public static void Restore(IntPtr hwnd)
    {
        if (hwnd != IntPtr.Zero)
        {
            SetForegroundWindow(hwnd);
        }
    }

    private const uint SPI_GETFOREGROUNDLOCKTIMEOUT = 0x2000;
    private const uint SPI_SETFOREGROUNDLOCKTIMEOUT = 0x2001;
    private const uint SPIF_SENDCHANGE = 0x2;
    private const uint ASFW_ANY = unchecked((uint)-1);
    private const int SW_SHOW = 5;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindowW(string? className, string? windowName);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern IntPtr SetFocus(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern IntPtr SetActiveWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern bool BringWindowToTop(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern void SwitchToThisWindow(IntPtr hwnd, bool altTab);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hwnd, int cmd);

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(uint pid);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hwnd, IntPtr pid);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    private static extern bool AttachThreadInput(uint attach, uint attachTo, bool doAttach);

    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
    private static extern bool SystemParametersInfoW(uint action, uint param, ref uint value, uint winIni);

    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
    private static extern bool SystemParametersInfoW(uint action, uint param, IntPtr value, uint winIni);
}
