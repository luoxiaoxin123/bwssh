using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Windows.Graphics;

namespace BwSshAgent.App.Services;

internal static class WindowHelpers
{
    public static double GetScale(Window window)
    {
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
        var dpi = GetDpiForWindow(hwnd);
        return dpi == 0 ? 1.0 : dpi / 96.0;
    }

    public static void CenterOnScreen(Window window)
    {
        var appWindow = window.AppWindow;
        var area = DisplayArea.GetFromWindowId(appWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        var size = appWindow.Size;
        appWindow.Move(new PointInt32(area.X + (area.Width - size.Width) / 2, area.Y + (area.Height - size.Height) / 2));
    }

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);
}
