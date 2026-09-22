using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace BwSshAgent.App.Services;

internal static class InfoBars
{
    /// <summary>
    /// A closed InfoBar has zero height but still takes part in layout, so each one adds a StackPanel
    /// Spacing gap. Collapse it whenever it is closed.
    /// </summary>
    public static void CollapseWhenClosed(params InfoBar[] bars)
    {
        foreach (var bar in bars)
        {
            Sync(bar);
            bar.RegisterPropertyChangedCallback(InfoBar.IsOpenProperty, (sender, _) => Sync((InfoBar)sender));
        }
    }

    private static void Sync(InfoBar bar) =>
        bar.Visibility = bar.IsOpen ? Visibility.Visible : Visibility.Collapsed;
}
