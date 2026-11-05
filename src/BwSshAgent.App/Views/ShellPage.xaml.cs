using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml;
using BwSshAgent.Core;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace BwSshAgent.App.Views;

public sealed partial class ShellPage : Page, IRefreshable
{
    private MainWindow? _window;

    public ShellPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        Nav.SelectedItem = Nav.MenuItems[0];
        Refresh();
    }

    public void Refresh()
    {
        var update = _window?.Host.AvailableUpdate;
        UpdateLink.Visibility = update == null ? Visibility.Collapsed : Visibility.Visible;
        if (update != null)
        {
            UpdateText.Text = L.T($"有新版本 v{update.Version}", $"Update available: v{update.Version}");
            ToolTipService.SetToolTip(UpdateLink, L.T("前往 GitHub 查看更新与下载", "View release and downloads on GitHub"));
        }
        (ContentFrame.Content as IRefreshable)?.Refresh();
    }

    private void OnUpdateClicked(object sender, RoutedEventArgs e) => _window?.Host.OpenUpdateRelease();

    private void OnSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        var tag = (args.SelectedItem as NavigationViewItem)?.Tag as string;
        var page = tag switch
        {
            "audit" => typeof(AuditPage),
            "diag" => typeof(DiagnosticsPage),
            "settings" => typeof(SettingsPage),
            _ => typeof(KeysPage),
        };
        if (ContentFrame.Content?.GetType() != page)
        {
            ContentFrame.Navigate(page, _window, new EntranceNavigationTransitionInfo());
            ContentFrame.BackStack.Clear();
        }
    }
}
