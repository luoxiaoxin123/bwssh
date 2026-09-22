using Microsoft.UI.Xaml.Controls;
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
    }

    public void Refresh() => (ContentFrame.Content as IRefreshable)?.Refresh();

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
