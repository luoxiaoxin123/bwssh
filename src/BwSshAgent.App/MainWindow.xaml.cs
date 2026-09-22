using BwSshAgent.App.Services;
using BwSshAgent.App.Views;
using BwSshAgent.Core.Native;
using BwSshAgent.Core.Security;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Graphics;

namespace BwSshAgent.App;

public sealed partial class MainWindow : Window
{
    private readonly AppHost _host;
    private bool _forceLogin;

    public MainWindow(AppHost host)
    {
        _host = host;
        InitializeComponent();
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico"));
        var scale = WindowHelpers.GetScale(this);
        AppWindow.Resize(new SizeInt32((int)(980 * scale), (int)(700 * scale)));
        WindowHelpers.CenterOnScreen(this);

        _host.StateChanged += OnStateChanged;
        Closed += (_, _) => _host.StateChanged -= OnStateChanged;
        NavigateForState();
    }

    public AppHost Host => _host;

    public void BringToFront()
    {
        if (AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized } presenter)
        {
            presenter.Restore();
        }
        Activate();
        WindowFocus.ForceForeground(WinRT.Interop.WindowNative.GetWindowHandle(this));
    }

    /// <summary>Show the login page even though an account exists (re-login after the session expired).</summary>
    public void ShowLogin()
    {
        _forceLogin = true;
        NavigateForState();
    }

    public void LoginFinished()
    {
        _forceLogin = false;
        NavigateForState();
    }

    private void OnStateChanged() => NavigateForState();

    private void NavigateForState()
    {
        var target = _host.Session.State switch
        {
            _ when _forceLogin => typeof(LoginPage),
            VaultState.LoggedOut => typeof(LoginPage),
            VaultState.Locked => typeof(UnlockPage),
            _ => typeof(ShellPage),
        };
        if (RootFrame.Content?.GetType() == target)
        {
            (RootFrame.Content as IRefreshable)?.Refresh();
            return;
        }
        RootFrame.Navigate(target, this, new DrillInNavigationTransitionInfo());
        RootFrame.BackStack.Clear();
    }
}

public interface IRefreshable
{
    void Refresh();
}
