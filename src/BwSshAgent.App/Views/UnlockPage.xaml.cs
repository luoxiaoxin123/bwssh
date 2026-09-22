using BwSshAgent.Core;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Security;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.System;

namespace BwSshAgent.App.Views;

public sealed partial class UnlockPage : Page, IRefreshable
{
    private MainWindow? _window;
    private bool _showPassword;
    private AppHost Host => _window!.Host;

    public UnlockPage()
    {
        InitializeComponent();
        InfoBars.CollapseWhenClosed(PendingBar, ErrorBar);
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        Refresh();
        if (PinPanel.Visibility == Visibility.Visible)
        {
            PinBox.Focus(FocusState.Programmatic);
        }
        else
        {
            PasswordBox.Focus(FocusState.Programmatic);
        }
    }

    public void Refresh()
    {
        var session = Host.Session;
        var account = session.Account;
        AccountText.Text = account == null ? "" : $"{account.Email} · {account.Environment.DisplayName}";
        HelloButton.Visibility = session.Hello.IsEnrolled ? Visibility.Visible : Visibility.Collapsed;
        var pin = session.Pin.IsAvailable && !_showPassword;
        PinPanel.Visibility = pin ? Visibility.Visible : Visibility.Collapsed;
        PasswordPanel.Visibility = pin ? Visibility.Collapsed : Visibility.Visible;
        TogglePasswordLink.Visibility = pin ? Visibility.Visible : Visibility.Collapsed;

        var pending = Host.Agent.Pending.Where(p => p.Locked).ToList();
        PendingBar.IsOpen = pending.Count > 0;
        PendingBar.Message = pending.Count == 0 ? "" :
            string.Join("\n", pending.Select(p => $"{p.Operation} · {p.Key.Name} · {p.ProcessChain}")) + L.T("\n解锁后将继续处理。", "\nThey continue after you unlock.");
    }

    private async Task RunAsync(Func<Task> unlock)
    {
        ErrorBar.IsOpen = false;
        Busy.IsActive = true;
        IsEnabled = false;
        try
        {
            // Unlocking from this window counts as approval for requests waiting on the unlock.
            foreach (var p in Host.Agent.Pending.Where(p => p.Locked))
            {
                Host.Agent.MarkUnlockRequested(p.Id);
            }
            await unlock();
            PasswordBox.Password = "";
            PinBox.Password = "";
        }
        catch (UnlockException ex)
        {
            ErrorBar.Title = L.T("解锁失败", "Unlock failed");
            ErrorBar.Message = ex.Message;
            ErrorBar.IsOpen = true;
            Refresh();
        }
        finally
        {
            Busy.IsActive = false;
            IsEnabled = true;
        }
    }

    private async void OnHello(object sender, RoutedEventArgs e) => await RunAsync(() => Host.Session.UnlockWithHelloAsync());

    private async void OnPin(object sender, RoutedEventArgs e)
    {
        if (PinBox.Password.Length > 0)
        {
            await RunAsync(() => Host.Session.UnlockWithPinAsync(PinBox.Password));
        }
    }

    private async void OnPassword(object sender, RoutedEventArgs e)
    {
        if (PasswordBox.Password.Length > 0)
        {
            await RunAsync(() => Host.Session.UnlockWithMasterPasswordAsync(PasswordBox.Password));
        }
    }

    private void OnPinKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            OnPin(sender, e);
        }
    }

    private void OnPasswordKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            OnPassword(sender, e);
        }
    }

    private void OnTogglePassword(object sender, RoutedEventArgs e)
    {
        _showPassword = true;
        Refresh();
        PasswordBox.Focus(FocusState.Programmatic);
    }

    private void OnRelogin(object sender, RoutedEventArgs e) => _window!.ShowLogin();

    private async void OnLogout(object sender, RoutedEventArgs e)
    {
        if (await Dialogs.ConfirmAsync(XamlRoot, L.T("退出登录？", "Sign out?"), L.T("将删除本地缓存的密码库数据、PIN 和 Windows Hello 设置。", "This deletes the local vault cache, PIN and Windows Hello settings."), L.T("退出登录", "Sign out")))
        {
            Host.Session.Logout();
        }
    }
}
