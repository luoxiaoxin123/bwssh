using BwSshAgent.Core;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Bitwarden;
using BwSshAgent.Core.Security;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.System;

namespace BwSshAgent.App.Views;

public sealed partial class LoginPage : Page
{
    private MainWindow? _window;
    private AppHost Host => _window!.Host;

    public LoginPage()
    {
        InitializeComponent();
        InfoBars.CollapseWhenClosed(ErrorBar, NoticeBar);
        ServerBox.SelectedIndex = 0;
        MethodBox.SelectedIndex = 0;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        var account = Host.Session.Account;
        if (account != null)
        {
            // Re-login: keep server and email.
            ServerBox.SelectedIndex = account.ServerKind switch
            {
                ServerKind.BitwardenUs => 0,
                ServerKind.BitwardenEu => 1,
                _ => 2,
            };
            ServerUrlBox.Text = account.BaseUrl ?? "";
            IdentityUrlBox.Text = account.IdentityUrl ?? "";
            ApiUrlBox.Text = account.ApiUrl ?? "";
            EmailBox.Text = account.Email;
            MethodBox.SelectedIndex = account.ApiClientId != null ? 1 : 0;
            ClientIdBox.Text = account.ApiClientId ?? "";
            CancelButton.Visibility = Visibility.Visible;
            NoticeBar.Title = L.T("重新登录", "Sign in again");
            NoticeBar.Message = L.T("登录令牌已失效，重新登录后即可继续同步。已缓存的密钥和 PIN / Windows Hello 设置会保留。", "Your session expired. Sign in again to resume syncing. Cached keys, PIN and Windows Hello settings are kept.");
            NoticeBar.IsOpen = account.NeedsReauth;
        }
    }

    private void OnServerChanged(object sender, SelectionChangedEventArgs e) =>
        SelfHostedPanel.Visibility = ServerBox.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;

    private void OnMethodChanged(object sender, SelectionChangedEventArgs e)
    {
        var apiKey = MethodBox.SelectedIndex == 1;
        ApiKeyPanel.Visibility = apiKey ? Visibility.Visible : Visibility.Collapsed;
        EmailBox.Visibility = apiKey ? Visibility.Collapsed : Visibility.Visible;
    }

    private ServerEnvironment? BuildEnvironment()
    {
        switch (ServerBox.SelectedIndex)
        {
            case 0:
                return ServerEnvironment.Us;
            case 1:
                return ServerEnvironment.Eu;
            default:
                try
                {
                    return ServerEnvironment.SelfHosted(ServerUrlBox.Text, IdentityUrlBox.Text, ApiUrlBox.Text);
                }
                catch (ArgumentException)
                {
                    ShowError(L.T("请填写有效的服务器地址，例如 https://vault.example.com", "Enter a valid server URL, e.g. https://vault.example.com"));
                    return null;
                }
        }
    }

    private async void OnLogin(object sender, RoutedEventArgs e)
    {
        ErrorBar.IsOpen = false;
        var env = BuildEnvironment();
        if (env == null)
        {
            return;
        }
        if (PasswordBox.Password.Length == 0)
        {
            ShowError(L.T("请输入主密码。", "Enter your master password."));
            return;
        }
        SetBusy(true);
        try
        {
            LoginStep step;
            if (MethodBox.SelectedIndex == 1)
            {
                if (string.IsNullOrWhiteSpace(ClientIdBox.Text) || string.IsNullOrWhiteSpace(ClientSecretBox.Password))
                {
                    ShowError(L.T("请填写 client_id 和 client_secret。", "Enter client_id and client_secret."));
                    return;
                }
                step = await Host.Accounts.LoginWithApiKeyAsync(env, ClientIdBox.Text, ClientSecretBox.Password, PasswordBox.Password);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(EmailBox.Text))
                {
                    ShowError(L.T("请输入邮箱。", "Enter your email."));
                    return;
                }
                step = await Host.Accounts.LoginWithPasswordAsync(env, EmailBox.Text, PasswordBox.Password);
            }
            Handle(step);
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void Handle(LoginStep step)
    {
        switch (step)
        {
            case LoginStep.Done:
                PasswordBox.Password = "";
                ClientSecretBox.Password = "";
                _window!.LoginFinished();
                break;
            case LoginStep.TwoFactor tf:
                ShowTwoFactor(tf);
                break;
            case LoginStep.NewDeviceOtp:
                Show(NewDevicePanel);
                OtpBox.Focus(FocusState.Programmatic);
                break;
            case LoginStep.Error err:
                ShowError(err.Message);
                break;
        }
    }

    private void ShowTwoFactor(LoginStep.TwoFactor tf)
    {
        ProviderBox.Items.Clear();
        foreach (var provider in tf.Providers)
        {
            ProviderBox.Items.Add(new ComboBoxItem
            {
                Tag = provider,
                Content = provider switch
                {
                    TwoFactorProvider.Authenticator => L.T("验证器 App（TOTP）", "Authenticator app (TOTP)"),
                    TwoFactorProvider.Email => L.T("邮件", "Email") + (tf.EmailHint != null ? L.T($"（{tf.EmailHint}）", $" ({tf.EmailHint})") : ""),
                    TwoFactorProvider.YubiKey => "YubiKey OTP",
                    _ => provider.ToString(),
                },
            });
        }
        ProviderBox.SelectedIndex = 0;
        CodeBox.Text = "";
        Show(TwoFactorPanel);
        CodeBox.Focus(FocusState.Programmatic);
    }

    private TwoFactorProvider SelectedProvider =>
        ProviderBox.SelectedItem is ComboBoxItem { Tag: TwoFactorProvider p } ? p : TwoFactorProvider.Authenticator;

    private void OnProviderChanged(object sender, SelectionChangedEventArgs e) =>
        SendEmailButton.Visibility = SelectedProvider == TwoFactorProvider.Email ? Visibility.Visible : Visibility.Collapsed;

    private async void OnSendEmail(object sender, RoutedEventArgs e)
    {
        TwoFactorBusy.IsActive = true;
        var error = await Host.Accounts.SendEmailCodeAsync();
        TwoFactorBusy.IsActive = false;
        if (error != null)
        {
            ShowError(error);
        }
        else
        {
            ErrorBar.IsOpen = false;
            NoticeBar.Title = L.T("已发送", "Sent");
            NoticeBar.Message = L.T("验证码已发送到你的邮箱。", "The code was sent to your email.");
            NoticeBar.IsOpen = true;
        }
    }

    private async void OnSubmitTwoFactor(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(CodeBox.Text))
        {
            return;
        }
        ErrorBar.IsOpen = false;
        TwoFactorBusy.IsActive = true;
        try
        {
            Handle(await Host.Accounts.SubmitTwoFactorAsync(SelectedProvider, CodeBox.Text, RememberBox.IsChecked == true));
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
        finally
        {
            TwoFactorBusy.IsActive = false;
        }
    }

    private async void OnSubmitOtp(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(OtpBox.Text))
        {
            return;
        }
        ErrorBar.IsOpen = false;
        OtpBusy.IsActive = true;
        try
        {
            Handle(await Host.Accounts.SubmitNewDeviceOtpAsync(OtpBox.Text));
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
        finally
        {
            OtpBusy.IsActive = false;
        }
    }

    private void OnBack(object sender, RoutedEventArgs e)
    {
        Host.Accounts.CancelLogin();
        Show(CredentialsPanel);
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        Host.Accounts.CancelLogin();
        _window!.LoginFinished();
    }

    private void OnPasswordKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            OnLogin(sender, e);
        }
    }

    private void OnCodeKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            OnSubmitTwoFactor(sender, e);
        }
    }

    private void OnOtpKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            OnSubmitOtp(sender, e);
        }
    }

    private void Show(FrameworkElement panel)
    {
        CredentialsPanel.Visibility = panel == CredentialsPanel ? Visibility.Visible : Visibility.Collapsed;
        TwoFactorPanel.Visibility = panel == TwoFactorPanel ? Visibility.Visible : Visibility.Collapsed;
        NewDevicePanel.Visibility = panel == NewDevicePanel ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SetBusy(bool busy)
    {
        Busy.IsActive = busy;
        LoginButton.IsEnabled = !busy;
    }

    private void ShowError(string message)
    {
        ErrorBar.Title = L.T("登录失败", "Sign-in failed");
        ErrorBar.Message = message;
        ErrorBar.IsOpen = true;
    }
}
