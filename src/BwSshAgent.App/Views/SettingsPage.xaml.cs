using BwSshAgent.App.Services;
using BwSshAgent.Core;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Settings;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BwSshAgent.App.Views;

public sealed partial class SettingsPage : Page, IRefreshable
{
    private MainWindow? _window;
    private bool _loading;
    private AppHost Host => _window!.Host;

    public SettingsPage()
    {
        InitializeComponent();
        InfoBars.CollapseWhenClosed(MessageBar);
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        _loading = true;
        var s = Host.Settings;
        PromptModeBox.SelectedIndex = (int)s.PromptMode;
        ApprovalUiBox.SelectedIndex = (int)s.ApprovalUi;
        GrantBox.Value = s.GrantMinutes;
        TimeoutBox.Value = s.ApprovalTimeoutSeconds;
        IdleBox.Value = s.LockAfterIdleMinutes;
        SyncBox.Value = s.SyncIntervalMinutes;
        LockOnSystemLockSwitch.IsOn = s.LockOnSystemLock;
        LockOnSleepSwitch.IsOn = s.LockOnSleep;
        PipeNameBox.Text = s.PipeName;
        AutoStartSwitch.IsOn = AutoStart.IsEnabled;
        VersionText.Text = L.T($"bwssh {typeof(SettingsPage).Assembly.GetName().Version?.ToString(3)} · 数据目录 {Core.Storage.AppPaths.Root}", $"bwssh {typeof(SettingsPage).Assembly.GetName().Version?.ToString(3)} · data folder {Core.Storage.AppPaths.Root}");
        _loading = false;
        Refresh();
        HelloSwitch.IsEnabled = HelloSwitch.IsEnabled && await HelloProtector.IsSupportedAsync();
    }

    public void Refresh()
    {
        if (_window == null)
        {
            return;
        }
        _loading = true;
        var session = Host.Session;
        var unlocked = session.State == VaultState.Unlocked;
        HelloSwitch.IsOn = session.Hello.IsEnrolled;
        PinSwitch.IsOn = session.Pin.IsEnabled;
        HelloSwitch.IsEnabled = unlocked || session.Hello.IsEnrolled;
        PinSwitch.IsEnabled = unlocked || session.Pin.IsEnabled;
        UnlockHint.Text = unlocked
            ? L.T("Windows Hello 和 PIN 只保存在这台电脑上，用来代替输入主密码。", "Windows Hello and PIN stay on this computer and replace typing your master password.")
            : L.T("开启 Windows Hello 或 PIN 需要先解锁密码库。", "Unlock the vault to turn on Windows Hello or PIN.");
        PinModeText.Text = !session.Pin.IsEnabled ? "" :
            session.Pin.IsPersistent ? L.T("PIN 在重启后仍可使用。", "The PIN keeps working after a restart.") : L.T("每次启动后需要先用主密码或 Windows Hello 解锁一次，之后才能用 PIN。", "After each start, unlock once with your master password or Windows Hello before the PIN works.");
        ToastStatusText.Text = Host.Toasts.ToastStatus;
        var account = session.Account;
        AccountText.Text = account == null ? L.T("未登录", "Signed out") : $"{account.Email} · {account.Environment.DisplayName}" +
            (account.ApiClientId != null ? L.T(" · API Key 登录", " · API key sign-in") : "");
        _loading = false;
    }

    private void Save()
    {
        if (!_loading)
        {
            Host.SaveSettings();
        }
    }

    private void OnPromptModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || PromptModeBox.SelectedIndex < 0)
        {
            return;
        }
        Host.Settings.PromptMode = (PromptMode)PromptModeBox.SelectedIndex;
        Save();
    }

    private void OnApprovalUiChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || ApprovalUiBox.SelectedIndex < 0)
        {
            return;
        }
        Host.Settings.ApprovalUi = (ApprovalUi)ApprovalUiBox.SelectedIndex;
        Save();
    }

    private void OnNumberChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_loading || double.IsNaN(args.NewValue))
        {
            return;
        }
        var s = Host.Settings;
        var value = (int)args.NewValue;
        if (sender == GrantBox)
        {
            s.GrantMinutes = value;
        }
        else if (sender == TimeoutBox)
        {
            s.ApprovalTimeoutSeconds = value;
        }
        else if (sender == IdleBox)
        {
            s.LockAfterIdleMinutes = value;
        }
        else if (sender == SyncBox)
        {
            s.SyncIntervalMinutes = value;
        }
        Save();
    }

    private void OnToggled(object sender, RoutedEventArgs e)
    {
        if (_loading)
        {
            return;
        }
        Host.Settings.LockOnSystemLock = LockOnSystemLockSwitch.IsOn;
        Host.Settings.LockOnSleep = LockOnSleepSwitch.IsOn;
        Save();
    }

    private void OnAutoStartToggled(object sender, RoutedEventArgs e)
    {
        if (_loading)
        {
            return;
        }
        try
        {
            AutoStart.Set(AutoStartSwitch.IsOn);
        }
        catch (Exception ex)
        {
            ShowMessage(InfoBarSeverity.Error, L.T("无法修改开机启动", "Could not change startup setting"), ex.Message);
        }
    }

    private async void OnHelloToggled(object sender, RoutedEventArgs e)
    {
        if (_loading)
        {
            return;
        }
        var session = Host.Session;
        if (HelloSwitch.IsOn && !session.Hello.IsEnrolled)
        {
            using var userKey = session.CopyUserKey();
            if (userKey == null)
            {
                Refresh();
                return;
            }
            try
            {
                await session.Hello.EnrollAsync(userKey);
                ShowMessage(InfoBarSeverity.Success, L.T("已启用 Windows Hello", "Windows Hello enabled"), L.T("之后可以用 Windows Hello 解锁，锁定状态下的签名请求也可以直接在通知里用 Windows Hello 批准。", "You can now unlock with Windows Hello, and approve requests from the notification while locked."));
            }
            catch (Exception ex)
            {
                ShowMessage(InfoBarSeverity.Error, L.T("启用失败", "Could not enable"), ex.Message);
            }
        }
        else if (!HelloSwitch.IsOn && session.Hello.IsEnrolled)
        {
            await session.Hello.DisableAsync();
        }
        Refresh();
    }

    private async void OnPinToggled(object sender, RoutedEventArgs e)
    {
        if (_loading)
        {
            return;
        }
        var session = Host.Session;
        if (PinSwitch.IsOn && !session.Pin.IsEnabled)
        {
            await SetPinAsync();
        }
        else if (!PinSwitch.IsOn && session.Pin.IsEnabled)
        {
            session.Pin.Disable();
        }
        Refresh();
    }

    private async Task SetPinAsync()
    {
        var pin = new PasswordBox { Header = L.T("PIN（至少 4 位）", "PIN (at least 4 characters)") };
        var confirm = new PasswordBox { Header = L.T("再次输入 PIN", "Confirm PIN") };
        var requireMaster = new CheckBox { Content = L.T("重启程序后需要先用主密码或 Windows Hello 解锁", "After restarting, require the master password or Windows Hello first"), IsChecked = true };
        var error = new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.IndianRed), TextWrapping = TextWrapping.Wrap };
        var panel = new StackPanel { Spacing = 10, Children = { pin, confirm, requireMaster, error } };
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = L.T("设置 PIN", "Set PIN"),
            Content = panel,
            PrimaryButtonText = L.T("保存", "Save"),
            CloseButtonText = L.T("取消", "Cancel"),
            DefaultButton = ContentDialogButton.Primary,
        };
        dialog.PrimaryButtonClick += (_, args) =>
        {
            if (pin.Password.Length < 4)
            {
                error.Text = L.T("PIN 至少需要 4 位。", "The PIN needs at least 4 characters.");
                args.Cancel = true;
            }
            else if (pin.Password != confirm.Password)
            {
                error.Text = L.T("两次输入的 PIN 不一致。", "The PINs do not match.");
                args.Cancel = true;
            }
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }
        using var userKey = Host.Session.CopyUserKey();
        if (userKey == null)
        {
            ShowMessage(InfoBarSeverity.Warning, L.T("请先解锁", "Unlock first"), L.T("设置 PIN 需要先解锁密码库。", "Unlock the vault to set a PIN."));
            return;
        }
        try
        {
            await Host.Session.Pin.EnableAsync(pin.Password, persistent: requireMaster.IsChecked != true, userKey);
            ShowMessage(InfoBarSeverity.Success, L.T("已设置 PIN", "PIN set"), "");
        }
        catch (Exception ex)
        {
            Log.Error("Setting PIN failed", ex);
            ShowMessage(InfoBarSeverity.Error, L.T("设置 PIN 失败", "Could not set PIN"), ex.Message);
        }
    }

    private async void OnApplyPipe(object sender, RoutedEventArgs e)
    {
        var name = PipeNameBox.Text.Trim();
        if (name.Length == 0 || name.Contains('\\') || name.Contains('/'))
        {
            ShowMessage(InfoBarSeverity.Error, L.T("管道名称无效", "Invalid pipe name"), L.T("只填写名称部分，例如 openssh-ssh-agent。", "Enter only the name, e.g. openssh-ssh-agent."));
            return;
        }
        await Host.ApplyPipeNameAsync(name);
        ShowMessage(InfoBarSeverity.Success, L.T("已应用", "Applied"), L.T($"现在监听 \\\\.\\pipe\\{name}", $"Now listening on \\\\.\\pipe\\{name}"));
    }

    private async void OnLogout(object sender, RoutedEventArgs e)
    {
        if (await Dialogs.ConfirmAsync(XamlRoot, L.T("退出登录？", "Sign out?"), L.T("将删除本地缓存的密码库数据、PIN 和 Windows Hello 设置。", "This deletes the local vault cache, PIN and Windows Hello settings."), L.T("退出登录", "Sign out")))
        {
            Host.Session.Logout();
        }
    }

    private void OnExit(object sender, RoutedEventArgs e) => Host.Exit();

    private void ShowMessage(InfoBarSeverity severity, string title, string message)
    {
        MessageBar.Severity = severity;
        MessageBar.Title = title;
        MessageBar.Message = message;
        MessageBar.IsOpen = true;
    }
}
