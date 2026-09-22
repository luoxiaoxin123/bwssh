using BwSshAgent.Core;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Settings;
using BwSshAgent.Core.Ssh;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BwSshAgent.App.Views;

public sealed class KeyRow
{
    public required string CipherId { get; init; }
    public required string Name { get; init; }
    public required string Detail { get; init; }
    public required string PublicKeyLine { get; init; }
}

public sealed partial class KeysPage : Page, IRefreshable
{
    private MainWindow? _window;
    private AppHost Host => _window!.Host;

    public KeysPage()
    {
        InitializeComponent();
        InfoBars.CollapseWhenClosed(ReauthBar, PipeBar, SyncErrorBar, DecryptBar, ActionBar);
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        Refresh();
    }

    public void Refresh()
    {
        if (_window == null)
        {
            return;
        }
        var session = Host.Session;
        var account = session.Account;
        AccountText.Text = account == null ? "" : $"{account.Email} · {account.Environment.DisplayName}";

        PipeText.Text = Host.Pipe.State switch
        {
            PipeState.Listening => L.T($"SSH agent 正在监听 {Host.Pipe.PipePath}", $"SSH agent is listening on {Host.Pipe.PipePath}"),
            PipeState.Busy => L.T($"管道 {Host.Pipe.PipePath} 被占用，每 5 秒自动重试", $"Pipe {Host.Pipe.PipePath} is in use, retrying every 5 seconds"),
            _ => L.T("SSH agent 未运行", "SSH agent is not running"),
        };
        PipeBar.IsOpen = Host.Pipe.State == PipeState.Busy;
        PipeBar.Message = L.T($"占用者：{Host.Pipe.BusyOwner ?? "未知进程"}。请关闭官方 Bitwarden 客户端的 SSH agent，或停止 Windows 的 OpenSSH Authentication Agent 服务，详见“诊断”页。", $"Used by: {Host.Pipe.BusyOwner ?? "unknown process"}. Turn off the SSH agent in the Bitwarden desktop app or stop the Windows OpenSSH Authentication Agent service. See Diagnostics.");

        var last = Host.Accounts.LastSync;
        SyncText.Text = Host.Accounts.Syncing ? L.T("正在同步…", "Syncing…") :
            last == null ? L.T("尚未同步", "Not synced yet") : L.T($"上次同步：{last.Value.LocalDateTime:yyyy-MM-dd HH:mm:ss}", $"Last sync: {last.Value.LocalDateTime:yyyy-MM-dd HH:mm:ss}");
        SyncButton.IsEnabled = !Host.Accounts.Syncing;
        SyncErrorBar.IsOpen = Host.Accounts.LastSyncError != null && account?.NeedsReauth != true;
        SyncErrorBar.Message = Host.Accounts.LastSyncError ?? "";
        ReauthBar.IsOpen = account?.NeedsReauth == true;
        ReauthBar.Message = L.T("登录令牌已失效，暂时无法同步。已缓存的密钥仍然可以使用。", "Your session expired, so syncing is paused. Cached keys still work.");

        ModeText.Text = L.T("批准方式：", "Approval: ") + Host.Settings.PromptMode switch
        {
            PromptMode.Always => L.T("每次都询问", "Always ask"),
            PromptMode.RememberUntilLock => L.T("锁定密码库前记住", "Remember until lock"),
            _ => L.T("从不询问", "Never ask"),
        };

        var errors = session.DecryptErrors;
        DecryptBar.IsOpen = errors.Count > 0;
        DecryptBar.Message = string.Join("\n", errors);

        var keys = session.PublicKeys;
        KeysHeader.Text = L.T($"密钥（{keys.Count}）", $"Keys ({keys.Count})");
        EmptyText.Visibility = keys.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        KeysList.ItemsSource = keys.Select(k => new KeyRow
        {
            CipherId = k.CipherId,
            Name = k.Name,
            Detail = $"{k.KeyType}  {k.Fingerprint}",
            PublicKeyLine = k.PublicKeyLine,
        }).ToList();

        var names = keys.ToDictionary(k => k.CipherId, k => k.Name, StringComparer.OrdinalIgnoreCase);
        var grants = Host.Agent.ActiveGrants.Select(g => DescribeGrant(g.Identity, g.Expires, names)).ToList();
        GrantsPanel.Visibility = grants.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        GrantsList.ItemsSource = grants;
    }

    private static string DescribeGrant(string identity, DateTimeOffset expires, Dictionary<string, string> names)
    {
        // Format: cipherId|image path|pid|creation time
        var parts = identity.Split('|');
        var key = parts.Length > 0 && names.TryGetValue(parts[0], out var n) ? n : "?";
        var process = parts.Length > 1 ? Path.GetFileName(parts[1]) : identity;
        var pid = parts.Length > 2 ? parts[2] : "?";
        var minutes = Math.Max(0, (int)Math.Ceiling((expires - DateTimeOffset.Now).TotalMinutes));
        return L.T($"{process}（PID {pid}） · 密钥 {key} · 剩余约 {minutes} 分钟", $"{process} (PID {pid}) · key {key} · about {minutes} min left");
    }

    private async void OnSync(object sender, RoutedEventArgs e)
    {
        await Host.SyncNowAsync();
        Refresh();
    }

    private void OnLock(object sender, RoutedEventArgs e) => Host.Lock(L.T("手动锁定", "manual lock"));

    private void OnRevoke(object sender, RoutedEventArgs e) => Host.Agent.RevokeAllGrants();

    private void OnRelogin(object sender, RoutedEventArgs e) => _window!.ShowLogin();

    private async void OnAdd(object sender, RoutedEventArgs e)
    {
        var dialog = new AddKeyDialog(Host, WinRT.Interop.WindowNative.GetWindowHandle(_window)) { XamlRoot = XamlRoot };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary && dialog.SavedPublicKey != null)
        {
            Dialogs.CopyText(dialog.SavedPublicKey);
            ShowAction(InfoBarSeverity.Success, L.T($"已添加“{dialog.SavedName}”", $"Added \"{dialog.SavedName}\""), L.T("公钥已复制到剪贴板，可以直接粘贴到服务器的 authorized_keys 或 GitHub 等平台。", "The public key is on the clipboard. Paste it into authorized_keys on your server or into GitHub."));
        }
        Refresh();
    }

    private async void OnRename(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string cipherId })
        {
            return;
        }
        var key = Host.Session.PublicKeys.FirstOrDefault(k => k.CipherId == cipherId);
        if (key == null)
        {
            return;
        }
        var box = new TextBox { Text = key.Name, Header = L.T("新名称", "New name") };
        box.SelectAll();
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = L.T("改名", "Rename"),
            Content = box,
            PrimaryButtonText = L.T("保存", "Save"),
            CloseButtonText = L.T("取消", "Cancel"),
            DefaultButton = ContentDialogButton.Primary,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }
        var name = box.Text.Trim();
        if (name.Length == 0 || name == key.Name)
        {
            return;
        }
        var error = await Host.Accounts.RenameSshKeyAsync(cipherId, name);
        ShowResult(error, L.T("已改名", "Renamed"), L.T($"“{key.Name}”已改名为“{name}”。", $"\"{key.Name}\" was renamed to \"{name}\"."));
    }

    private async void OnDelete(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string cipherId })
        {
            return;
        }
        var key = Host.Session.PublicKeys.FirstOrDefault(k => k.CipherId == cipherId);
        if (key == null)
        {
            return;
        }
        var confirmed = await Dialogs.ConfirmAsync(XamlRoot, L.T($"把“{key.Name}”移到回收站？", $"Move \"{key.Name}\" to the trash?"),
            L.T("移到回收站后，这把密钥不再提供给 SSH agent。需要时可以在 Bitwarden 网页版的回收站里恢复。", "The key will no longer be offered by the SSH agent. You can restore it from the trash in the Bitwarden web vault."), L.T("移到回收站", "Move to trash"));
        if (!confirmed)
        {
            return;
        }
        var error = await Host.Accounts.DeleteSshKeyAsync(cipherId);
        ShowResult(error, L.T("已移到回收站", "Moved to trash"), L.T($"“{key.Name}”已移到回收站。", $"\"{key.Name}\" was moved to the trash."));
    }

    private void ShowResult(string? error, string title, string message)
    {
        if (error == null)
        {
            ShowAction(InfoBarSeverity.Success, title, message);
        }
        else
        {
            ShowAction(InfoBarSeverity.Error, L.T("操作失败", "Operation failed"), error);
        }
        Refresh();
    }

    private void ShowAction(InfoBarSeverity severity, string title, string message)
    {
        ActionBar.Severity = severity;
        ActionBar.Title = title;
        ActionBar.Message = message;
        ActionBar.IsOpen = true;
    }

    private void OnCopy(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string line })
        {
            Dialogs.CopyText(line);
        }
    }
}
