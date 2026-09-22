using BwSshAgent.Core;
using BwSshAgent.Core.Approval;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Settings;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace BwSshAgent.App.Services;

/// <summary>
/// Shows approval prompts as native Windows toasts (bottom-right), falling back to a topmost window when
/// notifications are disabled or the user prefers windows.
/// </summary>
public sealed class ToastPresenter : IApprovalPresenter
{
    private const string Group = "sign";
    private readonly AppHost _host;
    private readonly Dictionary<string, ApprovalWindow> _windows = [];
    private bool _registered;

    public ToastPresenter(AppHost host)
    {
        _host = host;
    }

    public void Register()
    {
        try
        {
            var manager = AppNotificationManager.Default;
            manager.NotificationInvoked += OnInvoked;
            var icon = new Uri(Path.Combine(AppContext.BaseDirectory, "Assets", "app.png"));
            manager.Register("bwssh", icon);
            _registered = true;
            _ = manager.RemoveAllAsync();
        }
        catch (Exception ex)
        {
            Log.Error("Toast registration failed", ex);
        }
    }

    public void Unregister()
    {
        if (!_registered)
        {
            return;
        }
        try
        {
            AppNotificationManager.Default.RemoveAllAsync().AsTask().Wait(1000);
            AppNotificationManager.Default.Unregister();
        }
        catch (Exception ex)
        {
            Log.Error("Toast unregister failed", ex);
        }
    }

    private bool UseToasts =>
        _registered && _host.Settings.ApprovalUi == ApprovalUi.Toast &&
        AppNotificationManager.Default.Setting == AppNotificationSetting.Enabled;

    public string ToastStatus
    {
        get
        {
            if (!_registered)
            {
                return L.T("通知注册失败，将使用置顶窗口。", "Notification registration failed; a topmost window is used instead.");
            }
            return AppNotificationManager.Default.Setting switch
            {
                AppNotificationSetting.Enabled => L.T("Windows 通知可用。", "Windows notifications are available."),
                AppNotificationSetting.DisabledForApplication => L.T("已在系统设置中关闭了本应用的通知，将改用置顶窗口。", "Notifications for this app are off in Windows settings; a topmost window is used instead."),
                AppNotificationSetting.DisabledForUser => L.T("系统通知已被关闭，将改用置顶窗口。", "Windows notifications are off; a topmost window is used instead."),
                AppNotificationSetting.DisabledByGroupPolicy => L.T("通知被组策略禁用，将改用置顶窗口。", "Notifications are disabled by policy; a topmost window is used instead."),
                _ => L.T("通知不可用，将改用置顶窗口。", "Notifications are unavailable; a topmost window is used instead."),
            };
        }
    }

    public void ShowApproval(PendingApproval request, int grantMinutes)
    {
        if (!UseToasts)
        {
            ShowWindow(request, locked: false, grantMinutes);
            return;
        }
        var title = (request.Request.IsForwarding ? L.T("⚠ 转发的 ", "⚠ Forwarded ") : "") + L.T($"{request.Operation}请求 · {request.Key.Name}", $"{request.Operation} request · {request.Key.Name}");
        var builder = NewBuilder(request.Id)
            .AddText(title)
            .AddText(L.T("发起程序：", "Requested by: ") + request.ProcessChain)
            .AddText(Detail(request))
            .AddButton(Button(L.T("批准", "Approve"), "approve", request.Id).SetButtonStyle(AppNotificationButtonStyle.Success));
        if (!request.Request.IsForwarding)
        {
            // Toast buttons share the width and truncate long labels; the process is named in the chain line.
            builder.AddButton(Button(L.T($"{GrantLabel(grantMinutes)}内放行", $"Allow {GrantLabel(grantMinutes)}"), "grant", request.Id));
        }
        builder.AddButton(Button(L.T("拒绝", "Deny"), "deny", request.Id).SetButtonStyle(AppNotificationButtonStyle.Critical));
        Show(builder, request.Id);
    }

    public void ShowUnlockRequired(PendingApproval request)
    {
        if (!UseToasts)
        {
            ShowWindow(request, locked: true, _host.Settings.GrantMinutes);
            return;
        }
        var hello = _host.Session.Hello.IsEnrolled;
        var builder = NewBuilder(request.Id)
            .AddText(L.T($"需要解锁 · {request.Operation} · {request.Key.Name}", $"Unlock needed · {request.Operation} · {request.Key.Name}"))
            .AddText(L.T("发起程序：", "Requested by: ") + request.ProcessChain)
            .AddText(hello ? L.T("使用 Windows Hello 解锁后将批准此次请求。", "Unlocking with Windows Hello approves this request.") : L.T("解锁密码库后将批准此次请求。", "Unlocking the vault approves this request."))
            .AddButton(Button(hello ? L.T("Windows Hello 解锁并批准", "Hello unlock and approve") : L.T("打开解锁窗口", "Open unlock window"), "unlock", request.Id)
                .SetButtonStyle(AppNotificationButtonStyle.Success))
            .AddButton(Button(L.T("拒绝", "Deny"), "deny", request.Id).SetButtonStyle(AppNotificationButtonStyle.Critical));
        Show(builder, request.Id);
    }

    public void ShowListUnlockRequired(string processChain)
    {
        if (!UseToasts)
        {
            _host.Dispatcher.TryEnqueue(() => _host.ShowMainWindow());
            return;
        }
        var hello = _host.Session.Hello.IsEnrolled;
        var builder = NewBuilder("list")
            .AddText(L.T("SSH 密钥列表需要先解锁", "Unlock to list SSH keys"))
            .AddText(processChain)
            .AddButton(Button(hello ? L.T("Windows Hello 解锁", "Unlock with Hello") : L.T("打开解锁窗口", "Open unlock window"), "unlock", "list"));
        Show(builder, "list");
    }

    public void Dismiss(PendingApproval request)
    {
        if (_registered)
        {
            _ = AppNotificationManager.Default.RemoveByTagAndGroupAsync(request.Id, Group);
        }
        _host.Dispatcher.TryEnqueue(() =>
        {
            if (_windows.Remove(request.Id, out var window))
            {
                window.CloseQuietly();
            }
        });
    }

    private static string Detail(PendingApproval request)
    {
        var parts = new List<string>();
        if (request.Destination != null)
        {
            parts.Add(L.T("目标 ", "to ") + request.Destination);
        }
        else if (request.Request.RemoteUser != null)
        {
            parts.Add(L.T("用户 ", "user ") + request.Request.RemoteUser);
        }
        if (request.Request.HostFingerprint != null)
        {
            parts.Add(L.T("主机 ", "host ") + Shorten(request.Request.HostFingerprint));
        }
        parts.Add("PID " + request.Client.Pid);
        return string.Join(" · ", parts);
    }

    private static string GrantLabel(int minutes) =>
        minutes % 60 == 0 ? L.T($"{minutes / 60} 小时", $"{minutes / 60} h") : L.T($"{minutes} 分钟", $"{minutes} min");

    private static string Shorten(string fingerprint) =>
        fingerprint.Length > 26 ? fingerprint[..26] + "…" : fingerprint;

    private AppNotificationBuilder NewBuilder(string id)
    {
        var builder = new AppNotificationBuilder()
            .AddArgument("action", "open")
            .AddArgument("id", id)
            .SetTag(id)
            .SetGroup(Group);
        builder.SetScenario(AppNotificationBuilder.IsUrgentScenarioSupported()
            ? AppNotificationScenario.Urgent
            : AppNotificationScenario.Reminder);
        return builder;
    }

    private static AppNotificationButton Button(string text, string action, string id) =>
        new AppNotificationButton(text).AddArgument("action", action).AddArgument("id", id);

    private void Show(AppNotificationBuilder builder, string id)
    {
        try
        {
            var notification = builder.BuildNotification();
            notification.Expiration = DateTimeOffset.Now.AddSeconds(Math.Max(_host.Settings.ApprovalTimeoutSeconds, 120));
            AppNotificationManager.Default.Show(notification);
        }
        catch (Exception ex)
        {
            Log.Error("Showing toast failed", ex);
            var pending = _host.Agent.Pending.FirstOrDefault(p => p.Id == id);
            if (pending != null)
            {
                ShowWindow(pending, pending.Locked, _host.Settings.GrantMinutes);
            }
        }
    }

    private void ShowWindow(PendingApproval request, bool locked, int grantMinutes)
    {
        _host.Dispatcher.TryEnqueue(() =>
        {
            if (_windows.Remove(request.Id, out var old))
            {
                old.CloseQuietly();
            }
            var window = new ApprovalWindow(_host, request, locked, grantMinutes);
            _windows[request.Id] = window;
            window.Closed += (_, _) =>
            {
                if (_windows.TryGetValue(request.Id, out var w) && w == window)
                {
                    _windows.Remove(request.Id);
                }
            };
            window.ShowOnTop();
        });
    }

    private void OnInvoked(AppNotificationManager sender, AppNotificationActivatedEventArgs args)
    {
        args.Arguments.TryGetValue("action", out var action);
        args.Arguments.TryGetValue("id", out var id);
        id ??= "";
        switch (action)
        {
            case "approve":
                _host.Agent.Respond(id, UserChoice.Approve);
                break;
            case "grant":
                _host.Agent.Respond(id, UserChoice.ApproveForProcess);
                break;
            case "deny":
                _host.Agent.Respond(id, UserChoice.Deny);
                break;
            case "unlock":
                _host.Agent.MarkUnlockRequested(id);
                _ = UnlockFromPromptAsync();
                break;
            default:
                _host.Dispatcher.TryEnqueue(() => _host.ShowMainWindow());
                break;
        }
    }

    /// <summary>Unlock requested from a prompt: Windows Hello when enrolled, otherwise the unlock window.</summary>
    public async Task UnlockFromPromptAsync()
    {
        if (_host.Session.State == VaultState.Unlocked)
        {
            return;
        }
        if (_host.Session.Hello.IsEnrolled)
        {
            try
            {
                await _host.Session.UnlockWithHelloAsync();
                return;
            }
            catch (UnlockException ex)
            {
                Log.Warn("Hello unlock from prompt failed: " + ex.Message);
            }
        }
        _host.Dispatcher.TryEnqueue(() => _host.ShowMainWindow());
    }
}
