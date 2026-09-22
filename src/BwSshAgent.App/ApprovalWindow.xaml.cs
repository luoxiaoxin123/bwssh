using BwSshAgent.Core;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Approval;
using BwSshAgent.Core.Native;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Windows.Graphics;

namespace BwSshAgent.App;

/// <summary>Topmost approval prompt used when toasts are unavailable or disabled.</summary>
public sealed partial class ApprovalWindow : Window
{
    private readonly AppHost _host;
    private readonly PendingApproval _request;
    private readonly bool _locked;
    private bool _answered;

    public ApprovalWindow(AppHost host, PendingApproval request, bool locked, int grantMinutes)
    {
        _host = host;
        _request = request;
        _locked = locked;
        InitializeComponent();
        Title = L.T("SSH 签名请求", "SSH signing request");
        InfoBars.CollapseWhenClosed(ForwardWarning);

        TitleText.Text = locked ? L.T($"需要解锁 · {request.Operation}", $"Unlock needed · {request.Operation}") : L.T($"{request.Operation}请求", $"{request.Operation} request");
        ForwardWarning.IsOpen = request.Request.IsForwarding;
        KeyText.Text = L.T($"密钥：{request.Key.Name}（{request.Key.Fingerprint}）", $"Key: {request.Key.Name} ({request.Key.Fingerprint})");
        ProcessText.Text = L.T($"发起程序：{request.ProcessChain}", $"Requested by: {request.ProcessChain}");
        var details = new List<string>();
        if (request.Destination != null)
        {
            details.Add(L.T("目标：", "Destination: ") + request.Destination);
        }
        if (request.Request.RemoteUser != null)
        {
            details.Add(L.T("远程用户：", "Remote user: ") + request.Request.RemoteUser);
        }
        if (request.Request.HostFingerprint != null)
        {
            details.Add(L.T("主机指纹：", "Host fingerprint: ") + request.Request.HostFingerprint);
        }
        details.Add($"PID：{request.Client.Pid}");
        DetailText.Text = string.Join(Environment.NewLine, details);

        if (locked)
        {
            ApproveButton.Content = host.Session.Hello.IsEnrolled ? L.T("Windows Hello 解锁并批准", "Hello unlock and approve") : L.T("解锁…", "Unlock…");
            GrantButton.Visibility = Visibility.Collapsed;
        }
        else
        {
            ApproveButton.Content = L.T("批准", "Approve");
            GrantButton.Content = L.T($"允许 {request.GrantTarget.Name} {grantMinutes} 分钟", $"Allow {request.GrantTarget.Name} for {grantMinutes} min");
            GrantButton.Visibility = request.Request.IsForwarding ? Visibility.Collapsed : Visibility.Visible;
        }

        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico"));
        var scale = WindowHelpers.GetScale(this);
        AppWindow.Resize(new SizeInt32((int)(520 * scale), (int)(340 * scale)));
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsAlwaysOnTop = true;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
        }
        WindowHelpers.CenterOnScreen(this);
        Closed += (_, _) =>
        {
            if (!_answered)
            {
                _host.Agent.Respond(_request.Id, UserChoice.Deny);
            }
        };
    }

    public void ShowOnTop()
    {
        Activate();
        WindowFocus.ForceForeground(WinRT.Interop.WindowNative.GetWindowHandle(this));
    }

    public void CloseQuietly()
    {
        _answered = true;
        Close();
    }

    private void OnApprove(object sender, RoutedEventArgs e)
    {
        if (_locked)
        {
            _host.Agent.MarkUnlockRequested(_request.Id);
            _ = _host.Toasts.UnlockFromPromptAsync();
            return;
        }
        Answer(UserChoice.Approve);
    }

    private void OnGrant(object sender, RoutedEventArgs e) => Answer(UserChoice.ApproveForProcess);

    private void OnDeny(object sender, RoutedEventArgs e) => Answer(UserChoice.Deny);

    private void Answer(UserChoice choice)
    {
        _answered = true;
        _host.Agent.Respond(_request.Id, choice);
        Close();
    }
}
