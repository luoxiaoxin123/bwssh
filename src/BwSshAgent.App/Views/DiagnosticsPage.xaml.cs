using BwSshAgent.Core;
using System.Diagnostics;
using System.Text;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Settings;
using BwSshAgent.Core.Ssh;
using BwSshAgent.Core.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.Win32;

namespace BwSshAgent.App.Views;

public sealed partial class DiagnosticsPage : Page, IRefreshable
{
    private static readonly string SystemSsh = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe");
    private static readonly string SystemSshAdd = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-add.exe");

    private readonly OnDemandLaunch _onDemand = new();
    private IReadOnlyList<string> _skippedShims = [];
    private MainWindow? _window;
    private AppHost Host => _window!.Host;

    public DiagnosticsPage()
    {
        InitializeComponent();
        ServiceCommand.Text = "Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled";
        GitCommand.Text = $"git config --global core.sshCommand \"{SystemSsh.Replace('\\', '/')}\"";
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        Refresh();
        await CheckAsync();
    }

    public void Refresh()
    {
        if (_window == null)
        {
            return;
        }
        var pipe = Host.Pipe;
        var sock = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        PipeStatus.Text = pipe.State switch
        {
            PipeState.Listening => L.T($"✅ 正在监听 {pipe.PipePath}", $"✅ Listening on {pipe.PipePath}"),
            PipeState.Busy => L.T($"❌ {pipe.PipePath} 已被 {pipe.BusyOwner ?? "其他进程"} 占用。关闭占用者后会在 5 秒内自动接管。", $"❌ {pipe.PipePath} is used by {pipe.BusyOwner ?? "another process"}. bwssh takes over within 5 seconds after it is closed."),
            _ => L.T("⏹ 未运行", "⏹ Not running"),
        } + (string.IsNullOrEmpty(sock) ? "" : L.T($"\n注意：当前环境变量 SSH_AUTH_SOCK = {sock}，ssh 会优先连接它。", $"\nNote: SSH_AUTH_SOCK is set to {sock}; ssh connects to that first."));
        RefreshOnDemand();
    }

    private void RefreshOnDemand()
    {
        bool configured;
        IReadOnlyList<string> shims;
        try
        {
            configured = _onDemand.IsConfigured;
            shims = _onDemand.InstalledShims;
        }
        catch (Exception ex)
        {
            OnDemandStatus.Text = L.T($"❌ 无法读取 {_onDemand.SshConfigPath}：{ex.Message}", $"❌ Could not read {_onDemand.SshConfigPath}: {ex.Message}");
            return;
        }
        OnDemandEnableButton.Visibility = configured ? Visibility.Collapsed : Visibility.Visible;
        OnDemandDisableButton.Visibility = configured ? Visibility.Visible : Visibility.Collapsed;
        if (!configured)
        {
            OnDemandStatus.Text = L.T(
                $"未设置。一键设置会在 {_onDemand.SshConfigPath} 开头加入一段 Match exec 规则（原文件备份为 config.bwssh.bak），并在 {_onDemand.BinDir} 中放入 ssh、scp、sftp、ssh-add 脚本，让 Git Bash 改用系统 OpenSSH（Git 自带的 ssh 无法连接本 agent）。",
                $"Not set up. Setting up adds a Match exec rule at the top of {_onDemand.SshConfigPath} (the old file is backed up to config.bwssh.bak) and puts ssh, scp, sftp and ssh-add scripts in {_onDemand.BinDir} so Git Bash uses the Windows OpenSSH client (Git's bundled ssh cannot reach this agent).");
            return;
        }
        var lines = new List<string>
        {
            L.T($"✅ 已设置：{_onDemand.SshConfigPath} 中已加入按需启动规则。", $"✅ Set up: {_onDemand.SshConfigPath} has the start-on-demand rule."),
        };
        if (shims.Count > 0)
        {
            lines.Add(L.T($"✅ Git Bash 中的 {string.Join("、", shims)} 会使用系统 OpenSSH（{_onDemand.BinDir}）。", $"✅ In Git Bash, {string.Join(", ", shims)} use the Windows OpenSSH client ({_onDemand.BinDir})."));
        }
        if (_skippedShims.Count > 0)
        {
            lines.Add(L.T($"⚠ {_onDemand.BinDir} 中已有同名文件，没有覆盖：{string.Join("、", _skippedShims)}。", $"⚠ {_onDemand.BinDir} already has files with these names, left untouched: {string.Join(", ", _skippedShims)}."));
        }
        lines.Add(L.T("注意：ssh-add 和 Git 的 SSH 提交签名不读取 ssh 配置，不会自动启动 bwssh。", "Note: ssh-add and Git SSH commit signing don't read the ssh config, so they don't start bwssh."));
        OnDemandStatus.Text = string.Join("\n", lines);
    }

    private void OnEnableOnDemand(object sender, RoutedEventArgs e)
    {
        try
        {
            _skippedShims = _onDemand.Enable(Environment.ProcessPath!);
            Log.Info("Start on demand set up");
        }
        catch (Exception ex)
        {
            Log.Error("Start on demand setup failed", ex);
            OnDemandStatus.Text = L.T($"❌ 设置失败：{ex.Message}", $"❌ Setup failed: {ex.Message}");
            return;
        }
        RefreshOnDemand();
    }

    private void OnDisableOnDemand(object sender, RoutedEventArgs e)
    {
        try
        {
            _onDemand.Disable();
            _skippedShims = [];
            Log.Info("Start on demand removed");
        }
        catch (Exception ex)
        {
            Log.Error("Start on demand removal failed", ex);
            OnDemandStatus.Text = L.T($"❌ 撤销失败：{ex.Message}", $"❌ Undo failed: {ex.Message}");
            return;
        }
        RefreshOnDemand();
    }

    private async Task CheckAsync()
    {
        var conflicts = new List<string>();
        var serviceStart = ReadServiceStart();
        var serviceRunning = Process.GetProcessesByName("ssh-agent").Length > 0;
        if (serviceRunning)
        {
            conflicts.Add(L.T("❌ Windows OpenSSH Authentication Agent（ssh-agent.exe）正在运行。", "❌ The Windows OpenSSH Authentication Agent (ssh-agent.exe) is running."));
        }
        else if (serviceStart is 2 or 3)
        {
            conflicts.Add(serviceStart == 2
                ? L.T("⚠ Windows OpenSSH Authentication Agent 服务未运行，但启动类型为“自动”，可能会被再次启动。", "⚠ The Windows OpenSSH Authentication Agent service is stopped but set to Automatic, so it may start again.")
                : L.T("⚠ Windows OpenSSH Authentication Agent 服务未运行，但启动类型为“手动”，可能会被再次启动。", "⚠ The Windows OpenSSH Authentication Agent service is stopped but set to Manual, so it may start again."));
        }
        if (Process.GetProcessesByName("Bitwarden").Length > 0)
        {
            conflicts.Add(L.T("⚠ 官方 Bitwarden 桌面客户端正在运行。如果它开启了 SSH agent，会占用同一个管道：请在它的设置中关闭 SSH agent，或退出它。", "⚠ The Bitwarden desktop app is running. If its SSH agent is on it uses the same pipe: turn it off in its settings or quit it."));
        }
        ConflictStatus.Text = conflicts.Count == 0 ? L.T("✅ 没有发现冲突。", "✅ No conflicts found.") : string.Join("\n", conflicts);
        ServiceFix.Visibility = serviceRunning || serviceStart is 2 ? Visibility.Visible : Visibility.Collapsed;

        var sshCommand = (await RunAsync("git", "config --global --get core.sshCommand")).Output.Trim();
        var gitSshEnv = Environment.GetEnvironmentVariable("GIT_SSH_COMMAND") ?? Environment.GetEnvironmentVariable("GIT_SSH");
        var gitInstalled = (await RunAsync("git", "--version")).Code == 0;
        var effective = gitSshEnv ?? (sshCommand.Length > 0 ? sshCommand : null);
        var usesSystemSsh = effective != null &&
            effective.Replace('/', '\\').Contains(@"System32\OpenSSH", StringComparison.OrdinalIgnoreCase);
        if (!gitInstalled)
        {
            GitStatus.Text = L.T("未检测到 git。", "git was not found.");
            GitFix.Visibility = Visibility.Collapsed;
        }
        else if (usesSystemSsh)
        {
            GitStatus.Text = L.T($"✅ Git 使用系统 OpenSSH：{effective}", $"✅ Git uses the Windows OpenSSH client: {effective}");
            GitFix.Visibility = Visibility.Collapsed;
        }
        else
        {
            GitStatus.Text = effective == null
                ? L.T("⚠ Git 使用默认 ssh。如果装的是 Git for Windows，默认的是它自带的 ssh，无法使用本 agent。", "⚠ Git uses its default ssh. With Git for Windows that is its bundled ssh, which cannot use this agent.")
                : L.T($"⚠ Git 当前使用：{effective}", $"⚠ Git currently uses: {effective}");
            GitFix.Visibility = Visibility.Visible;
        }
    }

    private static int? ReadServiceStart()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\ssh-agent");
        return key?.GetValue("Start") as int?;
    }

    private async void OnRecheck(object sender, RoutedEventArgs e)
    {
        Refresh();
        await CheckAsync();
    }

    private async void OnTest(object sender, RoutedEventArgs e)
    {
        TestOutput.Visibility = Visibility.Visible;
        TestOutput.Text = L.T("运行中…", "Running…");
        var env = new Dictionary<string, string> { ["SSH_AUTH_SOCK"] = Host.Pipe.PipePath };
        var (code, output) = await RunAsync(SystemSshAdd, "-L", env);
        TestOutput.Text = code switch
        {
            0 => output.Trim(),
            1 when output.Contains("no identities", StringComparison.OrdinalIgnoreCase) => L.T("agent 可以连接，但没有密钥（未登录，或密码库中没有 SSH 密钥）。", "The agent is reachable but has no keys (not signed in, or no SSH keys in the vault)."),
            -2 => L.T("找不到系统 OpenSSH（C:\\Windows\\System32\\OpenSSH\\ssh-add.exe）。请在“设置 → 系统 → 可选功能”中安装 OpenSSH 客户端。", "Windows OpenSSH was not found (C:\\Windows\\System32\\OpenSSH\\ssh-add.exe). Install the OpenSSH Client under Settings → System → Optional features."),
            _ => L.T($"失败（退出码 {code}）：{output.Trim()}", $"Failed (exit code {code}): {output.Trim()}"),
        };
    }

    private void OnOpenLog(object sender, RoutedEventArgs e)
    {
        var path = AppPaths.File("app.log");
        if (File.Exists(path))
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
    }

    private void OnCopyServiceCommand(object sender, RoutedEventArgs e) => Dialogs.CopyText(ServiceCommand.Text);

    private void OnCopyGitCommand(object sender, RoutedEventArgs e) => Dialogs.CopyText(GitCommand.Text);

    private static async Task<(int Code, string Output)> RunAsync(string exe, string args, Dictionary<string, string>? env = null)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                // OpenSSH and git print UTF-8 (key comments, paths); the default would decode it with the ANSI code page.
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            if (env != null)
            {
                foreach (var kv in env)
                {
                    psi.Environment[kv.Key] = kv.Value;
                }
            }
            using var process = Process.Start(psi)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await process.WaitForExitAsync(cts.Token);
            return (process.ExitCode, await stdout + await stderr);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (-2, "");
        }
        catch (OperationCanceledException)
        {
            return (-1, L.T("超时", "Timed out"));
        }
    }
}
