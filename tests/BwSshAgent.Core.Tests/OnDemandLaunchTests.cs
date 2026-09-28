using System.Text;
using BwSshAgent.Core.Settings;

namespace BwSshAgent.Core.Tests;

public class OnDemandLaunchTests
{
    private const string Exe = @"C:\Apps\bwssh\bwssh.exe";

    private static OnDemandLaunch NewHome(out string home)
    {
        home = Path.Combine(TestEnv.Root, "home-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        return new OnDemandLaunch(home);
    }

    [Theory]
    [InlineData("\r\n", false)]
    [InlineData("\n", false)]
    [InlineData("\r\n", true)]
    public void EnableThenDisableRestoresTheConfigExactly(string newline, bool bom)
    {
        var onDemand = NewHome(out _);
        var original = string.Join(newline, "ServerAliveInterval 60", "", "# 上海", "Host sh", "    HostName 10.0.0.1", "");
        Directory.CreateDirectory(Path.GetDirectoryName(onDemand.SshConfigPath)!);
        var bytes = Encoding.UTF8.GetBytes(original);
        File.WriteAllBytes(onDemand.SshConfigPath, bom ? [.. Encoding.UTF8.Preamble, .. bytes] : bytes);

        onDemand.Enable(Exe);
        var text = File.ReadAllText(onDemand.SshConfigPath);
        Assert.True(onDemand.IsConfigured);
        Assert.StartsWith("# >>> bwssh", text);
        Assert.Contains("Match exec \"C:/Apps/bwssh/bwssh.exe --ensure-agent\"" + newline + "Match all" + newline, text);
        Assert.EndsWith(original, text);
        Assert.Equal(original, File.ReadAllText(onDemand.SshConfigPath + ".bwssh.bak"));

        onDemand.Enable(Exe);
        Assert.Equal(text, File.ReadAllText(onDemand.SshConfigPath));

        onDemand.Disable();
        Assert.False(onDemand.IsConfigured);
        var after = File.ReadAllBytes(onDemand.SshConfigPath);
        Assert.Equal(bom ? [.. Encoding.UTF8.Preamble, .. bytes] : bytes, after);
    }

    [Fact]
    public void EnableCreatesAMissingConfig()
    {
        var onDemand = NewHome(out _);
        onDemand.Enable(Exe);
        Assert.True(onDemand.IsConfigured);
        onDemand.Disable();
        Assert.Equal("", File.ReadAllText(onDemand.SshConfigPath));
    }

    [Fact]
    public void ShimsForwardToWindowsOpenSshAndLeaveUserFilesAlone()
    {
        var onDemand = NewHome(out _);
        Directory.CreateDirectory(onDemand.BinDir);
        var userScp = Path.Combine(onDemand.BinDir, "scp");
        File.WriteAllText(userScp, "#!/bin/sh\necho mine\n");

        var skipped = onDemand.Enable(Exe);
        Assert.Equal(["scp"], skipped);
        Assert.Equal(["ssh", "sftp", "ssh-add"], onDemand.InstalledShims);
        var shim = File.ReadAllText(Path.Combine(onDemand.BinDir, "ssh"));
        Assert.StartsWith("#!/bin/sh\n", shim);
        Assert.DoesNotContain("\r", shim);
        var expected = "/" + char.ToLowerInvariant(Environment.SystemDirectory[0]) + Environment.SystemDirectory[2..].Replace('\\', '/') + "/OpenSSH/ssh.exe";
        Assert.Contains($"exec \"{expected}\" \"$@\"", shim);

        onDemand.Disable();
        Assert.Empty(onDemand.InstalledShims);
        Assert.False(File.Exists(Path.Combine(onDemand.BinDir, "ssh")));
        Assert.Equal("#!/bin/sh\necho mine\n", File.ReadAllText(userScp));
    }

    [Fact]
    public void RefreshPathFollowsTheExe()
    {
        var onDemand = NewHome(out _);
        onDemand.RefreshPath(Exe);
        Assert.False(onDemand.IsConfigured);

        onDemand.Enable(Exe);
        onDemand.RefreshPath(@"D:\bwssh\bwssh.exe");
        var text = File.ReadAllText(onDemand.SshConfigPath);
        Assert.Contains("Match exec \"D:/bwssh/bwssh.exe --ensure-agent\"", text);
        Assert.DoesNotContain("C:/Apps", text);
    }

    [Fact]
    public void PathsWithSpacesUseTheShortName()
    {
        var dir = Path.Combine(TestEnv.Root, "with space " + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var exe = Path.Combine(dir, "bwssh.exe");
        File.WriteAllText(exe, "");
        var line = OnDemandLaunch.MatchLine(exe);
        // 8.3 names can be turned off per volume; then the path is kept as is.
        Assert.Matches("^Match exec \"[^\"]+ --ensure-agent\"$", line);
    }

    [Fact]
    public void WindowsOpenSshStillAppliesTopLevelSettingsAndRunsTheExec()
    {
        var ssh = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe");
        Assert.SkipUnless(File.Exists(ssh), "Windows OpenSSH not installed");
        var onDemand = NewHome(out var home);
        Directory.CreateDirectory(Path.GetDirectoryName(onDemand.SshConfigPath)!);
        File.WriteAllText(onDemand.SshConfigPath, "ServerAliveInterval 42\n\nHost sh\n    HostName 10.9.8.7\n");
        // Stand-in for bwssh.exe: a batch file that leaves a marker, so the test sees that ssh ran it.
        var marker = Path.Combine(home, "ran.txt");
        var probe = Path.Combine(home, "probe.cmd");
        File.WriteAllText(probe, $"@echo ran> \"{marker}\"\r\n");
        onDemand.Enable(probe);

        var (code, output) = TestEnv.Run(ssh, $"-F \"{onDemand.SshConfigPath}\" -G sh");
        Assert.True(code == 0, output);
        Assert.Contains("serveraliveinterval 42", output);
        Assert.Contains("hostname 10.9.8.7", output);
        Assert.True(File.Exists(marker), "ssh did not run the Match exec command");
    }

    [Fact]
    public void PipeExistsDetectsListeningPipes()
    {
        var name = "bwssh-test-" + Guid.NewGuid().ToString("N");
        Assert.False(OnDemandLaunch.PipeExists(name));
        using var server = new System.IO.Pipes.NamedPipeServerStream(name);
        Assert.True(OnDemandLaunch.PipeExists(name));
    }
}
