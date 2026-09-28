using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace BwSshAgent.Core.Settings;

/// <summary>
/// Starts bwssh on demand instead of keeping it resident: a <c>Match exec</c> line in ~/.ssh/config runs
/// <c>bwssh.exe --ensure-agent</c> before ssh connects, and small scripts in ~/bin make Git Bash use the
/// Windows OpenSSH client (Git's bundled ssh cannot talk to Windows named pipes).
/// </summary>
public sealed class OnDemandLaunch
{
    public const string EnsureArg = "--ensure-agent";
    private const string BeginMarker = "# >>> bwssh: start bwssh on demand (managed by bwssh) >>>";
    private const string EndMarker = "# <<< bwssh <<<";
    private const string ShimMarker = "# Managed by bwssh";
    private static readonly string[] ShimTools = ["ssh", "scp", "sftp", "ssh-add"];

    public OnDemandLaunch(string? home = null)
    {
        home ??= Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        SshConfigPath = Path.Combine(home, ".ssh", "config");
        BinDir = Path.Combine(home, "bin");
    }

    public string SshConfigPath { get; }
    public string BinDir { get; }

    /// <summary>The Windows OpenSSH folder the Git Bash scripts forward to. Overridable for tests.</summary>
    public string WindowsOpenSshDir { get; init; } = Path.Combine(Environment.SystemDirectory, "OpenSSH");

    public bool IsConfigured => ReadConfig().Text.Contains(BeginMarker, StringComparison.Ordinal);

    /// <summary>Names of the ~/bin scripts written by bwssh.</summary>
    public IReadOnlyList<string> InstalledShims => ShimTools.Where(t => IsOurShim(Path.Combine(BinDir, t))).ToList();

    /// <summary>
    /// Adds the Match exec block to the top of ~/.ssh/config (backing the old file up to config.bwssh.bak) and writes the
    /// Git Bash scripts. Returns the ~/bin scripts skipped because a file of the user's own already has that name.
    /// </summary>
    public IReadOnlyList<string> Enable(string exePath)
    {
        WriteConfigBlock(exePath, backup: true);
        var skipped = new List<string>();
        Directory.CreateDirectory(BinDir);
        foreach (var tool in ShimTools)
        {
            var path = Path.Combine(BinDir, tool);
            if (File.Exists(path) && !IsOurShim(path))
            {
                skipped.Add(tool);
                continue;
            }
            File.WriteAllText(path, ShimScript(tool), new UTF8Encoding(false));
        }
        return skipped;
    }

    public void Disable()
    {
        var (text, bom) = ReadConfig();
        var stripped = RemoveBlock(text);
        if (stripped != text)
        {
            WriteConfig(stripped, bom);
        }
        foreach (var tool in ShimTools)
        {
            var path = Path.Combine(BinDir, tool);
            if (IsOurShim(path))
            {
                File.Delete(path);
            }
        }
    }

    /// <summary>Keeps the exe path in ~/.ssh/config current when the app is moved or updated.</summary>
    public void RefreshPath(string exePath)
    {
        var (text, _) = ReadConfig();
        if (text.Contains(BeginMarker, StringComparison.Ordinal) && !text.Contains(MatchLine(exePath), StringComparison.Ordinal))
        {
            WriteConfigBlock(exePath, backup: false);
        }
    }

    internal static string MatchLine(string exePath)
    {
        // Both ssh builds run the command through a shell (cmd for Windows OpenSSH, sh for Git's ssh), and the
        // value can't nest quotes: use the 8.3 name if the path has spaces, and forward slashes for sh.
        var path = exePath.Contains(' ') ? ShortPath(exePath) : exePath;
        return $"Match exec \"{path.Replace('\\', '/')} {EnsureArg}\"";
    }

    private void WriteConfigBlock(string exePath, bool backup)
    {
        var (text, bom) = ReadConfig();
        var newline = text.Contains("\r\n", StringComparison.Ordinal) || text.Length == 0 ? "\r\n" : "\n";
        // "Match all" closes our block so the user's top-level settings that follow stay unconditional.
        var block = string.Join(newline, BeginMarker, MatchLine(exePath), "Match all", EndMarker) + newline;
        var rest = RemoveBlock(text);
        if (backup && File.Exists(SshConfigPath))
        {
            File.Copy(SshConfigPath, SshConfigPath + ".bwssh.bak", overwrite: true);
        }
        WriteConfig(block + (rest.Length > 0 ? newline + rest : ""), bom);
    }

    private static string RemoveBlock(string text)
    {
        var begin = text.IndexOf(BeginMarker, StringComparison.Ordinal);
        if (begin < 0)
        {
            return text;
        }
        var end = text.IndexOf(EndMarker, begin, StringComparison.Ordinal);
        end = end < 0 ? text.Length : end + EndMarker.Length;
        // Also drop the line break after the block and the blank line WriteConfigBlock put after it.
        for (var i = 0; i < 2; i++)
        {
            if (end < text.Length && text[end] == '\r')
            {
                end++;
            }
            if (end < text.Length && text[end] == '\n')
            {
                end++;
            }
        }
        return text[..begin] + text[end..];
    }

    private (string Text, bool Bom) ReadConfig()
    {
        if (!File.Exists(SshConfigPath))
        {
            return ("", false);
        }
        var bytes = File.ReadAllBytes(SshConfigPath);
        var bom = bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble);
        return (Encoding.UTF8.GetString(bom ? bytes[3..] : bytes), bom);
    }

    private void WriteConfig(string text, bool bom)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SshConfigPath)!);
        // Overwrite in place rather than replace, so the file keeps its ACL (Windows OpenSSH checks it).
        using var stream = new FileStream(SshConfigPath, FileMode.Create, FileAccess.Write);
        if (bom)
        {
            stream.Write(Encoding.UTF8.Preamble);
        }
        stream.Write(Encoding.UTF8.GetBytes(text));
    }

    private string ShimScript(string tool)
    {
        var exe = Path.Combine(WindowsOpenSshDir, tool + ".exe");
        // C:\Windows\System32\OpenSSH\ssh.exe -> /c/Windows/System32/OpenSSH/ssh.exe
        var posix = "/" + char.ToLowerInvariant(exe[0]) + exe[2..].Replace('\\', '/');
        return $"#!/bin/sh\n{ShimMarker}: use the Windows OpenSSH client, which can reach the bwssh agent pipe.\nexec \"{posix}\" \"$@\"\n";
    }

    private static bool IsOurShim(string path)
    {
        try
        {
            return File.Exists(path) && new FileInfo(path).Length < 4096 && File.ReadAllText(path).Contains(ShimMarker, StringComparison.Ordinal);
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Entry point of <c>bwssh.exe --ensure-agent</c>, run by ssh before it connects: returns at once when the agent
    /// pipe exists, otherwise starts bwssh in the tray and waits until the pipe is listening.
    /// </summary>
    public static int EnsureAgent(string exePath, string pipeName, string appMutexName)
    {
        if (PipeExists(pipeName))
        {
            return 0;
        }
        var running = Mutex.TryOpenExisting(appMutexName, out var mutex);
        mutex?.Dispose();
        if (!running)
        {
            // Shell execute, so the long-lived app doesn't inherit ssh's stdio handles: a caller that reads ssh's
            // output until EOF (an agent's shell tool, a pipeline) would otherwise hang until bwssh exits.
            Process.Start(new ProcessStartInfo(exePath, "--background") { UseShellExecute = true })?.Dispose();
        }
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(running ? 3 : 20))
        {
            Thread.Sleep(50);
            if (PipeExists(pipeName))
            {
                return 0;
            }
        }
        return 1;
    }

    /// <summary>True when a server has created the pipe; unlike opening it, this doesn't use up a pipe instance.</summary>
    public static bool PipeExists(string pipeName) =>
        WaitNamedPipeW(@"\\.\pipe\" + pipeName, 1) || Marshal.GetLastPInvokeError() != ERROR_FILE_NOT_FOUND;

    private static string ShortPath(string path)
    {
        var buffer = new StringBuilder(1024);
        var length = GetShortPathNameW(path, buffer, buffer.Capacity);
        return length > 0 && length < buffer.Capacity ? buffer.ToString() : path;
    }

    private const int ERROR_FILE_NOT_FOUND = 2;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WaitNamedPipeW(string name, uint timeout);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, int bufferLength);
}
