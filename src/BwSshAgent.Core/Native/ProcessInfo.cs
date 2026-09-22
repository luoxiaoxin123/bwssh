using System.Runtime.InteropServices;
using System.Text;

namespace BwSshAgent.Core.Native;

public sealed record ProcessNode(int Pid, string Name, string? ImagePath, long CreationTime, string? CommandLine)
{
    /// <summary>Stable identity that survives PID reuse.</summary>
    public string Identity => $"{ImagePath ?? Name}|{Pid}|{CreationTime}";
}

public static class ProcessInfo
{
    /// <summary>Processes that merely relay a request (shells, git, ssh tools); a grant is attached to the first ancestor that is not one of these.</summary>
    private static readonly HashSet<string> Intermediaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "ssh.exe", "scp.exe", "sftp.exe", "ssh-keygen.exe", "ssh-add.exe", "rsync.exe",
        "git.exe", "git-remote-http.exe", "git-remote-https.exe", "git-lfs.exe", "git-upload-pack.exe", "git-receive-pack.exe",
        "bash.exe", "sh.exe", "zsh.exe", "fish.exe", "dash.exe", "env.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "conhost.exe", "openconsole.exe", "wsl.exe", "wslhost.exe", "timeout.exe", "xargs.exe", "sudo.exe",
    };

    private static readonly HashSet<string> StopAt = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "services.exe", "svchost.exe", "wininit.exe", "winlogon.exe", "userinit.exe", "sihost.exe",
    };

    public static List<ProcessNode> GetChain(int pid, int maxDepth = 12)
    {
        var chain = new List<ProcessNode>();
        var table = Snapshot();
        var current = pid;
        long childCreation = long.MaxValue;
        while (current > 4 && chain.Count < maxDepth && table.TryGetValue(current, out var entry))
        {
            var (path, creation, cmd) = Query(current);
            if (creation > childCreation)
            {
                break; // parent PID was reused by a newer process
            }
            chain.Add(new ProcessNode(current, entry.Name, path, creation, cmd));
            if (StopAt.Contains(entry.Name))
            {
                break;
            }
            childCreation = creation == 0 ? long.MaxValue : creation;
            current = entry.ParentPid;
        }
        if (chain.Count == 0)
        {
            chain.Add(new ProcessNode(pid, pid == 0 ? L.T("未知程序", "Unknown program") : $"PID {pid}", null, 0, null));
        }
        return chain;
    }

    /// <summary>The process a time-limited grant is bound to, e.g. claude.exe for claude → bash → git → ssh.</summary>
    public static ProcessNode GrantTarget(IReadOnlyList<ProcessNode> chain)
    {
        foreach (var node in chain)
        {
            if (!Intermediaries.Contains(node.Name))
            {
                return node;
            }
        }
        return chain[^1];
    }

    public static bool IsSshClient(ProcessNode node) =>
        node.Name.Equals("ssh.exe", StringComparison.OrdinalIgnoreCase) ||
        node.Name.Equals("scp.exe", StringComparison.OrdinalIgnoreCase) ||
        node.Name.Equals("sftp.exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>Extracts the destination ("user@host[:port]") from an ssh command line.</summary>
    public static string? ParseSshDestination(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }
        var args = SplitCommandLine(commandLine);
        const string withArg = "BbcDEeFIiJLlmOoPpQRSWw";
        string? user = null;
        string? port = null;
        for (var i = 1; i < args.Count; i++)
        {
            var a = args[i];
            if (a == "--")
            {
                return i + 1 < args.Count ? Format(args[i + 1], user, port) : null;
            }
            if (a.Length >= 2 && a[0] == '-')
            {
                for (var j = 1; j < a.Length; j++)
                {
                    if (withArg.Contains(a[j]))
                    {
                        var value = j + 1 < a.Length ? a[(j + 1)..] : (i + 1 < args.Count ? args[++i] : null);
                        if (a[j] == 'l')
                        {
                            user = value;
                        }
                        else if (a[j] == 'p')
                        {
                            port = value;
                        }
                        break;
                    }
                }
                continue;
            }
            return Format(a, user, port);
        }
        return null;
    }

    private static string Format(string destination, string? user, string? port)
    {
        if (destination.StartsWith("ssh://", StringComparison.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(destination, UriKind.Absolute, out var uri))
            {
                var u = string.IsNullOrEmpty(uri.UserInfo) ? user : uri.UserInfo;
                return (u != null ? u + "@" : "") + uri.Host + (uri.Port > 0 && uri.Port != 22 ? ":" + uri.Port : "");
            }
            return destination;
        }
        if (user != null && !destination.Contains('@'))
        {
            destination = user + "@" + destination;
        }
        if (port != null && port != "22")
        {
            destination += ":" + port;
        }
        return destination;
    }

    private static List<string> SplitCommandLine(string commandLine)
    {
        var result = new List<string>();
        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == IntPtr.Zero)
        {
            return result;
        }
        try
        {
            for (var i = 0; i < count; i++)
            {
                result.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size)) ?? "");
            }
        }
        finally
        {
            LocalFree(argv);
        }
        return result;
    }

    private readonly record struct Entry(int ParentPid, string Name);

    private static Dictionary<int, Entry> Snapshot()
    {
        var table = new Dictionary<int, Entry>();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            return table;
        }
        try
        {
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref pe))
            {
                do
                {
                    table[(int)pe.th32ProcessID] = new Entry((int)pe.th32ParentProcessID, pe.szExeFile);
                }
                while (Process32NextW(snap, ref pe));
            }
        }
        finally
        {
            CloseHandle(snap);
        }
        return table;
    }

    private static (string? Path, long Creation, string? CommandLine) Query(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == IntPtr.Zero)
        {
            return (null, 0, null);
        }
        try
        {
            string? path = null;
            var sb = new StringBuilder(1024);
            var size = (uint)sb.Capacity;
            if (QueryFullProcessImageNameW(h, 0, sb, ref size))
            {
                path = sb.ToString();
            }
            long creation = 0;
            if (GetProcessTimes(h, out var c, out _, out _, out _))
            {
                creation = c;
            }
            return (path, creation, ReadCommandLine(h));
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static string? ReadCommandLine(IntPtr process)
    {
        const int ProcessCommandLineInformation = 60;
        NtQueryInformationProcess(process, ProcessCommandLineInformation, IntPtr.Zero, 0, out var needed);
        if (needed <= 0 || needed > 1 << 20)
        {
            return null;
        }
        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (NtQueryInformationProcess(process, ProcessCommandLineInformation, buffer, needed, out _) != 0)
            {
                return null;
            }
            var length = Marshal.ReadInt16(buffer);
            var ptr = Marshal.ReadIntPtr(buffer, IntPtr.Size);
            return length > 0 && ptr != IntPtr.Zero ? Marshal.PtrToStringUni(ptr, length / 2) : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private const uint TH32CS_SNAPPROCESS = 0x2;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref uint size);

    [DllImport("kernel32.dll")]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr info, int length, out int returnLength);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);
}
