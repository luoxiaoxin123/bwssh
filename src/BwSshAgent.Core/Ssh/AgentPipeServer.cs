using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using BwSshAgent.Core.Native;

namespace BwSshAgent.Core.Ssh;

public enum PipeState
{
    Stopped,
    Listening,
    Busy,
}

/// <summary>
/// SSH agent over a Windows named pipe (default \\.\pipe\openssh-ssh-agent), restricted to the current user.
/// </summary>
public sealed class AgentPipeServer : IAsyncDisposable
{
    public const string DefaultPipeName = "openssh-ssh-agent";

    private readonly IAgentHandler _handler;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public AgentPipeServer(IAgentHandler handler, string pipeName = DefaultPipeName)
    {
        _handler = handler;
        PipeName = pipeName;
    }

    public string PipeName { get; private set; }
    public string PipePath => @"\\.\pipe\" + PipeName;
    public PipeState State { get; private set; } = PipeState.Stopped;
    public string? BusyOwner { get; private set; }

    public event Action? StateChanged;

    public void Start()
    {
        if (_loop != null)
        {
            return;
        }
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    public async Task RestartAsync(string pipeName)
    {
        await StopAsync();
        PipeName = pipeName;
        Start();
    }

    public async Task StopAsync()
    {
        if (_cts == null)
        {
            return;
        }
        await _cts.CancelAsync();
        try
        {
            if (_loop != null)
            {
                await _loop;
            }
        }
        catch (OperationCanceledException)
        {
        }
        _cts.Dispose();
        _cts = null;
        _loop = null;
        SetState(PipeState.Stopped, null);
    }

    private NamedPipeServerStream CreateInstance(bool first)
    {
        var options = PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly;
        if (first)
        {
            options |= PipeOptions.FirstPipeInstance;
        }
        return new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options, 16 * 1024, 16 * 1024);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                server = CreateInstance(first: true);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                if (State != PipeState.Busy)
                {
                    var owner = FindPipeOwner(PipeName);
                    Log.Warn($"Pipe {PipeName} is in use by {owner ?? "another process"}");
                    SetState(PipeState.Busy, owner);
                }
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
                continue;
            }

            SetState(PipeState.Listening, null);
            Log.Info($"Listening on {PipePath}");
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await server.WaitForConnectionAsync(ct);
                    var connected = server;
                    server = CreateInstance(first: false);
                    _ = Task.Run(() => HandleConnectionAsync(connected, ct), ct);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                Log.Error("Pipe accept loop failed", ex);
                await Task.Delay(1000, CancellationToken.None);
            }
            finally
            {
                await server.DisposeAsync();
            }
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var _ = pipe;
        try
        {
            GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid);
            var client = new AgentClient { Pid = (int)pid, Chain = ProcessInfo.GetChain((int)pid) };
            var binds = new SessionBindState();
            var header = new byte[4];
            while (!ct.IsCancellationRequested)
            {
                if (!await ReadExactAsync(pipe, header, ct))
                {
                    return;
                }
                var length = BinaryPrimitives.ReadUInt32BigEndian(header);
                if (length == 0 || length > AgentMessage.MaxMessageLength)
                {
                    return;
                }
                var body = new byte[length];
                if (!await ReadExactAsync(pipe, body, ct))
                {
                    return;
                }
                var reply = await DispatchAsync(client, binds, body, ct);
                var frame = new byte[4 + reply.Length];
                BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)reply.Length);
                reply.CopyTo(frame, 4);
                await pipe.WriteAsync(frame, ct);
                await pipe.FlushAsync(ct);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            Log.Error("Agent connection failed", ex);
        }
    }

    private async Task<byte[]> DispatchAsync(AgentClient client, SessionBindState binds, byte[] body, CancellationToken ct)
    {
        try
        {
            switch (body[0])
            {
                case AgentMessage.RequestIdentities:
                    return AgentReplies.Identities(await _handler.ListAsync(client, ct));

                case AgentMessage.SignRequest:
                {
                    var request = ParseSign(body, binds);
                    var signature = await _handler.SignAsync(client, request, ct);
                    return signature == null ? AgentReplies.Failure() : AgentReplies.Signature(signature);
                }

                case AgentMessage.Extension:
                {
                    var name = ReadExtensionName(body, out var payloadOffset);
                    if (name == "session-bind@openssh.com")
                    {
                        return binds.Bind(body.AsSpan(payloadOffset)) ? AgentReplies.Success() : AgentReplies.Failure();
                    }
                    return AgentReplies.Failure();
                }

                default:
                    return AgentReplies.Failure();
            }
        }
        catch (SshFormatException ex)
        {
            Log.Warn("Malformed agent message: " + ex.Message);
            return AgentReplies.Failure();
        }
    }

    private static string ReadExtensionName(byte[] body, out int payloadOffset)
    {
        var r = new SshReader(body.AsSpan(1));
        var name = r.ReadUtf8();
        payloadOffset = body.Length - r.Remaining;
        return name;
    }

    internal static SignRequest ParseSign(byte[] body, SessionBindState binds)
    {
        var r = new SshReader(body.AsSpan(1));
        var keyBlob = r.ReadString().ToArray();
        var data = r.ReadString().ToArray();
        var flags = r.Remaining >= 4 ? r.ReadUInt32() : 0;

        var ns = SignDataInspector.DetectNamespace(data);
        var auth = ns == null ? SignDataInspector.ParseUserAuth(data) : null;
        string? host = null;
        if (auth != null)
        {
            host = binds.HostFor(auth.Value.SessionId) ?? binds.LastHostFingerprint;
        }
        return new SignRequest
        {
            KeyBlob = keyBlob,
            Data = data,
            Flags = flags,
            Namespace = ns,
            Kind = SignDataInspector.Classify(ns, auth != null),
            RemoteUser = auth?.User,
            IsForwarding = binds.IsForwarding,
            HostFingerprint = host,
        };
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0)
            {
                return false;
            }
            read += n;
        }
        return true;
    }

    /// <summary>Best effort: connects to the existing pipe to learn which process serves it.</summary>
    public static string? FindPipeOwner(string pipeName)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.None);
            client.Connect(500);
            if (GetNamedPipeServerProcessId(client.SafePipeHandle, out var pid))
            {
                var chain = ProcessInfo.GetChain((int)pid, 1);
                return $"{chain[0].Name} (PID {pid})";
            }
        }
        catch (Exception)
        {
        }
        return null;
    }

    private void SetState(PipeState state, string? owner)
    {
        if (State == state && BusyOwner == owner)
        {
            return;
        }
        State = state;
        BusyOwner = owner;
        StateChanged?.Invoke();
    }

    public async ValueTask DisposeAsync() => await StopAsync();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafeHandle pipe, out uint serverProcessId);
}
