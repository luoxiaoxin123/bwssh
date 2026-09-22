using System.Text;
using BwSshAgent.Core.Native;

namespace BwSshAgent.Core.Ssh;

public static class AgentMessage
{
    public const byte Failure = 5;
    public const byte Success = 6;
    public const byte RequestIdentities = 11;
    public const byte IdentitiesAnswer = 12;
    public const byte SignRequest = 13;
    public const byte SignResponse = 14;
    public const byte Extension = 27;

    public const int MaxMessageLength = 256 * 1024;
}

public enum SignKind
{
    SshAuth,
    GitSign,
    FileSign,
    OtherSign,
    Unknown,
}

public sealed class SignRequest
{
    public required byte[] KeyBlob { get; init; }
    public required byte[] Data { get; init; }
    public uint Flags { get; init; }
    public SignKind Kind { get; init; }
    public string? Namespace { get; init; }
    public string? RemoteUser { get; init; }
    public bool IsForwarding { get; init; }
    public string? HostFingerprint { get; init; }
}

public sealed record AgentIdentity(byte[] Blob, string Comment);

public sealed class AgentClient
{
    public required int Pid { get; init; }
    public required IReadOnlyList<ProcessNode> Chain { get; init; }
}

public interface IAgentHandler
{
    Task<IReadOnlyList<AgentIdentity>> ListAsync(AgentClient client, CancellationToken ct);

    /// <summary>Returns the signature blob, or null to answer SSH_AGENT_FAILURE.</summary>
    Task<byte[]?> SignAsync(AgentClient client, SignRequest request, CancellationToken ct);
}

public static class SignDataInspector
{
    /// <summary>
    /// SSHSIG signed data: byte[6] "SSHSIG", string namespace, string reserved, string hash_alg, string H(msg).
    /// See openssh-portable PROTOCOL.sshsig.
    /// </summary>
    public static string? DetectNamespace(ReadOnlySpan<byte> data)
    {
        var magic = "SSHSIG"u8;
        if (!data.StartsWith(magic))
        {
            return null;
        }
        try
        {
            var r = new SshReader(data[magic.Length..]);
            return r.ReadUtf8();
        }
        catch (SshFormatException)
        {
            return "";
        }
    }

    /// <summary>Parses an SSH_MSG_USERAUTH_REQUEST publickey payload: returns (sessionId, user) or null.</summary>
    public static (byte[] SessionId, string User)? ParseUserAuth(ReadOnlySpan<byte> data)
    {
        try
        {
            var r = new SshReader(data);
            var sessionId = r.ReadString().ToArray();
            if (r.ReadByte() != 50)
            {
                return null;
            }
            var user = r.ReadUtf8();
            var service = r.ReadUtf8();
            var method = r.ReadUtf8();
            if (service != "ssh-connection" || !method.StartsWith("publickey", StringComparison.Ordinal))
            {
                return null;
            }
            return (sessionId, user);
        }
        catch (SshFormatException)
        {
            return null;
        }
    }

    public static SignKind Classify(string? ns, bool isUserAuth) => ns switch
    {
        null => isUserAuth ? SignKind.SshAuth : SignKind.Unknown,
        "git" => SignKind.GitSign,
        "file" => SignKind.FileSign,
        _ => SignKind.OtherSign,
    };
}

/// <summary>Per-connection session-bind@openssh.com state.</summary>
public sealed class SessionBindState
{
    private readonly List<(byte[] SessionId, string HostFingerprint)> _binds = [];

    public bool IsForwarding { get; private set; }

    public string? LastHostFingerprint => _binds.Count > 0 ? _binds[^1].HostFingerprint : null;

    public string? HostFor(ReadOnlySpan<byte> sessionId)
    {
        foreach (var (sid, fp) in _binds)
        {
            if (sessionId.SequenceEqual(sid))
            {
                return fp;
            }
        }
        return null;
    }

    /// <summary>Parses and verifies the bind; returns false (agent FAILURE) when the host signature is invalid.</summary>
    public bool Bind(ReadOnlySpan<byte> payload)
    {
        try
        {
            var r = new SshReader(payload);
            var hostKey = r.ReadString();
            var sessionId = r.ReadString();
            var signature = r.ReadString();
            var forwarding = r.ReadByte() != 0;
            if (!SshKeyUtil.Verify(hostKey, signature, sessionId))
            {
                Log.Warn("session-bind signature verification failed");
                return false;
            }
            if (_binds.Count >= 16)
            {
                _binds.RemoveAt(0);
            }
            _binds.Add((sessionId.ToArray(), SshKeyUtil.Fingerprint(hostKey)));
            IsForwarding |= forwarding;
            return true;
        }
        catch (Exception ex) when (ex is SshFormatException or System.Security.Cryptography.CryptographicException)
        {
            Log.Warn("session-bind parse failed: " + ex.Message);
            return false;
        }
    }
}

internal static class AgentReplies
{
    public static byte[] Failure() => [AgentMessage.Failure];

    public static byte[] Success() => [AgentMessage.Success];

    public static byte[] Identities(IReadOnlyList<AgentIdentity> identities)
    {
        var w = new SshWriter().WriteByte(AgentMessage.IdentitiesAnswer).WriteUInt32((uint)identities.Count);
        foreach (var id in identities)
        {
            w.WriteString(id.Blob).WriteString(Encoding.UTF8.GetBytes(id.Comment));
        }
        return w.ToArray();
    }

    public static byte[] Signature(byte[] signatureBlob) =>
        new SshWriter().WriteByte(AgentMessage.SignResponse).WriteString(signatureBlob).ToArray();
}
