using System.Security.Cryptography;
using BwSshAgent.Core.Native;
using BwSshAgent.Core.Ssh;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace BwSshAgent.Core.Tests;

public class SshTests
{
    public static TheoryData<string, int> KeyTypes => new()
    {
        { "ed25519", 0 },
        { "rsa", 2048 },
        { "ecdsa", 256 },
        { "ecdsa", 384 },
        { "ecdsa", 521 },
    };

    [Theory]
    [MemberData(nameof(KeyTypes))]
    public void ParsesOpenSshKeysAndPublicBlobMatchesSshKeygen(string type, int bits)
    {
        var (pem, pub, _) = TestEnv.GenerateKey(type, bits);
        using var key = SshKeyParser.Parse(System.Text.Encoding.UTF8.GetBytes(pem));
        var parts = pub.Split(' ');
        Assert.Equal(parts[0], key.KeyType);
        Assert.Equal(parts[1], Convert.ToBase64String(key.PublicBlob));
    }

    [Theory]
    [MemberData(nameof(KeyTypes))]
    public void SignaturesVerify(string type, int bits)
    {
        var (pem, _, _) = TestEnv.GenerateKey(type, bits);
        using var key = SshKeyParser.Parse(pem);
        var data = RandomNumberGenerator.GetBytes(100);
        var flags = type == "rsa" ? SshSignFlags.RsaSha512 : 0u;
        var sig = key.Sign(data, flags);
        Assert.True(SshKeyUtil.Verify(key.PublicBlob, sig, data));
        data[0] ^= 1;
        Assert.False(SshKeyUtil.Verify(key.PublicBlob, sig, data));
    }

    [Fact]
    public void RsaRefusesSha1AndHonoursFlags()
    {
        var (pem, _, _) = TestEnv.GenerateKey("rsa", 2048);
        using var key = SshKeyParser.Parse(pem);
        Assert.Throws<SshSignException>(() => key.Sign([1, 2, 3], 0));
        Assert.Equal("rsa-sha2-256", SshKeyUtil.KeyTypeOf(key.Sign([1], SshSignFlags.RsaSha256)));
        Assert.Equal("rsa-sha2-512", SshKeyUtil.KeyTypeOf(key.Sign([1], SshSignFlags.RsaSha512)));
    }

    [Fact]
    public void ParsesPkcs8AndTraditionalPem()
    {
        using var rsa = RSA.Create(2048);
        using var fromPkcs8 = SshKeyParser.Parse(rsa.ExportPkcs8PrivateKeyPem());
        using var fromPkcs1 = SshKeyParser.Parse(rsa.ExportRSAPrivateKeyPem());
        Assert.Equal(fromPkcs8.PublicBlob, fromPkcs1.PublicBlob);

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var ecKey = SshKeyParser.Parse(ec.ExportPkcs8PrivateKeyPem());
        Assert.Equal("ecdsa-sha2-nistp384", ecKey.KeyType);

        var ed = new Ed25519PrivateKeyParameters(new Org.BouncyCastle.Security.SecureRandom());
        var info = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(ed);
        var edPem = "-----BEGIN PRIVATE KEY-----\n" + Convert.ToBase64String(info.GetEncoded()) + "\n-----END PRIVATE KEY-----\n";
        using var edKey = SshKeyParser.Parse(edPem);
        Assert.Equal("ssh-ed25519", edKey.KeyType);
    }

    [Fact]
    public void RejectsEncryptedAndGarbageKeys()
    {
        var dir = Path.Combine(TestEnv.Root, "keys");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "enc-" + Guid.NewGuid().ToString("N"));
        TestEnv.Run(TestEnv.SshKeygenPath, $"-q -t ed25519 -N secretpass -f \"{path}\"");
        Assert.Throws<SshPassphraseRequiredException>(() => SshKeyParser.Parse(File.ReadAllText(path)));
        Assert.Throws<SshFormatException>(() => SshKeyParser.Parse("not a key"));
    }

    [Theory]
    [InlineData("ed25519", 0)]
    [InlineData("ecdsa", 256)]
    [InlineData("ecdsa", 521)]
    [InlineData("rsa", 2048)]
    public void SessionBindVerifiesHostSignature(string type, int bits)
    {
        var (pem, _, _) = TestEnv.GenerateKey(type, bits);
        using var host = SshKeyParser.Parse(pem);
        var sessionId = RandomNumberGenerator.GetBytes(32);
        var sig = host.Sign(sessionId, SshSignFlags.RsaSha256);

        var state = new SessionBindState();
        Assert.True(state.Bind(BindPayload(host.PublicBlob, sessionId, sig, forwarding: false)));
        Assert.Equal(host.Fingerprint, state.HostFor(sessionId));
        Assert.False(state.IsForwarding);

        var otherSession = RandomNumberGenerator.GetBytes(32);
        Assert.False(state.Bind(BindPayload(host.PublicBlob, otherSession, sig, forwarding: false)));

        var forwardedSig = host.Sign(otherSession, SshSignFlags.RsaSha256);
        Assert.True(state.Bind(BindPayload(host.PublicBlob, otherSession, forwardedSig, forwarding: true)));
        Assert.True(state.IsForwarding);
    }

    private static byte[] BindPayload(byte[] hostKey, byte[] sessionId, byte[] sig, bool forwarding) =>
        new SshWriter().WriteString(hostKey).WriteString(sessionId).WriteString(sig).WriteByte(forwarding ? (byte)1 : (byte)0).ToArray();

    [Fact]
    public void DetectsSshSigNamespaceAndUserAuth()
    {
        var git = new SshWriter().WriteRaw("SSHSIG"u8).WriteString("git").WriteString("").WriteString("sha512").WriteString(new byte[64]).ToArray();
        Assert.Equal("git", SignDataInspector.DetectNamespace(git));
        Assert.Equal(SignKind.GitSign, SignDataInspector.Classify("git", false));
        Assert.Equal(SignKind.OtherSign, SignDataInspector.Classify("email", false));

        var auth = new SshWriter().WriteString(new byte[32]).WriteByte(50).WriteString("git").WriteString("ssh-connection")
            .WriteString("publickey").WriteByte(1).WriteString("ssh-ed25519").WriteString(new byte[51]).ToArray();
        Assert.Null(SignDataInspector.DetectNamespace(auth));
        Assert.Equal("git", SignDataInspector.ParseUserAuth(auth)!.Value.User);
        Assert.Null(SignDataInspector.ParseUserAuth("random"u8));
    }

    [Theory]
    [InlineData("ssh.exe -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'a/b.git'\"", "git@github.com")]
    [InlineData("C:\\Windows\\System32\\OpenSSH\\ssh.exe -p 2222 -i key.pem deploy@example.com uptime", "deploy@example.com:2222")]
    [InlineData("ssh -l root -J jump host.internal", "root@host.internal")]
    [InlineData("ssh -oPort=22 -v ssh://git@gitlab.com:2200/x", "git@gitlab.com:2200")]
    [InlineData("ssh -T", null)]
    public void ParsesSshDestination(string commandLine, string? expected)
    {
        Assert.Equal(expected, ProcessInfo.ParseSshDestination(commandLine));
    }

    [Fact]
    public void GrantTargetSkipsShellsAndTools()
    {
        var chain = TestEnv.FakeChain();
        Assert.Equal("claude.exe", ProcessInfo.GrantTarget(chain).Name);
        var own = ProcessInfo.GetChain(Environment.ProcessId);
        Assert.Equal(Environment.ProcessId, own[0].Pid);
        Assert.NotNull(own[0].ImagePath);
        Assert.NotNull(own[0].CommandLine);
    }

    [Fact]
    public void Ed25519KeyRejectsMismatchedPublicKey()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        Assert.Throws<SshFormatException>(() => new Ed25519SshKey(seed, new byte[32]));
        var pub = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
        using var key = new Ed25519SshKey(seed, pub);
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(pub, 0));
        var sig = key.Sign("x"u8, 0);
        Assert.True(SshKeyUtil.Verify(key.PublicBlob, sig, "x"u8));
    }
}

/// <summary>Drives the real Windows OpenSSH client tools against our named-pipe agent.</summary>
public class OpenSshEndToEndTests
{
    private sealed class AutoApproveHandler(List<SshPrivateKey> keys) : IAgentHandler
    {
        public List<SignRequest> Requests { get; } = [];
        public List<AgentClient> Clients { get; } = [];

        public Task<IReadOnlyList<AgentIdentity>> ListAsync(AgentClient client, CancellationToken ct)
        {
            Clients.Add(client);
            return Task.FromResult<IReadOnlyList<AgentIdentity>>(keys.Select(k => new AgentIdentity(k.PublicBlob, "key-" + k.KeyType)).ToList());
        }

        public Task<byte[]?> SignAsync(AgentClient client, SignRequest request, CancellationToken ct)
        {
            lock (Requests)
            {
                Requests.Add(request);
                Clients.Add(client);
            }
            var key = keys.First(k => k.PublicBlob.AsSpan().SequenceEqual(request.KeyBlob));
            return Task.FromResult<byte[]?>(key.Sign(request.Data, request.Flags));
        }
    }

    [Fact]
    public async Task SshAddListsAndSshKeygenSignsThroughAgent()
    {
        Assert.True(File.Exists(TestEnv.SshKeygenPath), "Windows OpenSSH client is required");
        var generated = new[] { ("ed25519", 0), ("rsa", 2048), ("ecdsa", 256), ("ecdsa", 521) }
            .Select(t => TestEnv.GenerateKey(t.Item1, t.Item2)).ToList();
        var keys = generated.Select(g => SshKeyParser.Parse(g.PrivatePem)).ToList();
        var handler = new AutoApproveHandler(keys);
        var pipeName = "bwssh-test-" + Guid.NewGuid().ToString("N");
        await using var server = new AgentPipeServer(handler, pipeName);
        server.Start();
        for (var i = 0; i < 50 && server.State != PipeState.Listening; i++)
        {
            await Task.Delay(50);
        }
        Assert.Equal(PipeState.Listening, server.State);

        var env = new Dictionary<string, string> { ["SSH_AUTH_SOCK"] = server.PipePath };
        var (code, output) = TestEnv.Run(TestEnv.SshAddPath, "-L", env);
        Assert.Equal(0, code);
        foreach (var g in generated)
        {
            Assert.Contains(g.PublicLine.Split(' ')[1], output);
        }
        Assert.Contains(handler.Clients, c => c.Chain[0].Name.Equals("ssh-add.exe", StringComparison.OrdinalIgnoreCase));

        var message = Path.Combine(TestEnv.Root, "msg-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(message, "hello from the agent test");
        foreach (var (pem, pub, path) in generated)
        {
            // Remove the private key so ssh-keygen must use the agent.
            File.Delete(path);
            var pubPath = path + ".pub";
            (code, output) = TestEnv.Run(TestEnv.SshKeygenPath, $"-Y sign -f \"{pubPath}\" -n git \"{message}\"", env);
            Assert.True(code == 0, output);

            var allowed = Path.Combine(TestEnv.Root, "allowed-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(allowed, "test@example.com " + pub + "\n");
            (code, output) = TestEnv.Run(TestEnv.SshKeygenPath,
                $"-Y verify -f \"{allowed}\" -I test@example.com -n git -s \"{message}.sig\"", env, File.ReadAllText(message));
            Assert.True(code == 0, output);
            File.Delete(message + ".sig");
        }

        Assert.Equal(generated.Count, handler.Requests.Count);
        Assert.All(handler.Requests, r =>
        {
            Assert.Equal(SignKind.GitSign, r.Kind);
            Assert.Equal("git", r.Namespace);
        });
        Assert.Contains(handler.Requests, r => r.Flags == SshSignFlags.RsaSha512);
        foreach (var k in keys)
        {
            k.Dispose();
        }
    }

    [Fact]
    public async Task PipeReportsBusyWhenNameTaken()
    {
        var pipeName = "bwssh-test-" + Guid.NewGuid().ToString("N");
        await using var first = new AgentPipeServer(new AutoApproveHandler([]), pipeName);
        first.Start();
        for (var i = 0; i < 50 && first.State != PipeState.Listening; i++)
        {
            await Task.Delay(50);
        }
        await using var second = new AgentPipeServer(new AutoApproveHandler([]), pipeName);
        second.Start();
        for (var i = 0; i < 50 && second.State != PipeState.Busy; i++)
        {
            await Task.Delay(50);
        }
        Assert.Equal(PipeState.Busy, second.State);
        Assert.Contains("PID " + Environment.ProcessId, second.BusyOwner);
    }
}
