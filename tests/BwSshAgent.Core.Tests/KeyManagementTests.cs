using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using BwSshAgent.Core.Bitwarden;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Ssh;

namespace BwSshAgent.Core.Tests;

public class KeyFormatTests
{
    [Fact]
    public void BlowfishInitialStateMatchesPublishedConstants()
    {
        var w = BcryptPbkdf.PiWords.Value;
        Assert.Equal(0x243F6A88u, w[0]);   // P[0]
        Assert.Equal(0x8979FB1Bu, w[17]);  // P[17]
        Assert.Equal(0xD1310BA6u, w[18]);  // S0[0]
        Assert.Equal(0x3AC372E6u, w[^1]);  // S3[255]
    }

    [Theory]
    [InlineData("ed25519", 0, null)]
    [InlineData("rsa", 2048, null)]
    [InlineData("ecdsa", 384, null)]
    [InlineData("ed25519", 0, "aes256-gcm@openssh.com")]
    [InlineData("ed25519", 0, "aes256-cbc")]
    [InlineData("ecdsa", 256, "aes128-ctr")]
    public void ImportsPassphraseProtectedOpenSshKeys(string type, int bits, string? cipher)
    {
        var dir = Path.Combine(TestEnv.Root, "keys");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "enc-" + Guid.NewGuid().ToString("N"));
        var args = $"-q -t {type} {(bits > 0 ? "-b " + bits : "")} -N \"s3cret pass\" -a 4 {(cipher != null ? "-Z " + cipher : "")} -f \"{path}\"";
        var (code, output) = TestEnv.Run(TestEnv.SshKeygenPath, args);
        Assert.True(code == 0, output);
        var pem = File.ReadAllText(path);
        var pub = File.ReadAllText(path + ".pub").Split(' ')[1];

        Assert.Throws<SshPassphraseRequiredException>(() => SshKeyParser.Parse(pem));
        Assert.Throws<SshWrongPassphraseException>(() => SshKeyParser.Parse(pem, "wrong"));
        using var key = SshKeyParser.Parse(pem, "s3cret pass");
        Assert.Equal(pub, Convert.ToBase64String(key.PublicBlob));
    }

    [Theory]
    [InlineData("ed25519")]
    [InlineData("rsa")]
    [InlineData("ecdsa")]
    public void SerializedKeysAreAcceptedByOpenSsh(string type)
    {
        using var key = type switch
        {
            "ed25519" => SshKeyFactory.GenerateEd25519(),
            "rsa" => SshKeyFactory.GenerateRsa(2048),
            _ => SshKeyParser.Parse(ECDsa.Create(ECCurve.NamedCurves.nistP521).ExportPkcs8PrivateKeyPem()),
        };
        var pem = SshKeyFactory.ToOpenSshPem(key, "roundtrip");
        Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n", pem);

        var path = Path.Combine(TestEnv.Root, "keys", "ser-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, pem);
        RestrictToCurrentUser(path); // OpenSSH refuses private key files others can read
        var (code, output) = TestEnv.Run(TestEnv.SshKeygenPath, $"-y -f \"{path}\"");
        Assert.True(code == 0, output);
        Assert.Equal(key.PublicKeyLine("").Split(' ')[1], output.Trim().Split(' ')[1]);

        using var reparsed = SshKeyParser.Parse(pem);
        Assert.Equal(key.PublicBlob, reparsed.PublicBlob);
        var data = RandomNumberGenerator.GetBytes(32);
        Assert.True(SshKeyUtil.Verify(key.PublicBlob, reparsed.Sign(data, SshSignFlags.RsaSha256), data));
    }

    private static void RestrictToCurrentUser(string path)
    {
        var security = new System.Security.AccessControl.FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            System.Security.Principal.WindowsIdentity.GetCurrent().User!,
            System.Security.AccessControl.FileSystemRights.FullControl,
            System.Security.AccessControl.AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    [Fact]
    public void ImportsEncryptedPkcs8AndTraditionalPem()
    {
        using var rsa = RSA.Create(2048);
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10000);
        var encrypted = rsa.ExportEncryptedPkcs8PrivateKeyPem("pkcs8pass", pbe);
        Assert.Throws<SshPassphraseRequiredException>(() => SshKeyParser.Parse(encrypted));
        Assert.Throws<SshWrongPassphraseException>(() => SshKeyParser.Parse(encrypted, "nope"));
        using var fromPkcs8 = SshKeyParser.Parse(encrypted, "pkcs8pass");
        using var plain = SshKeyParser.Parse(rsa.ExportPkcs8PrivateKeyPem());
        Assert.Equal(plain.PublicBlob, fromPkcs8.PublicBlob);

        var dir = Path.Combine(TestEnv.Root, "keys");
        var path = Path.Combine(dir, "pem-" + Guid.NewGuid().ToString("N"));
        var (code, output) = TestEnv.Run(TestEnv.SshKeygenPath, $"-q -t rsa -b 2048 -m PEM -N legacypass -f \"{path}\"");
        Assert.True(code == 0, output);
        var pem = File.ReadAllText(path);
        Assert.Contains("BEGIN RSA PRIVATE KEY", pem);
        using var legacy = SshKeyParser.Parse(pem, "legacypass");
        Assert.Equal(File.ReadAllText(path + ".pub").Split(' ')[1], Convert.ToBase64String(legacy.PublicBlob));
    }

    [Fact]
    public void RejectsPuttyKeys()
    {
        var ex = Assert.Throws<SshFormatException>(() => SshKeyParser.Parse("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"));
        Assert.Contains("PuTTY", ex.Message);
    }
}

public class VaultWriteTests
{
    private sealed class RecordingServer : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string Body)> Requests { get; } = [];
        public required Func<string> SyncJson { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content == null ? "" : await request.Content.ReadAsStringAsync(ct);
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method, path, body));
            var json = path == "/api/sync" ? SyncJson() : "{}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }

    [Fact]
    public void NewSshKeyRequestDecryptsLikeASyncedItem()
    {
        TestEnv.ResetAppData();
        var fx = new VaultFixture();
        using var key = SshKeyFactory.GenerateEd25519();
        var pem = SshKeyFactory.ToOpenSshPem(key);
        var request = CipherRequests.NewSshKey(fx.UserId, fx.UserKey, "新密钥", pem, key.PublicKeyLine(""), key.Fingerprint);

        request["id"] = "new-id";
        fx.Ciphers.Add(JsonNode.Parse(request.ToJsonString()));
        var snapshot = VaultSnapshot.FromSyncJson(fx.SyncJson());
        var item = VaultDecryptor.DecryptSshKeys(snapshot, fx.UserKey).Items.Single();
        Assert.Equal("新密钥", item.Name);
        Assert.Equal(pem, Encoding.UTF8.GetString(item.PrivateKeyUtf8));

        var json = request.ToJsonString();
        Assert.DoesNotContain("新密钥", json);
        Assert.DoesNotContain("OPENSSH", json);
        Assert.DoesNotContain(key.Fingerprint, json);
        Assert.DoesNotContain(Convert.ToBase64String(key.PublicBlob), json);
    }

    [Fact]
    public void RenameKeepsNotesFieldsAndAttachments()
    {
        TestEnv.ResetAppData();
        var fx = new VaultFixture();
        var id = fx.AddOrgKeyWithItemKey("old name", TestEnv.GenerateKey("ed25519").PrivatePem);
        var raw = (JsonObject)fx.Ciphers[^1]!;
        raw["Notes"] = "2.notes|x|y";
        raw["Fields"] = new JsonArray { new JsonObject { ["Type"] = 0, ["Name"] = "2.a|b|c", ["Value"] = "2.d|e|f" } };
        raw["Attachments"] = new JsonArray { new JsonObject { ["Id"] = "att1", ["FileName"] = "2.f|n|m", ["Key"] = "2.k|k|k", ["Size"] = "10" } };
        raw["RevisionDate"] = "2026-09-01T00:00:00Z";
        raw["FolderId"] = "folder-1";

        var snapshot = VaultSnapshot.FromSyncJson(fx.SyncJson());
        var cipher = snapshot.SshCiphers.Single(c => c.Id == id);
        using var cipherKey = VaultDecryptor.ResolveCipherKey(snapshot, cipher, fx.UserKey);
        var request = CipherRequests.Rename(cipher, fx.UserId, cipherKey, "new name");

        Assert.Equal("new name", EncString.Parse(request["name"]!.GetValue<string>()).DecryptToString(cipherKey));
        Assert.Equal("2.notes|x|y", request["notes"]!.GetValue<string>());
        Assert.Equal("folder-1", request["folderId"]!.GetValue<string>());
        Assert.Equal(fx.OrgId, request["organizationId"]!.GetValue<string>());
        Assert.Equal(cipher.Key, request["key"]!.GetValue<string>());
        Assert.Equal("2.d|e|f", request["fields"]![0]!["Value"]!.GetValue<string>());
        Assert.Equal("2.k|k|k", request["attachments2"]!["att1"]!["key"]!.GetValue<string>());
        Assert.Equal("2026-09-01T00:00:00Z", request["lastKnownRevisionDate"]!.GetValue<string>());
        Assert.Equal(cipher.PrivateKey, request["sshKey"]!["privateKey"]!.GetValue<string>());
    }

    [Fact]
    public async Task AddRenameDeleteCallTheCipherEndpointsAndResync()
    {
        TestEnv.ResetAppData();
        var (session, fx, _) = await VaultTests.LoggedInSessionAsync();
        var server = new RecordingServer { SyncJson = fx.SyncJson };
        var account = session.Account!;
        account.AccessToken = "token";
        account.AccessTokenExpiry = DateTimeOffset.UtcNow.AddHours(1);
        using var manager = new AccountManager(session, new BitwardenApi(server));

        using (var key = SshKeyFactory.GenerateEd25519())
        {
            Assert.Null(await manager.AddSshKeyAsync("  work laptop ", key));
        }
        var cipherId = session.PublicKeys.Single().CipherId;
        Assert.Null(await manager.RenameSshKeyAsync(cipherId, "renamed"));
        Assert.Null(await manager.DeleteSshKeyAsync(cipherId));

        var calls = server.Requests.Where(r => r.Path != "/api/sync").Select(r => $"{r.Method} {r.Path}").ToList();
        Assert.Equal(new[] { "POST /api/ciphers", $"PUT /api/ciphers/{cipherId}", $"PUT /api/ciphers/{cipherId}/delete" }, calls);
        Assert.Equal(3, server.Requests.Count(r => r.Path == "/api/sync"));
        Assert.DoesNotContain(server.Requests, r => r.Body.Contains("work laptop") || r.Body.Contains("renamed") || r.Body.Contains("PRIVATE KEY"));

        session.Lock("test");
        Assert.Equal("请先解锁密码库。", await manager.DeleteSshKeyAsync(cipherId));
    }
}
