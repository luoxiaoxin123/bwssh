using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Native;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Storage;

namespace BwSshAgent.Core.Tests;

internal static class TestLanguage
{
    // Assertions check Chinese messages; pin the language so tests pass on English CI machines too.
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void Init() => L.Zh = true;
}

internal static class TestEnv
{
    private static readonly Lazy<string> RootDir = new(() =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "bwssh-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        AppPaths.Root = Path.Combine(dir, "appdata");
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try
            {
                Directory.Delete(dir, true);
            }
            catch (Exception)
            {
            }
        };
        return dir;
    });

    public static string Root => RootDir.Value;

    /// <summary>Fresh app-data directory so tests don't share DPAPI files.</summary>
    public static void ResetAppData()
    {
        _ = Root;
        AppPaths.Root = Path.Combine(Root, "appdata-" + Guid.NewGuid().ToString("N"));
    }

    public static string SshKeygenPath => Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe");
    public static string SshAddPath => Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-add.exe");

    public static (string PrivatePem, string PublicLine, string Path) GenerateKey(string type, int bits = 0, string comment = "test")
    {
        var dir = System.IO.Path.Combine(Root, "keys");
        Directory.CreateDirectory(dir);
        var path = System.IO.Path.Combine(dir, $"{type}-{bits}-{Guid.NewGuid():N}");
        var args = $"-q -t {type} {(bits > 0 ? "-b " + bits : "")} -N \"\" -C {comment} -f \"{path}\"";
        var (code, output) = Run(SshKeygenPath, args);
        Assert.True(code == 0, "ssh-keygen failed: " + output);
        return (File.ReadAllText(path), File.ReadAllText(path + ".pub").Trim(), path);
    }

    public static (int Code, string Output) Run(string exe, string args, IDictionary<string, string>? env = null, string? stdin = null)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin != null,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (env != null)
        {
            foreach (var kv in env)
            {
                psi.Environment[kv.Key] = kv.Value;
            }
        }
        using var p = Process.Start(psi)!;
        if (stdin != null)
        {
            p.StandardInput.Write(stdin);
            p.StandardInput.Close();
        }
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(30_000))
        {
            p.Kill(true);
            return (-1, "timeout");
        }
        return (p.ExitCode, stdout.Result + stderr.Result);
    }

    public static IReadOnlyList<ProcessNode> FakeChain(int rootPid = 100, string root = "claude.exe") =>
    [
        new ProcessNode(rootPid + 2, "ssh.exe", @"C:\Windows\System32\OpenSSH\ssh.exe", 3, "ssh.exe -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'a/b.git'\""),
        new ProcessNode(rootPid + 1, "git.exe", @"C:\Program Files\Git\cmd\git.exe", 2, "git fetch"),
        new ProcessNode(rootPid, root, @"C:\Tools\" + root, 1, root),
    ];
}

/// <summary>Builds an encrypted Bitwarden account + /sync payload the same way the server would store it.</summary>
internal sealed class VaultFixture
{
    public const string Password = "correct horse battery staple";
    public const string Email = "user@example.com";
    public static readonly KdfConfig Kdf = new(KdfType.Pbkdf2, 5000, null, null);

    public SymmetricKey UserKey { get; } = SymmetricKey.Generate();
    public SymmetricKey OrgKey { get; } = SymmetricKey.Generate();
    public string EncUserKey { get; }
    public string OrgId { get; } = Guid.NewGuid().ToString();
    public string UserId { get; } = Guid.NewGuid().ToString();
    public JsonArray Ciphers { get; } = [];
    private readonly RSA _rsa = RSA.Create(2048);

    public VaultFixture()
    {
        var masterKey = KeyDerivation.DeriveMasterKey(Password, Email, Kdf);
        using var stretched = KeyDerivation.StretchKey(masterKey);
        EncUserKey = EncString.Encrypt(UserKey.ToBytes(), stretched);
    }

    public string AddPersonalKey(string name, string pem)
    {
        var id = Guid.NewGuid().ToString();
        Ciphers.Add(new JsonObject
        {
            ["id"] = id,
            ["type"] = 5,
            ["organizationId"] = null,
            ["key"] = null,
            ["name"] = EncString.Encrypt(name, UserKey),
            ["deletedDate"] = null,
            ["sshKey"] = new JsonObject { ["privateKey"] = EncString.Encrypt(pem, UserKey), ["publicKey"] = "x", ["keyFingerprint"] = "x" },
        });
        return id;
    }

    public string AddOrgKeyWithItemKey(string name, string pem)
    {
        var id = Guid.NewGuid().ToString();
        using var itemKey = SymmetricKey.Generate();
        Ciphers.Add(new JsonObject
        {
            ["Id"] = id,
            ["Type"] = 5,
            ["OrganizationId"] = OrgId,
            ["Key"] = EncString.Encrypt(itemKey.ToBytes(), OrgKey),
            ["Name"] = EncString.Encrypt(name, itemKey),
            ["SshKey"] = new JsonObject { ["PrivateKey"] = EncString.Encrypt(pem, itemKey) },
        });
        return id;
    }

    public void AddNoise(string pem)
    {
        Ciphers.Add(new JsonObject { ["id"] = "login", ["type"] = 1, ["name"] = EncString.Encrypt("login", UserKey) });
        Ciphers.Add(new JsonObject
        {
            ["id"] = "deleted",
            ["type"] = 5,
            ["deletedDate"] = "2026-01-01T00:00:00Z",
            ["name"] = EncString.Encrypt("deleted", UserKey),
            ["sshKey"] = new JsonObject { ["privateKey"] = EncString.Encrypt(pem, UserKey) },
        });
        Ciphers.Add(new JsonObject
        {
            ["id"] = "archived",
            ["type"] = 5,
            ["archivedDate"] = "2026-01-01T00:00:00Z",
            ["name"] = EncString.Encrypt("archived", UserKey),
            ["sshKey"] = new JsonObject { ["privateKey"] = EncString.Encrypt(pem, UserKey) },
        });
    }

    public string SyncJson()
    {
        var root = new JsonObject
        {
            ["object"] = "sync",
            ["profile"] = new JsonObject
            {
                ["id"] = UserId,
                ["email"] = Email,
                ["key"] = EncUserKey,
                ["privateKey"] = EncString.Encrypt(_rsa.ExportPkcs8PrivateKey(), UserKey),
                ["organizations"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = OrgId,
                        ["key"] = "4." + Convert.ToBase64String(_rsa.Encrypt(OrgKey.ToBytes(), RSAEncryptionPadding.OaepSHA1)),
                    },
                },
            },
            ["ciphers"] = JsonNode.Parse(Ciphers.ToJsonString()),
            ["userDecryption"] = new JsonObject
            {
                ["masterPasswordUnlock"] = new JsonObject
                {
                    ["kdf"] = new JsonObject { ["kdfType"] = 0, ["iterations"] = Kdf.Iterations },
                    ["salt"] = Email,
                    ["masterKeyEncryptedUserKey"] = EncUserKey,
                },
            },
        };
        return root.ToJsonString();
    }

    public AccountState Account() => new()
    {
        Environment = Bitwarden.ServerEnvironment.SelfHosted("https://vault.example.test"),
        Email = Email,
        UserId = UserId,
        Kdf = Kdf,
        Salt = Email,
        RefreshToken = "refresh",
    };
}
