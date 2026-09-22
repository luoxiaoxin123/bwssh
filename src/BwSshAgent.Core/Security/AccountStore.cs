using System.Text.Json;
using System.Text.Json.Serialization;
using BwSshAgent.Core.Bitwarden;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Storage;

namespace BwSshAgent.Core.Security;

public sealed class AccountState
{
    public ServerKind ServerKind { get; set; }
    public string? BaseUrl { get; set; }
    public string? IdentityUrl { get; set; }
    public string? ApiUrl { get; set; }
    public string Email { get; set; } = "";
    public string UserId { get; set; } = "";
    public KdfConfig? Kdf { get; set; }
    public string? Salt { get; set; }
    public string? AccessToken { get; set; }
    public DateTimeOffset AccessTokenExpiry { get; set; }
    public string? RefreshToken { get; set; }
    public string? ApiClientId { get; set; }
    public string? ApiClientSecret { get; set; }
    public bool NeedsReauth { get; set; }

    [JsonIgnore]
    public ServerEnvironment Environment
    {
        get => new(ServerKind, BaseUrl, IdentityUrl, ApiUrl);
        set
        {
            ServerKind = value.Kind;
            BaseUrl = value.BaseUrl;
            IdentityUrl = value.CustomIdentityUrl;
            ApiUrl = value.CustomApiUrl;
        }
    }
}

public sealed class PublicKeyEntry
{
    public string CipherId { get; set; } = "";
    public string Name { get; set; } = "";
    public string KeyType { get; set; } = "";
    public string BlobBase64 { get; set; } = "";
    public string Fingerprint { get; set; } = "";

    [JsonIgnore]
    public byte[] Blob => _blob ??= Convert.FromBase64String(BlobBase64);

    private byte[]? _blob;

    public string PublicKeyLine => $"{KeyType} {BlobBase64} {Name}".TrimEnd();
}

/// <summary>DPAPI-protected persistence for account, vault cache and key list.</summary>
public static class AccountStore
{
    public const string AccountFile = "account.dat";
    public const string VaultFile = "vault.dat";
    public const string PublicKeysFile = "pubkeys.dat";
    public const string RememberFile = "remember.dat";
    private const string DeviceFile = "device.json";

    public static AccountState? LoadAccount() => SecureFile.ReadJson<AccountState>(AccountFile);

    public static void SaveAccount(AccountState state) => SecureFile.WriteJson(AccountFile, state);

    public static VaultSnapshot? LoadSnapshot() => SecureFile.ReadJson<VaultSnapshot>(VaultFile);

    public static void SaveSnapshot(VaultSnapshot snapshot) => SecureFile.WriteJson(VaultFile, snapshot);

    public static List<PublicKeyEntry> LoadPublicKeys() => SecureFile.ReadJson<List<PublicKeyEntry>>(PublicKeysFile) ?? [];

    public static void SavePublicKeys(List<PublicKeyEntry> keys) => SecureFile.WriteJson(PublicKeysFile, keys);

    public static void DeleteAccountData()
    {
        SecureFile.Delete(AccountFile);
        SecureFile.Delete(VaultFile);
        SecureFile.Delete(PublicKeysFile);
    }

    public static string DeviceId
    {
        get
        {
            var path = AppPaths.File(DeviceFile);
            try
            {
                if (File.Exists(path))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(path));
                    if (doc.RootElement.TryGetProperty("deviceId", out var id) && Guid.TryParse(id.GetString(), out var g))
                    {
                        return g.ToString();
                    }
                }
            }
            catch (Exception)
            {
            }
            var created = Guid.NewGuid().ToString();
            File.WriteAllText(path, JsonSerializer.Serialize(new { deviceId = created }));
            return created;
        }
    }

    private static string RememberKey(ServerEnvironment env, string email) => $"{env.IdentityUrl}|{email.Trim().ToLowerInvariant()}";

    public static string? GetTwoFactorRemember(ServerEnvironment env, string email) =>
        SecureFile.ReadJson<Dictionary<string, string>>(RememberFile)?.GetValueOrDefault(RememberKey(env, email));

    public static void SetTwoFactorRemember(ServerEnvironment env, string email, string? token)
    {
        var map = SecureFile.ReadJson<Dictionary<string, string>>(RememberFile) ?? [];
        if (token == null)
        {
            map.Remove(RememberKey(env, email));
        }
        else
        {
            map[RememberKey(env, email)] = token;
        }
        SecureFile.WriteJson(RememberFile, map);
    }
}
