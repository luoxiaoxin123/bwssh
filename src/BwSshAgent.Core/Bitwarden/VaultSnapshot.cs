using System.Security.Cryptography;
using System.Text.Json.Nodes;
using BwSshAgent.Core.Crypto;

namespace BwSshAgent.Core.Bitwarden;

public sealed class EncryptedSshCipher
{
    public string Id { get; set; } = "";
    public string? OrganizationId { get; set; }
    public string? Key { get; set; }
    public string? Name { get; set; }
    public string? PrivateKey { get; set; }
    public string? PublicKey { get; set; }
    public string? Fingerprint { get; set; }

    /// <summary>The whole cipher object from /sync (still encrypted), needed to update it without losing fields.</summary>
    public string? Raw { get; set; }
}

public sealed class EncryptedOrgKey
{
    public string Id { get; set; } = "";
    public string Key { get; set; } = "";
}

/// <summary>
/// The subset of /sync kept on disk. All values remain encrypted exactly as the server returned them.
/// </summary>
public sealed class VaultSnapshot
{
    public string UserId { get; set; } = "";
    public string Email { get; set; } = "";
    public string? EncUserKey { get; set; }
    public KdfConfig? Kdf { get; set; }
    public string? Salt { get; set; }
    public string? EncPrivateKey { get; set; }
    public List<EncryptedOrgKey> Organizations { get; set; } = [];
    public List<EncryptedSshCipher> SshCiphers { get; set; } = [];
    public DateTimeOffset SyncedAt { get; set; }

    public static VaultSnapshot FromSyncJson(string json)
    {
        var root = JsonNode.Parse(json) ?? throw new BitwardenApiException(L.T("同步数据为空。", "Empty sync response."));
        var profile = J.Get(root, "Profile");
        var snapshot = new VaultSnapshot
        {
            UserId = J.Str(profile, "Id") ?? "",
            Email = J.Str(profile, "Email") ?? "",
            EncUserKey = J.Str(profile, "Key"),
            SyncedAt = DateTimeOffset.UtcNow,
        };

        var accountKeys = J.Get(profile, "AccountKeys");
        snapshot.EncPrivateKey = J.Str(J.Get(accountKeys, "PublicKeyEncryptionKeyPair"), "WrappedPrivateKey")
            ?? J.Str(profile, "PrivateKey");

        var unlock = J.Get(J.Get(root, "UserDecryption"), "MasterPasswordUnlock");
        if (unlock != null)
        {
            snapshot.EncUserKey ??= J.Str(unlock, "MasterKeyEncryptedUserKey");
            snapshot.Salt = J.Str(unlock, "Salt");
            var kdf = J.Get(unlock, "Kdf");
            if (kdf != null)
            {
                snapshot.Kdf = BitwardenApi.ParseKdf(kdf, "KdfType", "Iterations", "Memory", "Parallelism");
            }
        }

        foreach (var org in J.Arr(profile, "Organizations"))
        {
            var id = J.Str(org, "Id");
            var key = J.Str(org, "Key");
            if (id != null && key != null)
            {
                snapshot.Organizations.Add(new EncryptedOrgKey { Id = id, Key = key });
            }
        }

        foreach (var cipher in J.Arr(root, "Ciphers"))
        {
            if (J.Int(cipher, "Type") != 5 || !J.IsNull(cipher, "DeletedDate") || !J.IsNull(cipher, "ArchivedDate"))
            {
                continue;
            }
            var ssh = J.Get(cipher, "SshKey");
            if (ssh == null)
            {
                continue;
            }
            snapshot.SshCiphers.Add(new EncryptedSshCipher
            {
                Id = J.Str(cipher, "Id") ?? "",
                OrganizationId = J.Str(cipher, "OrganizationId"),
                Key = J.Str(cipher, "Key"),
                Name = J.Str(cipher, "Name"),
                PrivateKey = J.Str(ssh, "PrivateKey"),
                PublicKey = J.Str(ssh, "PublicKey"),
                Fingerprint = J.Str(ssh, "KeyFingerprint"),
                Raw = cipher!.ToJsonString(),
            });
        }
        return snapshot;
    }
}

public sealed record DecryptedSshItem(string CipherId, string Name, byte[] PrivateKeyUtf8);

public sealed record DecryptResult(List<DecryptedSshItem> Items, List<string> Errors);

public static class VaultDecryptor
{
    public static DecryptResult DecryptSshKeys(VaultSnapshot snapshot, SymmetricKey userKey)
    {
        var items = new List<DecryptedSshItem>();
        var errors = new List<string>();
        var orgKeys = new Dictionary<string, SymmetricKey>(StringComparer.OrdinalIgnoreCase);

        try
        {
            if (snapshot.SshCiphers.Any(c => c.OrganizationId != null) && snapshot.EncPrivateKey != null)
            {
                LoadOrgKeys(snapshot, userKey, orgKeys, errors);
            }

            foreach (var cipher in snapshot.SshCiphers)
            {
                try
                {
                    SymmetricKey baseKey;
                    if (cipher.OrganizationId != null)
                    {
                        if (!orgKeys.TryGetValue(cipher.OrganizationId, out baseKey!))
                        {
                            errors.Add(L.T($"条目 {cipher.Id}: 缺少组织密钥", $"Item {cipher.Id}: missing organization key"));
                            continue;
                        }
                    }
                    else
                    {
                        baseKey = userKey;
                    }

                    SymmetricKey? itemKey = null;
                    if (!string.IsNullOrEmpty(cipher.Key))
                    {
                        var raw = EncString.Parse(cipher.Key).DecryptToBytes(baseKey);
                        itemKey = new SymmetricKey(raw);
                        CryptographicOperations.ZeroMemory(raw);
                    }
                    try
                    {
                        var key = itemKey ?? baseKey;
                        if (string.IsNullOrEmpty(cipher.PrivateKey))
                        {
                            continue;
                        }
                        var name = cipher.Name == null ? L.T("(未命名)", "(unnamed)") : EncString.Parse(cipher.Name).DecryptToString(key);
                        var privateKey = EncString.Parse(cipher.PrivateKey).DecryptToBytes(key);
                        items.Add(new DecryptedSshItem(cipher.Id, name, privateKey));
                    }
                    finally
                    {
                        itemKey?.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    errors.Add(L.T($"条目 {cipher.Id}: {ex.Message}", $"Item {cipher.Id}: {ex.Message}"));
                }
            }
        }
        finally
        {
            foreach (var k in orgKeys.Values)
            {
                k.Dispose();
            }
        }
        return new DecryptResult(items, errors);
    }

    /// <summary>Returns a copy of the key that encrypts this cipher's fields (item key, org key or user key).</summary>
    public static SymmetricKey ResolveCipherKey(VaultSnapshot snapshot, EncryptedSshCipher cipher, SymmetricKey userKey)
    {
        var orgKeys = new Dictionary<string, SymmetricKey>(StringComparer.OrdinalIgnoreCase);
        try
        {
            SymmetricKey baseKey = userKey;
            if (cipher.OrganizationId != null)
            {
                LoadOrgKeys(snapshot, userKey, orgKeys, []);
                baseKey = orgKeys.TryGetValue(cipher.OrganizationId, out var k) ? k : throw new CryptographicException(L.T("缺少组织密钥。", "Missing organization key."));
            }
            var raw = string.IsNullOrEmpty(cipher.Key) ? baseKey.ToBytes() : EncString.Parse(cipher.Key).DecryptToBytes(baseKey);
            try
            {
                return new SymmetricKey(raw);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(raw);
            }
        }
        finally
        {
            foreach (var k in orgKeys.Values)
            {
                k.Dispose();
            }
        }
    }

    private static void LoadOrgKeys(VaultSnapshot snapshot, SymmetricKey userKey, Dictionary<string, SymmetricKey> orgKeys, List<string> errors)
    {
        var pkcs8 = EncString.Parse(snapshot.EncPrivateKey!).DecryptToBytes(userKey);
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            foreach (var org in snapshot.Organizations)
            {
                try
                {
                    var raw = EncString.Parse(org.Key).DecryptRsa(rsa);
                    orgKeys[org.Id] = new SymmetricKey(raw);
                    CryptographicOperations.ZeroMemory(raw);
                }
                catch (Exception ex)
                {
                    errors.Add(L.T($"组织 {org.Id}: {ex.Message}", $"Organization {org.Id}: {ex.Message}"));
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }
}
