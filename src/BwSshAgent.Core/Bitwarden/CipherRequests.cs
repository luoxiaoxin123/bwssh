using System.Text.Json.Nodes;
using BwSshAgent.Core.Crypto;

namespace BwSshAgent.Core.Bitwarden;

/// <summary>
/// Builds /ciphers request bodies (same shape as the clients' CipherRequest). Every value is encrypted
/// before it leaves this class; nothing in plain text is sent to the server.
/// </summary>
public static class CipherRequests
{
    public const int SshKeyType = 5;

    /// <summary>A new personal SSH key item, protected with a fresh per-item key like current Bitwarden clients.</summary>
    public static JsonObject NewSshKey(string userId, SymmetricKey userKey, string name, string privateKeyPem, string publicKeyLine, string fingerprint)
    {
        using var itemKey = SymmetricKey.Generate();
        return new JsonObject
        {
            ["type"] = SshKeyType,
            ["organizationId"] = null,
            ["folderId"] = null,
            ["favorite"] = false,
            ["reprompt"] = 0,
            ["encryptedFor"] = userId,
            ["key"] = EncString.Encrypt(itemKey.ToBytes(), userKey),
            ["name"] = EncString.Encrypt(name, itemKey),
            ["notes"] = null,
            ["sshKey"] = new JsonObject
            {
                ["privateKey"] = EncString.Encrypt(privateKeyPem, itemKey),
                ["publicKey"] = EncString.Encrypt(publicKeyLine, itemKey),
                ["keyFingerprint"] = EncString.Encrypt(fingerprint, itemKey),
            },
        };
    }

    /// <summary>
    /// PUT body for renaming: everything else (notes, custom fields, password history, attachments, folder)
    /// is copied unchanged from the synced cipher so the update does not drop data.
    /// </summary>
    public static JsonObject Rename(EncryptedSshCipher cipher, string userId, SymmetricKey cipherKey, string newName)
    {
        var raw = JsonNode.Parse(cipher.Raw ?? throw new InvalidOperationException(L.T("缺少条目数据，请先同步。", "Item data is missing, please sync first.")))!;
        var ssh = J.Get(raw, "SshKey");
        var request = new JsonObject
        {
            ["type"] = SshKeyType,
            ["organizationId"] = Copy(raw, "OrganizationId"),
            ["folderId"] = Copy(raw, "FolderId"),
            ["favorite"] = Copy(raw, "Favorite") ?? false,
            ["reprompt"] = Copy(raw, "Reprompt") ?? 0,
            ["encryptedFor"] = userId,
            ["key"] = Copy(raw, "Key"),
            ["name"] = EncString.Encrypt(newName, cipherKey),
            ["notes"] = Copy(raw, "Notes"),
            ["fields"] = Copy(raw, "Fields"),
            ["passwordHistory"] = Copy(raw, "PasswordHistory"),
            ["lastKnownRevisionDate"] = Copy(raw, "RevisionDate"),
            ["archivedDate"] = Copy(raw, "ArchivedDate"),
            ["sshKey"] = new JsonObject
            {
                ["privateKey"] = Copy(ssh, "PrivateKey"),
                ["publicKey"] = Copy(ssh, "PublicKey"),
                ["keyFingerprint"] = Copy(ssh, "KeyFingerprint"),
            },
        };

        if (J.Get(raw, "Attachments") is JsonArray attachments && attachments.Count > 0)
        {
            var map = new JsonObject();
            foreach (var a in attachments)
            {
                var id = J.Str(a, "Id");
                if (id != null)
                {
                    map[id] = new JsonObject { ["fileName"] = Copy(a, "FileName"), ["key"] = Copy(a, "Key") };
                }
            }
            request["attachments2"] = map;
        }
        return request;
    }

    private static JsonNode? Copy(JsonNode? node, string name) => J.Get(node, name)?.DeepClone();
}
