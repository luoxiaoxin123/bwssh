using System.Security.Cryptography;
using System.Text;

namespace BwSshAgent.Core.Crypto;

public enum EncryptionType
{
    AesCbc256_B64 = 0,
    AesCbc256_HmacSha256_B64 = 2,
    Rsa2048_OaepSha256_B64 = 3,
    Rsa2048_OaepSha1_B64 = 4,
    Rsa2048_OaepSha256_HmacSha256_B64 = 5,
    Rsa2048_OaepSha1_HmacSha256_B64 = 6,
    CoseEncrypt0 = 7,
}

public sealed class UnsupportedEncryptionException(string message) : Exception(message);

/// <summary>
/// Bitwarden "EncString": "&lt;type&gt;.&lt;iv&gt;|&lt;data&gt;|&lt;mac&gt;" (symmetric) or "&lt;type&gt;.&lt;data&gt;" (RSA).
/// </summary>
public sealed class EncString
{
    public EncryptionType Type { get; }
    public byte[]? Iv { get; }
    public byte[] Data { get; }
    public byte[]? Mac { get; }

    private EncString(EncryptionType type, byte[]? iv, byte[] data, byte[]? mac)
    {
        Type = type;
        Iv = iv;
        Data = data;
        Mac = mac;
    }

    public static EncString Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("Empty EncString.");
        }

        EncryptionType type;
        string[] parts;
        var dot = value.IndexOf('.');
        if (dot > 0 && dot < 3 && int.TryParse(value.AsSpan(0, dot), out var t))
        {
            type = (EncryptionType)t;
            parts = value[(dot + 1)..].Split('|');
        }
        else
        {
            parts = value.Split('|');
            type = parts.Length == 3 ? EncryptionType.AesCbc256_HmacSha256_B64 : EncryptionType.AesCbc256_B64;
        }

        switch (type)
        {
            case EncryptionType.AesCbc256_B64 when parts.Length == 2:
                return new EncString(type, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]), null);
            case EncryptionType.AesCbc256_HmacSha256_B64 when parts.Length == 3:
                return new EncString(type, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]), Convert.FromBase64String(parts[2]));
            case EncryptionType.Rsa2048_OaepSha256_B64 or EncryptionType.Rsa2048_OaepSha1_B64 when parts.Length == 1:
                return new EncString(type, null, Convert.FromBase64String(parts[0]), null);
            case EncryptionType.Rsa2048_OaepSha256_HmacSha256_B64 or EncryptionType.Rsa2048_OaepSha1_HmacSha256_B64 when parts.Length == 2:
                return new EncString(type, null, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));
            case EncryptionType.CoseEncrypt0:
                throw new UnsupportedEncryptionException(
                    L.T("此账户使用了新版加密格式 (COSE / type 7)，本客户端暂不支持。", "This account uses the new COSE (type 7) encryption format, which is not supported yet."));
            default:
                throw new FormatException($"Invalid EncString (type {(int)type}, {parts.Length} parts).");
        }
    }

    public byte[] DecryptToBytes(SymmetricKey key)
    {
        if (Type == EncryptionType.AesCbc256_HmacSha256_B64)
        {
            if (key.MacKey == null)
            {
                throw new CryptographicException("MAC key required.");
            }
            var macData = new byte[Iv!.Length + Data.Length];
            Iv.CopyTo(macData, 0);
            Data.CopyTo(macData, Iv.Length);
            var computed = HMACSHA256.HashData(key.MacKey, macData);
            if (!CryptographicOperations.FixedTimeEquals(computed, Mac))
            {
                throw new CryptographicException("MAC verification failed.");
            }
        }
        else if (Type != EncryptionType.AesCbc256_B64)
        {
            throw new CryptographicException($"Cannot decrypt type {(int)Type} with a symmetric key.");
        }

        using var aes = Aes.Create();
        aes.Key = key.EncKey;
        return aes.DecryptCbc(Data, Iv!, PaddingMode.PKCS7);
    }

    public string DecryptToString(SymmetricKey key)
    {
        var bytes = DecryptToBytes(key);
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public byte[] DecryptRsa(RSA privateKey)
    {
        var padding = Type switch
        {
            EncryptionType.Rsa2048_OaepSha256_B64 or EncryptionType.Rsa2048_OaepSha256_HmacSha256_B64 => RSAEncryptionPadding.OaepSHA256,
            EncryptionType.Rsa2048_OaepSha1_B64 or EncryptionType.Rsa2048_OaepSha1_HmacSha256_B64 => RSAEncryptionPadding.OaepSHA1,
            _ => throw new CryptographicException($"Type {(int)Type} is not an RSA EncString."),
        };
        return privateKey.Decrypt(Data, padding);
    }

    public static string Encrypt(ReadOnlySpan<byte> plaintext, SymmetricKey key)
    {
        if (key.MacKey == null)
        {
            throw new CryptographicException("MAC key required.");
        }
        var iv = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = key.EncKey;
        var data = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        var macData = new byte[iv.Length + data.Length];
        iv.CopyTo(macData, 0);
        data.CopyTo(macData, iv.Length);
        var mac = HMACSHA256.HashData(key.MacKey, macData);
        return $"2.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(data)}|{Convert.ToBase64String(mac)}";
    }

    public static string Encrypt(string plaintext, SymmetricKey key) => Encrypt(Encoding.UTF8.GetBytes(plaintext), key);
}
