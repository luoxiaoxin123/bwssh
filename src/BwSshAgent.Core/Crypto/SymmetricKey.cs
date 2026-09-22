using System.Security.Cryptography;

namespace BwSshAgent.Core.Crypto;

/// <summary>
/// A Bitwarden symmetric key: 32-byte AES key plus an optional 32-byte HMAC key.
/// 64-byte keys are split into enc (first half) and mac (second half).
/// </summary>
public sealed class SymmetricKey : IDisposable
{
    public byte[] EncKey { get; }
    public byte[]? MacKey { get; }

    public SymmetricKey(ReadOnlySpan<byte> key)
    {
        switch (key.Length)
        {
            case 32:
                EncKey = key.ToArray();
                break;
            case 64:
                EncKey = key[..32].ToArray();
                MacKey = key[32..].ToArray();
                break;
            default:
                throw new CryptographicException($"Unsupported symmetric key length {key.Length}.");
        }
    }

    public SymmetricKey(byte[] encKey, byte[] macKey)
    {
        if (encKey.Length != 32 || macKey.Length != 32)
        {
            throw new CryptographicException("Invalid key parts.");
        }
        EncKey = encKey;
        MacKey = macKey;
    }

    public byte[] ToBytes()
    {
        if (MacKey == null)
        {
            return (byte[])EncKey.Clone();
        }
        var result = new byte[64];
        EncKey.CopyTo(result, 0);
        MacKey.CopyTo(result, 32);
        return result;
    }

    public static SymmetricKey Generate() => new(RandomNumberGenerator.GetBytes(64));

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(EncKey);
        if (MacKey != null)
        {
            CryptographicOperations.ZeroMemory(MacKey);
        }
    }
}
