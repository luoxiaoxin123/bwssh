using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace BwSshAgent.Core.Crypto;

public enum KdfType
{
    Pbkdf2 = 0,
    Argon2id = 1,
}

public sealed record KdfConfig(KdfType Type, int Iterations, int? Memory, int? Parallelism)
{
    public void Validate()
    {
        if (Type == KdfType.Pbkdf2 && Iterations < 5000)
        {
            throw new CryptographicException("PBKDF2 iterations too low.");
        }
        if (Type == KdfType.Argon2id && (Iterations < 2 || Memory is null or < 16 || Parallelism is null or < 1))
        {
            throw new CryptographicException("Argon2id parameters too weak.");
        }
    }
}

public static class KeyDerivation
{
    public static string NormalizeEmailSalt(string email) => email.Trim().ToLowerInvariant();

    /// <summary>Derives the 32-byte master key from the master password.</summary>
    public static byte[] DeriveMasterKey(string password, string salt, KdfConfig kdf)
    {
        kdf.Validate();
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            var saltBytes = Encoding.UTF8.GetBytes(salt);
            return kdf.Type switch
            {
                KdfType.Pbkdf2 => Rfc2898DeriveBytes.Pbkdf2(passwordBytes, saltBytes, kdf.Iterations, HashAlgorithmName.SHA256, 32),
                KdfType.Argon2id => Argon2id(passwordBytes, SHA256.HashData(saltBytes), kdf.Iterations, kdf.Memory!.Value * 1024, kdf.Parallelism!.Value),
                _ => throw new CryptographicException($"Unknown KDF type {kdf.Type}."),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>Server authentication hash: PBKDF2-SHA256(masterKey, password, 1).</summary>
    public static string HashMasterPassword(byte[] masterKey, string password)
    {
        var hash = Rfc2898DeriveBytes.Pbkdf2(masterKey, Encoding.UTF8.GetBytes(password), 1, HashAlgorithmName.SHA256, 32);
        return Convert.ToBase64String(hash);
    }

    /// <summary>HKDF-Expand the master key into a 64-byte enc+mac key.</summary>
    public static SymmetricKey StretchKey(byte[] key32)
    {
        var enc = HKDF.Expand(HashAlgorithmName.SHA256, key32, 32, "enc"u8.ToArray());
        var mac = HKDF.Expand(HashAlgorithmName.SHA256, key32, 32, "mac"u8.ToArray());
        return new SymmetricKey(enc, mac);
    }

    public static byte[] Argon2id(byte[] password, byte[] salt, int iterations, int memoryKiB, int parallelism, int outputLength = 32)
    {
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithIterations(iterations)
            .WithMemoryAsKB(memoryKiB)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();
        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);
        var output = new byte[outputLength];
        generator.GenerateBytes(password, output);
        return output;
    }

    /// <summary>Decrypts the user key with the master key (stretched for type 2, raw for legacy type 0).</summary>
    public static SymmetricKey DecryptUserKey(byte[] masterKey, string encUserKey)
    {
        var enc = EncString.Parse(encUserKey);
        byte[] raw;
        if (enc.Type == EncryptionType.AesCbc256_B64)
        {
            using var legacy = new SymmetricKey(masterKey);
            raw = enc.DecryptToBytes(legacy);
        }
        else
        {
            using var stretched = StretchKey(masterKey);
            raw = enc.DecryptToBytes(stretched);
        }
        try
        {
            return new SymmetricKey(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }
}
