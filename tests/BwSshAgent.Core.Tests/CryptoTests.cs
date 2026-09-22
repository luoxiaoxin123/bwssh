using System.Security.Cryptography;
using BwSshAgent.Core.Crypto;

namespace BwSshAgent.Core.Tests;

public class CryptoTests
{
    // Reference values computed independently with Python hashlib (PBKDF2) and a manual HKDF-Expand.
    private const string Password = "correct horse battery staple";
    private const string Salt = "user@example.com";

    [Fact]
    public void Pbkdf2MasterKeyAndHashMatchReference()
    {
        var mk = KeyDerivation.DeriveMasterKey(Password, Salt, new KdfConfig(KdfType.Pbkdf2, 600000, null, null));
        Assert.Equal("VdxKlOSIH/15LWy0Fz1xRXVs2V3cmyMQuw/JMRI8gkg=", Convert.ToBase64String(mk));
        Assert.Equal("nfEypS52oCiXbQyehOT45BcIhAJYN/5ltdzSYVXHaWg=", KeyDerivation.HashMasterPassword(mk, Password));

        using var stretched = KeyDerivation.StretchKey(mk);
        Assert.Equal("k97T41uTRs9kxL3q1lcjhWxFhn7zw/soaWJp/CREOUs=", Convert.ToBase64String(stretched.EncKey));
        Assert.Equal("Ker/QWdMC7s48J+P3jx3AA4EDswOEJR5A5xptlrLobc=", Convert.ToBase64String(stretched.MacKey!));
    }

    [Fact]
    public void Argon2idIsDeterministicAndSaltDependent()
    {
        var kdf = new KdfConfig(KdfType.Argon2id, 3, 16, 2);
        var a = KeyDerivation.DeriveMasterKey(Password, Salt, kdf);
        var b = KeyDerivation.DeriveMasterKey(Password, Salt, kdf);
        var c = KeyDerivation.DeriveMasterKey(Password, "other@example.com", kdf);
        Assert.Equal(32, a.Length);
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
    }

    [Fact]
    public void KdfRejectsWeakParameters()
    {
        Assert.Throws<CryptographicException>(() => KeyDerivation.DeriveMasterKey("x", "y", new KdfConfig(KdfType.Pbkdf2, 1000, null, null)));
        Assert.Throws<CryptographicException>(() => KeyDerivation.DeriveMasterKey("x", "y", new KdfConfig(KdfType.Argon2id, 3, null, 4)));
    }

    [Fact]
    public void EncStringRoundTripAndTamperDetection()
    {
        using var key = SymmetricKey.Generate();
        var enc = EncString.Encrypt("hello ssh", key);
        Assert.StartsWith("2.", enc);
        Assert.Equal("hello ssh", EncString.Parse(enc).DecryptToString(key));

        var parts = enc[2..].Split('|');
        var data = Convert.FromBase64String(parts[1]);
        data[0] ^= 1;
        var tampered = $"2.{parts[0]}|{Convert.ToBase64String(data)}|{parts[2]}";
        Assert.ThrowsAny<CryptographicException>(() => EncString.Parse(tampered).DecryptToBytes(key));

        using var other = SymmetricKey.Generate();
        Assert.ThrowsAny<CryptographicException>(() => EncString.Parse(enc).DecryptToBytes(other));
    }

    [Fact]
    public void EncStringParsesLegacyAndRsaFormats()
    {
        using var key = new SymmetricKey(RandomNumberGenerator.GetBytes(32));
        var iv = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = key.EncKey;
        var ct = aes.EncryptCbc("legacy"u8, iv);
        var type0 = $"0.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(ct)}";
        Assert.Equal("legacy", EncString.Parse(type0).DecryptToString(key));

        // No type prefix, two parts => type 0.
        Assert.Equal(EncryptionType.AesCbc256_B64, EncString.Parse($"{Convert.ToBase64String(iv)}|{Convert.ToBase64String(ct)}").Type);

        using var rsa = RSA.Create(2048);
        var secret = RandomNumberGenerator.GetBytes(64);
        var sha1 = "4." + Convert.ToBase64String(rsa.Encrypt(secret, RSAEncryptionPadding.OaepSHA1));
        var sha256Mac = "5." + Convert.ToBase64String(rsa.Encrypt(secret, RSAEncryptionPadding.OaepSHA256)) + "|" + Convert.ToBase64String(new byte[32]);
        Assert.Equal(secret, EncString.Parse(sha1).DecryptRsa(rsa));
        Assert.Equal(secret, EncString.Parse(sha256Mac).DecryptRsa(rsa));

        Assert.Throws<UnsupportedEncryptionException>(() => EncString.Parse("7.AAAA"));
        Assert.Throws<FormatException>(() => EncString.Parse("2.onlyone"));
    }

    [Fact]
    public void DecryptUserKeyUsesStretchedKeyOrLegacyMasterKey()
    {
        var mk = RandomNumberGenerator.GetBytes(32);
        var userKey = RandomNumberGenerator.GetBytes(64);
        using (var stretched = KeyDerivation.StretchKey(mk))
        {
            var enc = EncString.Encrypt(userKey, stretched);
            using var decrypted = KeyDerivation.DecryptUserKey(mk, enc);
            Assert.Equal(userKey, decrypted.ToBytes());
        }

        var iv = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = mk;
        var legacy = $"0.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(aes.EncryptCbc(userKey, iv))}";
        using var legacyKey = KeyDerivation.DecryptUserKey(mk, legacy);
        Assert.Equal(userKey, legacyKey.ToBytes());
    }
}
