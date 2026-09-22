using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace BwSshAgent.Core.Ssh;

public sealed class SshPassphraseRequiredException() : Exception(L.T("此私钥受密码保护，请输入私钥密码。", "This private key is protected, enter its passphrase."));

public sealed class SshWrongPassphraseException() : Exception(L.T("私钥密码不正确。", "Incorrect private key passphrase."));

/// <summary>
/// Parses private keys. Bitwarden stores unencrypted OpenSSH keys; imports may also be passphrase-protected
/// OpenSSH keys, PKCS#8 (plain or encrypted) or traditional OpenSSL PEM.
/// </summary>
public static class SshKeyParser
{
    private const string OpenSshHeader = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private const string OpenSshFooter = "-----END OPENSSH PRIVATE KEY-----";

    public static SshPrivateKey Parse(ReadOnlySpan<byte> utf8Pem, string? passphrase = null)
    {
        var chars = new char[Encoding.UTF8.GetCharCount(utf8Pem)];
        Encoding.UTF8.GetChars(utf8Pem, chars);
        try
        {
            return Parse(chars, passphrase);
        }
        finally
        {
            Array.Clear(chars);
        }
    }

    public static SshPrivateKey Parse(ReadOnlySpan<char> pem, string? passphrase = null)
    {
        if (pem.IndexOf("PuTTY-User-Key-File".AsSpan()) >= 0)
        {
            throw new SshFormatException(L.T("不支持 PuTTY (.ppk) 格式，请先用 PuTTYgen 的 Conversions → Export OpenSSH key 导出。", "PuTTY (.ppk) keys are not supported. Use PuTTYgen: Conversions → Export OpenSSH key."));
        }
        var start = pem.IndexOf(OpenSshHeader.AsSpan());
        if (start >= 0)
        {
            var bodyStart = start + OpenSshHeader.Length;
            var end = pem[bodyStart..].IndexOf(OpenSshFooter.AsSpan());
            if (end < 0)
            {
                throw new SshFormatException("Missing OpenSSH footer.");
            }
            var body = StripWhitespace(pem.Slice(bodyStart, end));
            var buffer = new byte[body.Length];
            try
            {
                if (!Convert.TryFromBase64Chars(body, buffer, out var written))
                {
                    throw new SshFormatException("Invalid base64 in OpenSSH key.");
                }
                return ParseOpenSsh(buffer.AsSpan(0, written), passphrase);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                Array.Clear(body);
            }
        }
        return ParsePem(pem.ToString(), passphrase);
    }

    private static char[] StripWhitespace(ReadOnlySpan<char> s)
    {
        var result = new List<char>(s.Length);
        foreach (var c in s)
        {
            if (!char.IsWhiteSpace(c))
            {
                result.Add(c);
            }
        }
        return [.. result];
    }

    private static SshPrivateKey ParseOpenSsh(ReadOnlySpan<byte> blob, string? passphrase)
    {
        var magic = "openssh-key-v1\0"u8;
        if (!blob.StartsWith(magic))
        {
            throw new SshFormatException("Not an openssh-key-v1 blob.");
        }
        var r = new SshReader(blob[magic.Length..]);
        var cipher = r.ReadUtf8();
        var kdf = r.ReadUtf8();
        var kdfOptions = r.ReadString();
        if (r.ReadUInt32() != 1)
        {
            throw new SshFormatException("Expected exactly one key.");
        }
        r.ReadString(); // public key
        var encrypted = r.ReadString();

        if (cipher == "none")
        {
            return ParsePrivateSection(encrypted, wrongPassphraseOnMismatch: false);
        }

        if (string.IsNullOrEmpty(passphrase))
        {
            throw new SshPassphraseRequiredException();
        }
        if (kdf != "bcrypt")
        {
            throw new SshFormatException($"Unsupported key derivation {kdf}.");
        }
        var (keyLength, ivLength, tagLength) = cipher switch
        {
            "aes128-ctr" or "aes128-cbc" => (16, 16, 0),
            "aes192-ctr" or "aes192-cbc" => (24, 16, 0),
            "aes256-ctr" or "aes256-cbc" => (32, 16, 0),
            "aes128-gcm@openssh.com" => (16, 12, 16),
            "aes256-gcm@openssh.com" => (32, 12, 16),
            _ => throw new SshFormatException($"Unsupported private key cipher {cipher}."),
        };
        var opts = new SshReader(kdfOptions);
        var salt = opts.ReadString().ToArray();
        var rounds = (int)opts.ReadUInt32();
        var tag = tagLength > 0 ? r.ReadBytes(tagLength).ToArray() : [];

        var passBytes = Encoding.UTF8.GetBytes(passphrase);
        var derived = BcryptPbkdf.DeriveKey(passBytes, salt, rounds, keyLength + ivLength);
        CryptographicOperations.ZeroMemory(passBytes);
        var key = derived.AsSpan(0, keyLength).ToArray();
        var iv = derived.AsSpan(keyLength, ivLength).ToArray();
        var plain = new byte[encrypted.Length];
        try
        {
            if (cipher.EndsWith("-ctr", StringComparison.Ordinal))
            {
                AesCtr(key, iv, encrypted, plain);
            }
            else if (cipher.EndsWith("-cbc", StringComparison.Ordinal))
            {
                using var aes = Aes.Create();
                aes.Key = key;
                aes.DecryptCbc(encrypted, iv, plain, PaddingMode.None);
            }
            else
            {
                using var gcm = new AesGcm(key, tagLength);
                try
                {
                    gcm.Decrypt(iv, encrypted, tag, plain);
                }
                catch (AuthenticationTagMismatchException)
                {
                    throw new SshWrongPassphraseException();
                }
            }
            return ParsePrivateSection(plain, wrongPassphraseOnMismatch: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void AesCtr(byte[] key, byte[] iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        var counter = (byte[])iv.Clone();
        var keystream = new byte[16];
        for (var offset = 0; offset < input.Length; offset += 16)
        {
            aes.EncryptEcb(counter, keystream, PaddingMode.None);
            var n = Math.Min(16, input.Length - offset);
            for (var i = 0; i < n; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
            }
            for (var i = 15; i >= 0 && ++counter[i] == 0; i--)
            {
            }
        }
        CryptographicOperations.ZeroMemory(keystream);
    }

    private static SshPrivateKey ParsePrivateSection(ReadOnlySpan<byte> section, bool wrongPassphraseOnMismatch)
    {
        var priv = new SshReader(section);
        if (priv.ReadUInt32() != priv.ReadUInt32())
        {
            if (wrongPassphraseOnMismatch)
            {
                throw new SshWrongPassphraseException();
            }
            throw new SshFormatException("Checkint mismatch.");
        }
        var type = priv.ReadUtf8();
        switch (type)
        {
            case "ssh-ed25519":
            {
                var pub = priv.ReadString();
                var sk = priv.ReadString();
                if (sk.Length != 64)
                {
                    throw new SshFormatException("Invalid Ed25519 private key length.");
                }
                return new Ed25519SshKey(sk[..32], pub);
            }
            case "ssh-rsa":
            {
                var n = priv.ReadMpint();
                var e = priv.ReadMpint();
                var d = priv.ReadMpint();
                var iqmp = priv.ReadMpint();
                var p = priv.ReadMpint();
                var q = priv.ReadMpint();
                var rsa = RSA.Create();
                try
                {
                    rsa.ImportParameters(BuildRsaParameters(n, e, d, p, q, iqmp));
                }
                catch
                {
                    rsa.Dispose();
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(d);
                    CryptographicOperations.ZeroMemory(p);
                    CryptographicOperations.ZeroMemory(q);
                    CryptographicOperations.ZeroMemory(iqmp);
                }
                return new RsaSshKey(rsa);
            }
            case "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521":
            {
                var curve = priv.ReadUtf8();
                var qBytes = priv.ReadString();
                var d = priv.ReadMpint();
                var size = SshKeyUtil.CurveFieldBytes(curve);
                if (qBytes.Length != 1 + 2 * size || qBytes[0] != 4)
                {
                    throw new SshFormatException("Invalid ECDSA public point.");
                }
                try
                {
                    return EcdsaFromParts(curve, qBytes.Slice(1, size), qBytes.Slice(1 + size, size), d);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(d);
                }
            }
            default:
                throw new SshFormatException(L.T($"不支持的密钥类型 {type}。", $"Unsupported key type {type}."));
        }
    }

    private static EcdsaSshKey EcdsaFromParts(string curve, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> d)
    {
        var size = SshKeyUtil.CurveFieldBytes(curve);
        var ec = ECDsa.Create();
        try
        {
            ec.ImportParameters(new ECParameters
            {
                Curve = SshKeyUtil.Curve(curve),
                Q = new ECPoint { X = SshKeyUtil.PadLeft(x, size), Y = SshKeyUtil.PadLeft(y, size) },
                D = SshKeyUtil.PadLeft(d, size),
            });
        }
        catch
        {
            ec.Dispose();
            throw;
        }
        return new EcdsaSshKey(ec, curve);
    }

    internal static RSAParameters BuildRsaParameters(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q, byte[] iqmp)
    {
        var bd = new BigInteger(d, isUnsigned: true, isBigEndian: true);
        var bp = new BigInteger(p, isUnsigned: true, isBigEndian: true);
        var bq = new BigInteger(q, isUnsigned: true, isBigEndian: true);
        var dp = (bd % (bp - 1)).ToByteArray(isUnsigned: true, isBigEndian: true);
        var dq = (bd % (bq - 1)).ToByteArray(isUnsigned: true, isBigEndian: true);
        var modLen = n.Length;
        var half = (modLen + 1) / 2;
        return new RSAParameters
        {
            Modulus = n,
            Exponent = e,
            D = SshKeyUtil.PadLeft(d, modLen),
            P = SshKeyUtil.PadLeft(p, half),
            Q = SshKeyUtil.PadLeft(q, half),
            DP = SshKeyUtil.PadLeft(dp, half),
            DQ = SshKeyUtil.PadLeft(dq, half),
            InverseQ = SshKeyUtil.PadLeft(iqmp, half),
        };
    }

    private sealed class PasswordFinder(string? passphrase) : IPasswordFinder
    {
        public char[] GetPassword() =>
            string.IsNullOrEmpty(passphrase) ? throw new SshPassphraseRequiredException() : passphrase.ToCharArray();
    }

    /// <summary>PKCS#8 (plain / encrypted) and traditional OpenSSL PEM via BouncyCastle.</summary>
    private static SshPrivateKey ParsePem(string text, string? passphrase)
    {
        if (!text.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            throw new SshFormatException(L.T("无法识别的私钥格式。", "Unrecognized private key format."));
        }
        object? obj;
        try
        {
            using var reader = new StringReader(text);
            obj = new PemReader(reader, new PasswordFinder(passphrase)).ReadObject();
        }
        catch (SshPassphraseRequiredException)
        {
            throw;
        }
        catch (Exception ex) when (ex is PemException or InvalidCipherTextException or IOException or ArgumentException)
        {
            if (text.Contains("ENCRYPTED", StringComparison.Ordinal))
            {
                if (string.IsNullOrEmpty(passphrase))
                {
                    throw new SshPassphraseRequiredException();
                }
                throw new SshWrongPassphraseException();
            }
            throw new SshFormatException(L.T("无法解析私钥：", "Cannot parse the private key: ") + ex.Message);
        }

        var key = obj switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter { IsPrivate: true } k => k,
            _ => throw new SshFormatException(L.T("文件中没有找到私钥（可能是公钥或证书）。", "No private key found (is this a public key or certificate?).")),
        };
        return FromBouncyCastle(key);
    }

    private static SshPrivateKey FromBouncyCastle(AsymmetricKeyParameter key)
    {
        switch (key)
        {
            case Ed25519PrivateKeyParameters ed:
                return new Ed25519SshKey(ed.GetEncoded(), ed.GeneratePublicKey().GetEncoded());
            case RsaPrivateCrtKeyParameters crt:
            {
                var rsa = RSA.Create();
                try
                {
                    rsa.ImportParameters(DotNetUtilities.ToRSAParameters(crt));
                }
                catch
                {
                    rsa.Dispose();
                    throw;
                }
                return new RsaSshKey(rsa);
            }
            case ECPrivateKeyParameters ec:
            {
                var curve = ec.Parameters.Curve.FieldSize switch
                {
                    256 => "nistp256",
                    384 => "nistp384",
                    521 => "nistp521",
                    _ => throw new SshFormatException(L.T("不支持的 ECDSA 曲线。", "Unsupported ECDSA curve.")),
                };
                var q = ec.Parameters.G.Multiply(ec.D).Normalize();
                var d = ec.D.ToByteArrayUnsigned();
                try
                {
                    return EcdsaFromParts(curve, q.AffineXCoord.GetEncoded(), q.AffineYCoord.GetEncoded(), d);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(d);
                }
            }
            default:
                throw new SshFormatException(L.T("不支持的密钥类型（只支持 Ed25519、RSA、ECDSA）。", "Unsupported key type (only Ed25519, RSA and ECDSA)."));
        }
    }
}

/// <summary>Key generation and OpenSSH serialization (the format Bitwarden stores).</summary>
public static class SshKeyFactory
{
    public static SshPrivateKey GenerateEd25519()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        try
        {
            var pub = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
            return new Ed25519SshKey(seed, pub);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public static SshPrivateKey GenerateRsa(int bits) => new RsaSshKey(RSA.Create(bits));

    /// <summary>Unencrypted openssh-key-v1 PEM, as produced by ssh-keygen -N "".</summary>
    public static string ToOpenSshPem(SshPrivateKey key, string comment = "")
    {
        var check = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        var section = new SshWriter().WriteUInt32(check).WriteUInt32(check);
        key.WritePrivate(section);
        section.WriteString(comment);
        var body = section.ToArray();
        var padding = (8 - body.Length % 8) % 8;
        var padded = new byte[body.Length + padding];
        body.CopyTo(padded, 0);
        for (var i = 0; i < padding; i++)
        {
            padded[body.Length + i] = (byte)(i + 1);
        }
        CryptographicOperations.ZeroMemory(body);

        var blob = new SshWriter()
            .WriteRaw("openssh-key-v1\0"u8)
            .WriteString("none").WriteString("none").WriteString([])
            .WriteUInt32(1)
            .WriteString(key.PublicBlob)
            .WriteString(padded)
            .ToArray();
        CryptographicOperations.ZeroMemory(padded);

        var b64 = Convert.ToBase64String(blob);
        CryptographicOperations.ZeroMemory(blob);
        var sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < b64.Length; i += 70)
        {
            sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
        }
        sb.Append("-----END OPENSSH PRIVATE KEY-----\n");
        return sb.ToString();
    }
}
