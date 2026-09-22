using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace BwSshAgent.Core.Ssh;

public sealed class SshSignException(string message) : Exception(message);

public static class SshSignFlags
{
    public const uint RsaSha256 = 2;
    public const uint RsaSha512 = 4;
}

/// <summary>An in-memory SSH private key that can produce agent signatures.</summary>
public abstract class SshPrivateKey : IDisposable
{
    public abstract string KeyType { get; }
    public abstract byte[] PublicBlob { get; }

    /// <summary>Returns the SSH signature blob: string algorithm, string signature.</summary>
    public abstract byte[] Sign(ReadOnlySpan<byte> data, uint flags);

    public string Fingerprint => SshKeyUtil.Fingerprint(PublicBlob);

    public string PublicKeyLine(string comment) =>
        $"{KeyType} {Convert.ToBase64String(PublicBlob)}{(string.IsNullOrWhiteSpace(comment) ? "" : " " + comment.Replace('\n', ' '))}";

    /// <summary>Writes the key-type specific private fields of an openssh-key-v1 private section.</summary>
    internal abstract void WritePrivate(SshWriter writer);

    public abstract void Dispose();
}

public sealed class Ed25519SshKey : SshPrivateKey
{
    private readonly byte[] _seed;
    private readonly byte[] _publicKey;

    public Ed25519SshKey(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> publicKey)
    {
        if (seed.Length != 32 || publicKey.Length != 32)
        {
            throw new SshFormatException("Invalid Ed25519 key.");
        }
        _seed = seed.ToArray();
        _publicKey = publicKey.ToArray();
        var derived = new Ed25519PrivateKeyParameters(_seed, 0).GeneratePublicKey().GetEncoded();
        if (!derived.AsSpan().SequenceEqual(_publicKey))
        {
            throw new SshFormatException("Ed25519 public key does not match private key.");
        }
        PublicBlob = new SshWriter().WriteString("ssh-ed25519").WriteString(_publicKey).ToArray();
    }

    public override string KeyType => "ssh-ed25519";
    public override byte[] PublicBlob { get; }

    public override byte[] Sign(ReadOnlySpan<byte> data, uint flags)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(_seed, 0));
        var buf = data.ToArray();
        signer.BlockUpdate(buf, 0, buf.Length);
        return new SshWriter().WriteString("ssh-ed25519").WriteString(signer.GenerateSignature()).ToArray();
    }

    internal override void WritePrivate(SshWriter writer)
    {
        var secret = new byte[64];
        _seed.CopyTo(secret, 0);
        _publicKey.CopyTo(secret, 32);
        writer.WriteString(KeyType).WriteString(_publicKey).WriteString(secret);
        CryptographicOperations.ZeroMemory(secret);
    }

    public override void Dispose() => CryptographicOperations.ZeroMemory(_seed);
}

public sealed class RsaSshKey : SshPrivateKey
{
    private readonly RSA _rsa;

    public RsaSshKey(RSA rsa)
    {
        _rsa = rsa;
        var p = rsa.ExportParameters(false);
        PublicBlob = new SshWriter().WriteString("ssh-rsa").WriteMpint(p.Exponent).WriteMpint(p.Modulus).ToArray();
    }

    public override string KeyType => "ssh-rsa";
    public override byte[] PublicBlob { get; }

    public override byte[] Sign(ReadOnlySpan<byte> data, uint flags)
    {
        // Matches the Bitwarden agent: SHA-1 ("ssh-rsa" signatures) is refused.
        (HashAlgorithmName hash, string alg) = (flags & SshSignFlags.RsaSha256) != 0
            ? (HashAlgorithmName.SHA256, "rsa-sha2-256")
            : (flags & SshSignFlags.RsaSha512) != 0
                ? (HashAlgorithmName.SHA512, "rsa-sha2-512")
                : throw new SshSignException("RSA SHA-1 signatures are not permitted.");
        var sig = _rsa.SignData(data.ToArray(), hash, RSASignaturePadding.Pkcs1);
        return new SshWriter().WriteString(alg).WriteString(sig).ToArray();
    }

    internal override void WritePrivate(SshWriter writer)
    {
        var p = _rsa.ExportParameters(true);
        try
        {
            writer.WriteString(KeyType).WriteMpint(p.Modulus).WriteMpint(p.Exponent).WriteMpint(p.D)
                .WriteMpint(p.InverseQ).WriteMpint(p.P).WriteMpint(p.Q);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(p.D);
            CryptographicOperations.ZeroMemory(p.P);
            CryptographicOperations.ZeroMemory(p.Q);
            CryptographicOperations.ZeroMemory(p.DP);
            CryptographicOperations.ZeroMemory(p.DQ);
            CryptographicOperations.ZeroMemory(p.InverseQ);
        }
    }

    public override void Dispose() => _rsa.Dispose();
}

public sealed class EcdsaSshKey : SshPrivateKey
{
    private readonly ECDsa _ec;
    private readonly string _curve;

    public EcdsaSshKey(ECDsa ec, string curveName)
    {
        _ec = ec;
        _curve = curveName;
        var p = ec.ExportParameters(false);
        var q = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
        q[0] = 4;
        p.Q.X.CopyTo(q, 1);
        p.Q.Y.CopyTo(q, 1 + p.Q.X.Length);
        PublicBlob = new SshWriter().WriteString(KeyType).WriteString(curveName).WriteString(q).ToArray();
    }

    public override string KeyType => "ecdsa-sha2-" + _curve;
    public override byte[] PublicBlob { get; }

    public override byte[] Sign(ReadOnlySpan<byte> data, uint flags)
    {
        var sig = _ec.SignData(data.ToArray(), SshKeyUtil.EcdsaHash(_curve), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var half = sig.Length / 2;
        var inner = new SshWriter().WriteMpint(sig.AsSpan(0, half)).WriteMpint(sig.AsSpan(half)).ToArray();
        return new SshWriter().WriteString(KeyType).WriteString(inner).ToArray();
    }

    internal override void WritePrivate(SshWriter writer)
    {
        var p = _ec.ExportParameters(true);
        var q = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
        q[0] = 4;
        p.Q.X.CopyTo(q, 1);
        p.Q.Y.CopyTo(q, 1 + p.Q.X.Length);
        writer.WriteString(KeyType).WriteString(_curve).WriteString(q).WriteMpint(p.D);
        CryptographicOperations.ZeroMemory(p.D);
    }

    public override void Dispose() => _ec.Dispose();
}

public static class SshKeyUtil
{
    public static string Fingerprint(ReadOnlySpan<byte> publicBlob) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(publicBlob)).TrimEnd('=');

    public static HashAlgorithmName EcdsaHash(string curve) => curve switch
    {
        "nistp256" => HashAlgorithmName.SHA256,
        "nistp384" => HashAlgorithmName.SHA384,
        "nistp521" => HashAlgorithmName.SHA512,
        _ => throw new SshFormatException($"Unsupported curve {curve}."),
    };

    public static ECCurve Curve(string curve) => curve switch
    {
        "nistp256" => ECCurve.NamedCurves.nistP256,
        "nistp384" => ECCurve.NamedCurves.nistP384,
        "nistp521" => ECCurve.NamedCurves.nistP521,
        _ => throw new SshFormatException($"Unsupported curve {curve}."),
    };

    public static int CurveFieldBytes(string curve) => curve switch
    {
        "nistp256" => 32,
        "nistp384" => 48,
        "nistp521" => 66,
        _ => throw new SshFormatException($"Unsupported curve {curve}."),
    };

    public static byte[] PadLeft(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length > length)
        {
            var extra = value.Length - length;
            for (var i = 0; i < extra; i++)
            {
                if (value[i] != 0)
                {
                    throw new SshFormatException("Integer too large.");
                }
            }
            return value[extra..].ToArray();
        }
        var result = new byte[length];
        value.CopyTo(result.AsSpan(length - value.Length));
        return result;
    }

    public static string KeyTypeOf(ReadOnlySpan<byte> publicBlob)
    {
        var r = new SshReader(publicBlob);
        return r.ReadUtf8();
    }

    /// <summary>Verifies an SSH signature blob made by the given public key (used for session-bind).</summary>
    public static bool Verify(ReadOnlySpan<byte> publicBlob, ReadOnlySpan<byte> signatureBlob, ReadOnlySpan<byte> data)
    {
        var kr = new SshReader(publicBlob);
        var keyType = kr.ReadUtf8();
        var sr = new SshReader(signatureBlob);
        var sigAlg = sr.ReadUtf8();
        var sig = sr.ReadString();

        switch (keyType)
        {
            case "ssh-ed25519":
            {
                if (sigAlg != "ssh-ed25519")
                {
                    return false;
                }
                var pub = kr.ReadString();
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(pub.ToArray(), 0));
                var buf = data.ToArray();
                verifier.BlockUpdate(buf, 0, buf.Length);
                return verifier.VerifySignature(sig.ToArray());
            }
            case "ssh-rsa":
            {
                var hash = sigAlg switch
                {
                    "rsa-sha2-256" => HashAlgorithmName.SHA256,
                    "rsa-sha2-512" => HashAlgorithmName.SHA512,
                    _ => (HashAlgorithmName?)null,
                };
                if (hash == null)
                {
                    return false;
                }
                var e = kr.ReadMpint();
                var n = kr.ReadMpint();
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Exponent = e, Modulus = n });
                return rsa.VerifyData(data.ToArray(), sig.ToArray(), hash.Value, RSASignaturePadding.Pkcs1);
            }
            case "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521":
            {
                if (sigAlg != keyType)
                {
                    return false;
                }
                var curve = kr.ReadUtf8();
                var q = kr.ReadString();
                var size = CurveFieldBytes(curve);
                if (q.Length != 1 + 2 * size || q[0] != 4)
                {
                    return false;
                }
                using var ec = ECDsa.Create(new ECParameters
                {
                    Curve = Curve(curve),
                    Q = new ECPoint { X = q.Slice(1, size).ToArray(), Y = q.Slice(1 + size, size).ToArray() },
                });
                var ir = new SshReader(sig);
                var r = PadLeft(ir.ReadMpint(), size);
                var s = PadLeft(ir.ReadMpint(), size);
                byte[] p1363 = [.. r, .. s];
                return ec.VerifyData(data.ToArray(), p1363, EcdsaHash(curve), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            default:
                return false;
        }
    }
}

