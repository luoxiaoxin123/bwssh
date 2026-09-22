using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace BwSshAgent.Core.Ssh;

/// <summary>
/// bcrypt_pbkdf as used by OpenSSH to protect private keys (port of OpenBSD bcrypt_pbkdf.c).
/// </summary>
public static class BcryptPbkdf
{
    private const int HashWords = 8; // 32-byte bcrypt_hash output

    public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int rounds, int keyLength)
    {
        if (rounds < 1 || keyLength is < 1 or > 1024 || salt.Length == 0)
        {
            throw new ArgumentException("Invalid bcrypt_pbkdf parameters.");
        }
        var key = new byte[keyLength];
        var stride = (keyLength + 32 - 1) / 32;
        var amount = (keyLength + stride - 1) / stride;
        var sha2pass = SHA512.HashData(password);
        var countSalt = new byte[salt.Length + 4];
        salt.CopyTo(countSalt);
        var remaining = keyLength;

        for (uint count = 1; remaining > 0; count++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(countSalt.AsSpan(salt.Length), count);
            var sha2salt = SHA512.HashData(countSalt);
            var tmp = BcryptHash(sha2pass, sha2salt);
            var output = (byte[])tmp.Clone();
            for (var r = 1; r < rounds; r++)
            {
                sha2salt = SHA512.HashData(tmp);
                tmp = BcryptHash(sha2pass, sha2salt);
                for (var j = 0; j < output.Length; j++)
                {
                    output[j] ^= tmp[j];
                }
            }

            amount = Math.Min(amount, remaining);
            int i;
            for (i = 0; i < amount; i++)
            {
                var dest = i * stride + (int)(count - 1);
                if (dest >= keyLength)
                {
                    break;
                }
                key[dest] = output[i];
            }
            remaining -= i;
        }
        CryptographicOperations.ZeroMemory(sha2pass);
        return key;
    }

    private static byte[] BcryptHash(byte[] sha2pass, byte[] sha2salt)
    {
        var bf = new Blowfish();
        bf.ExpandState(sha2salt, sha2pass);
        for (var i = 0; i < 64; i++)
        {
            bf.Expand0State(sha2salt);
            bf.Expand0State(sha2pass);
        }

        var magic = "OxychromaticBlowfishSwatDynamite"u8;
        var cdata = new uint[HashWords];
        for (var i = 0; i < HashWords; i++)
        {
            cdata[i] = BinaryPrimitives.ReadUInt32BigEndian(magic[(i * 4)..]);
        }
        for (var i = 0; i < 64; i++)
        {
            for (var b = 0; b < HashWords; b += 2)
            {
                bf.Encipher(ref cdata[b], ref cdata[b + 1]);
            }
        }

        var result = new byte[HashWords * 4];
        for (var i = 0; i < HashWords; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4), cdata[i]);
        }
        return result;
    }

    /// <summary>Blowfish with the "expensive key schedule" hooks bcrypt needs.</summary>
    private sealed class Blowfish
    {
        private readonly uint[] _p = new uint[18];
        private readonly uint[] _s = new uint[1024];

        public Blowfish()
        {
            var init = PiWords.Value;
            Array.Copy(init, 0, _p, 0, 18);
            Array.Copy(init, 18, _s, 0, 1024);
        }

        private uint F(uint x) =>
            ((_s[x >> 24] + _s[0x100 + ((x >> 16) & 0xff)]) ^ _s[0x200 + ((x >> 8) & 0xff)]) + _s[0x300 + (x & 0xff)];

        public void Encipher(ref uint xl, ref uint xr)
        {
            var l = xl ^ _p[0];
            var r = xr;
            for (var i = 1; i <= 16; i += 2)
            {
                r ^= F(l) ^ _p[i];
                l ^= F(r) ^ _p[i + 1];
            }
            xl = r ^ _p[17];
            xr = l;
        }

        private static uint StreamToWord(ReadOnlySpan<byte> data, ref int j)
        {
            uint word = 0;
            for (var i = 0; i < 4; i++)
            {
                if (j >= data.Length)
                {
                    j = 0;
                }
                word = (word << 8) | data[j];
                j++;
            }
            return word;
        }

        public void ExpandState(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
        {
            var j = 0;
            for (var i = 0; i < 18; i++)
            {
                _p[i] ^= StreamToWord(key, ref j);
            }
            j = 0;
            uint l = 0, r = 0;
            for (var i = 0; i < 18; i += 2)
            {
                l ^= StreamToWord(data, ref j);
                r ^= StreamToWord(data, ref j);
                Encipher(ref l, ref r);
                _p[i] = l;
                _p[i + 1] = r;
            }
            for (var i = 0; i < 1024; i += 2)
            {
                l ^= StreamToWord(data, ref j);
                r ^= StreamToWord(data, ref j);
                Encipher(ref l, ref r);
                _s[i] = l;
                _s[i + 1] = r;
            }
        }

        public void Expand0State(ReadOnlySpan<byte> key)
        {
            var j = 0;
            for (var i = 0; i < 18; i++)
            {
                _p[i] ^= StreamToWord(key, ref j);
            }
            uint l = 0, r = 0;
            for (var i = 0; i < 18; i += 2)
            {
                Encipher(ref l, ref r);
                _p[i] = l;
                _p[i + 1] = r;
            }
            for (var i = 0; i < 1024; i += 2)
            {
                Encipher(ref l, ref r);
                _s[i] = l;
                _s[i + 1] = r;
            }
        }
    }

    /// <summary>
    /// Blowfish's initial P-array and S-boxes are the hexadecimal digits of the fractional part of pi
    /// (18 + 1024 words). Computed once with Machin's formula instead of embedding a 4 KB table.
    /// </summary>
    internal static readonly Lazy<uint[]> PiWords = new(() =>
    {
        const int words = 18 + 1024;
        const int guardBits = 64;
        var bits = words * 32 + guardBits;
        var one = BigInteger.One << bits;
        var pi = 16 * ArcTanInverse(5, one) - 4 * ArcTanInverse(239, one);
        var fraction = pi - 3 * one;
        var result = new uint[words];
        for (var i = 0; i < words; i++)
        {
            var shift = bits - 32 * (i + 1);
            result[i] = (uint)((fraction >> shift) & uint.MaxValue);
        }
        return result;
    });

    private static BigInteger ArcTanInverse(int x, BigInteger one)
    {
        var x2 = (BigInteger)x * x;
        var term = one / x;
        var sum = term;
        var n = 1;
        var sign = -1;
        while (!term.IsZero)
        {
            term /= x2;
            n += 2;
            sum += sign * (term / n);
            sign = -sign;
        }
        return sum;
    }
}
