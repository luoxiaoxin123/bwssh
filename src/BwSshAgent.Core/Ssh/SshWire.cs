using System.Buffers.Binary;
using System.Text;

namespace BwSshAgent.Core.Ssh;

public sealed class SshFormatException(string message) : Exception(message);

/// <summary>Reader for SSH wire encoding (RFC 4251).</summary>
public ref struct SshReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _pos;

    public SshReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _pos = 0;
    }

    public int Remaining => _data.Length - _pos;
    public bool End => _pos >= _data.Length;

    public byte ReadByte()
    {
        Ensure(1);
        return _data[_pos++];
    }

    public uint ReadUInt32()
    {
        Ensure(4);
        var v = BinaryPrimitives.ReadUInt32BigEndian(_data[_pos..]);
        _pos += 4;
        return v;
    }

    public ReadOnlySpan<byte> ReadString()
    {
        var len = ReadUInt32();
        if (len > (uint)Remaining)
        {
            throw new SshFormatException("String length exceeds buffer.");
        }
        var s = _data.Slice(_pos, (int)len);
        _pos += (int)len;
        return s;
    }

    public string ReadUtf8() => Encoding.UTF8.GetString(ReadString());

    /// <summary>Reads an mpint and returns its unsigned big-endian magnitude (leading zeros stripped).</summary>
    public byte[] ReadMpint()
    {
        var s = ReadString();
        var start = 0;
        while (start < s.Length && s[start] == 0)
        {
            start++;
        }
        return s[start..].ToArray();
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        Ensure(count);
        var s = _data.Slice(_pos, count);
        _pos += count;
        return s;
    }

    private readonly void Ensure(int count)
    {
        if (count < 0 || _pos + count > _data.Length)
        {
            throw new SshFormatException("Unexpected end of data.");
        }
    }
}

/// <summary>Writer for SSH wire encoding.</summary>
public sealed class SshWriter
{
    private readonly MemoryStream _ms = new();

    public SshWriter WriteByte(byte b)
    {
        _ms.WriteByte(b);
        return this;
    }

    public SshWriter WriteUInt32(uint v)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, v);
        _ms.Write(buf);
        return this;
    }

    public SshWriter WriteString(ReadOnlySpan<byte> s)
    {
        WriteUInt32((uint)s.Length);
        _ms.Write(s);
        return this;
    }

    public SshWriter WriteString(string s) => WriteString(Encoding.UTF8.GetBytes(s));

    /// <summary>Writes an unsigned big-endian magnitude as an mpint.</summary>
    public SshWriter WriteMpint(ReadOnlySpan<byte> magnitude)
    {
        var start = 0;
        while (start < magnitude.Length && magnitude[start] == 0)
        {
            start++;
        }
        var m = magnitude[start..];
        if (m.Length == 0)
        {
            return WriteUInt32(0);
        }
        if ((m[0] & 0x80) != 0)
        {
            WriteUInt32((uint)m.Length + 1);
            _ms.WriteByte(0);
            _ms.Write(m);
            return this;
        }
        return WriteString(m);
    }

    public SshWriter WriteRaw(ReadOnlySpan<byte> data)
    {
        _ms.Write(data);
        return this;
    }

    public byte[] ToArray() => _ms.ToArray();
}
