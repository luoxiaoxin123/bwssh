import Foundation

public struct SSHReader {
    private let data: Data
    public private(set) var offset = 0
    public init(_ data: Data) { self.data = data }
    public var remaining: Int { data.count - offset }
    public mutating func bytes(_ count: Int) throws -> Data {
        guard count >= 0, count <= remaining else { throw BwError("Truncated SSH message") }
        defer { offset += count }; return data.subdata(in: offset..<(offset + count))
    }
    public mutating func byte() throws -> UInt8 { try bytes(1)[0] }
    public mutating func uint32() throws -> UInt32 { try bytes(4).reduce(0) { ($0 << 8) | UInt32($1) } }
    public mutating func string() throws -> Data { let n = try uint32(); return try bytes(Int(n)) }
    public mutating func text() throws -> String {
        guard let result = String(data: try string(), encoding: .utf8) else { throw BwError("Invalid UTF-8") }; return result
    }
}

public struct SSHWriter {
    public private(set) var data = Data()
    public init() {}
    @discardableResult public mutating func byte(_ value: UInt8) -> Self { data.append(value); return self }
    @discardableResult public mutating func uint32(_ value: UInt32) -> Self {
        data.append(contentsOf: [UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]); return self
    }
    @discardableResult public mutating func string(_ value: Data) -> Self { uint32(UInt32(value.count)); data.append(value); return self }
    @discardableResult public mutating func text(_ value: String) -> Self { string(Data(value.utf8)); return self }
    @discardableResult public mutating func mpint(_ value: Data) -> Self {
        var v = Data(value.drop(while: { $0 == 0 })); if let first = v.first, first & 128 != 0 { v.insert(0, at: 0) }; return string(v)
    }
    public static func strings(_ values: Data...) -> Data { var w = Self(); for v in values { w.string(v) }; return w.data }
}

enum DER {
    static func length(_ n: Int) -> Data {
        if n < 128 { return Data([UInt8(n)]) }
        var n = n; var bytes = Data(); while n > 0 { bytes.insert(UInt8(n & 255), at: 0); n >>= 8 }
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }
    static func wrap(_ tag: UInt8, _ data: Data) -> Data { Data([tag]) + length(data.count) + data }
    static func integer(_ data: Data) -> Data {
        var value = Data(data.drop(while: { $0 == 0 })); if value.isEmpty { value = Data([0]) }
        if value[0] & 128 != 0 { value.insert(0, at: 0) }; return wrap(2, value)
    }
    static func sequence(_ values: Data...) -> Data { wrap(0x30, values.reduce(Data(), +)) }
    static func read(_ data: Data, at offset: inout Int) throws -> (UInt8, Data) {
        guard offset + 2 <= data.count else { throw BwError("Invalid DER") }
        let tag = data[offset]; offset += 1; var n = Int(data[offset]); offset += 1
        if n & 128 != 0 {
            let c = n & 127; guard c > 0, c <= 4, offset + c <= data.count else { throw BwError("Invalid DER length") }
            n = 0; for _ in 0..<c { n = n * 256 + Int(data[offset]); offset += 1 }
        }
        guard n <= data.count - offset else { throw BwError("Truncated DER") }
        defer { offset += n }; return (tag, data.subdata(in: offset..<(offset + n)))
    }
    /// Remainder for RSA CRT exponents. Public import operation; no signing uses this arithmetic.
    static func remainder(_ value: Data, modulusMinusOne: Data) throws -> Data {
        var m = Array(modulusMinusOne.drop(while: { $0 == 0 }))
        guard !m.isEmpty else { throw BwError("Invalid RSA prime") }
        var i = m.count - 1
        while m[i] == 0 { m[i] = 255; guard i > 0 else { throw BwError("Invalid RSA prime") }; i -= 1 }; m[i] -= 1
        var r = [UInt8](repeating: 0, count: m.count + 1); let mod = [UInt8(0)] + m
        for byte in value {
            for bit in (0..<8).reversed() {
                var carry = (byte >> bit) & 1
                for j in r.indices.reversed() { let next = r[j] >> 7; r[j] = (r[j] << 1) | carry; carry = next }
                if !r.lexicographicallyPrecedes(mod) {
                    var borrow = 0
                    for j in r.indices.reversed() { let x = Int(r[j]) - Int(mod[j]) - borrow; r[j] = UInt8(truncatingIfNeeded: x); borrow = x < 0 ? 1 : 0 }
                }
            }
        }
        return Data(r.drop(while: { $0 == 0 }))
    }
}
