import Foundation
import CryptoKit
import CommonCrypto
import Security
import CBwCrypto

public struct BwError: LocalizedError {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public func tr(_ zh: String, _ en: String) -> String {
    Locale.preferredLanguages.first?.hasPrefix("zh") == true ? zh : en
}

/// Owned, non-copy-on-write storage. mlock is best effort; every owned byte is wiped on release.
public final class Secret {
    private let pointer: UnsafeMutableRawPointer
    public let count: Int
    public init(_ data: Data) {
        count = data.count
        pointer = .allocate(byteCount: max(count, 1), alignment: 16)
        data.withUnsafeBytes { if let p = $0.baseAddress { pointer.copyMemory(from: p, byteCount: count) } }
        _ = mlock(pointer, count)
    }
    public func data() -> Data { Data(bytes: pointer, count: count) }
    deinit { bw_wipe(pointer, count); _ = munlock(pointer, count); pointer.deallocate() }
}

extension Data {
    mutating func wipe() { withUnsafeMutableBytes { if let p = $0.baseAddress { bw_wipe(p, $0.count) } }; removeAll() }
    var sha256: Data { Data(SHA256.hash(data: self)) }
    public var fingerprint: String { "SHA256:" + sha256.base64EncodedString().replacingOccurrences(of: "=", with: "") }
}

public struct KDF: Codable, Equatable {
    public var type: Int
    public var iterations: Int
    public var memory: Int
    public var parallelism: Int
    public init(type: Int = 0, iterations: Int = 600_000, memory: Int = 64, parallelism: Int = 4) {
        self.type = type; self.iterations = iterations; self.memory = memory; self.parallelism = parallelism
    }
    public func derive(password: String, salt: String) throws -> Data {
        var input = Data(password.utf8); defer { input.wipe() }
        guard iterations > 0, iterations <= 10_000_000 else { throw BwError("Invalid KDF iterations") }
        if type == 0 {
            guard iterations >= 5_000 else { throw BwError("Weak PBKDF2 settings") }
            return try Crypto.pbkdf(input, salt: Data(salt.utf8), rounds: iterations)
        }
        guard type == 1, iterations >= 2, iterations <= 100, memory >= 16, memory <= 1024,
              parallelism >= 1, parallelism <= 16 else { throw BwError("Unsupported or excessive Argon2id parameters") }
        return try Crypto.argon(input, salt: Data(salt.utf8).sha256, rounds: iterations, memory: memory, lanes: parallelism)
    }
}

public enum Crypto {
    public static func random(_ count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw BwError("Random generator failed") }
        return data
    }
    public static func pbkdf(_ password: Data, salt: Data, rounds: Int, count: Int = 32, sha1: Bool = false) throws -> Data {
        guard rounds > 0, rounds <= 10_000_000, count > 0, count <= 1024 else { throw BwError("Invalid PBKDF2 parameters") }
        var result = Data(count: count)
        let status = result.withUnsafeMutableBytes { out in password.withUnsafeBytes { pass in salt.withUnsafeBytes { s in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pass.baseAddress?.assumingMemoryBound(to: Int8.self), password.count,
                s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count, CCPseudoRandomAlgorithm(sha1 ? kCCPRFHmacAlgSHA1 : kCCPRFHmacAlgSHA256), UInt32(rounds), out.baseAddress!.assumingMemoryBound(to: UInt8.self), count)
        } } }
        guard status == kCCSuccess else { throw BwError("PBKDF2 failed") }; return result
    }
    public static func argon(_ password: Data, salt: Data, rounds: Int = 3, memory: Int = 64, lanes: Int = 1) throws -> Data {
        var result = Data(count: 32)
        let status = result.withUnsafeMutableBytes { out in password.withUnsafeBytes { p in salt.withUnsafeBytes { s in
            argon2id_hash_raw(UInt32(rounds), UInt32(memory * 1024), UInt32(lanes), p.baseAddress, password.count, s.baseAddress, salt.count, out.baseAddress, 32)
        } } }
        guard status == ARGON2_OK.rawValue else { throw BwError("Argon2id failed: \(status)") }; return result
    }
    public static func bcrypt(_ password: String, salt: Data, rounds: UInt32, count: Int) throws -> Data {
        guard rounds > 0, rounds <= 1_000_000 else { throw BwError("Invalid bcrypt rounds") }
        var input = Data(password.utf8); defer { input.wipe() }
        var output = Data(count: count)
        let status = output.withUnsafeMutableBytes { o in input.withUnsafeBytes { p in salt.withUnsafeBytes { s in
            bcrypt_pbkdf(p.baseAddress!.assumingMemoryBound(to: Int8.self), input.count,
                s.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                o.baseAddress!.assumingMemoryBound(to: UInt8.self), count, rounds)
        } } }
        guard status == 0 else { throw BwError("bcrypt derivation failed") }; return output
    }
    public static func stretch(_ master: Data) -> Data {
        // Bitwarden uses HKDF-Expand, without the HKDF-Extract step.
        Data(HMAC<SHA256>.authenticationCode(for: Data("enc".utf8) + Data([1]), using: SymmetricKey(data: master))) +
        Data(HMAC<SHA256>.authenticationCode(for: Data("mac".utf8) + Data([1]), using: SymmetricKey(data: master)))
    }
    public static func aes(_ input: Data, key: Data, iv: Data, encrypt: Bool, ctr: Bool = false, padding: Bool = true) throws -> Data {
        guard [16, 24, 32].contains(key.count), iv.count == 16 else { throw BwError("Invalid AES key or IV") }
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
            CCCryptorCreateWithMode(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCMode(ctr ? kCCModeCTR : kCCModeCBC),
                CCAlgorithm(kCCAlgorithmAES), CCPadding(padding && !ctr ? ccPKCS7Padding : ccNoPadding), v.baseAddress, k.baseAddress, key.count, nil, 0, 0,
                CCModeOptions(ctr ? kCCModeOptionCTR_BE : 0), &cryptor)
        } }
        guard status == kCCSuccess, let cryptor else { throw BwError("AES initialization failed") }
        defer { CCCryptorRelease(cryptor) }
        var output = Data(count: input.count + 32); var written = 0; var tail = 0
        let update = output.withUnsafeMutableBytes { out in input.withUnsafeBytes { i in
            CCCryptorUpdate(cryptor, i.baseAddress, input.count, out.baseAddress, out.count, &written)
        } }
        let final = output.withUnsafeMutableBytes { out in
            CCCryptorFinal(cryptor, out.baseAddress!.advanced(by: written), out.count - written, &tail)
        }
        guard update == kCCSuccess, final == kCCSuccess else { output.wipe(); throw BwError(tr("解密失败，请检查密码。", "Decryption failed. Check the password.")) }
        output.count = written + tail; return output
    }
    public static func decrypt(_ value: String, key: Data) throws -> Data {
        let dot = value.firstIndex(of: ".")
        let type = dot.flatMap { Int(value[..<$0]) } ?? (value.split(separator: "|").count == 3 ? 2 : 0)
        let body = dot.map { String(value[value.index(after: $0)...]) } ?? value
        let parts = body.split(separator: "|", omittingEmptySubsequences: false).map { Data(base64Encoded: String($0)) }
        guard (type == 2 && parts.count == 3) || (type == 0 && parts.count == 2),
              let iv = parts[0], let cipher = parts[1], iv.count == 16, key.count >= 32 else {
            throw BwError("Unsupported encryption format (type \(type)); COSE is not supported")
        }
        if type == 2 {
            guard key.count == 64, let mac = parts[2], HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: iv + cipher, using: SymmetricKey(data: key.suffix(32))) else {
                throw BwError(tr("密码错误或密文校验失败。", "Incorrect password or invalid ciphertext authentication."))
            }
        }
        return try aes(cipher, key: Data(key.prefix(32)), iv: iv, encrypt: false)
    }
    public static func encrypt(_ input: Data, key: Data) throws -> String {
        guard key.count == 64 else { throw BwError("A 64-byte encryption key is required") }
        let iv = try random(16)
        let cipher = try aes(input, key: Data(key.prefix(32)), iv: iv, encrypt: true)
        let mac = Data(HMAC<SHA256>.authenticationCode(for: iv + cipher, using: SymmetricKey(data: key.suffix(32))))
        return "2.\(iv.base64EncodedString())|\(cipher.base64EncodedString())|\(mac.base64EncodedString())"
    }
    public static func decryptUserKey(_ value: String, master: Data) throws -> Data {
        try decrypt(value, key: value.hasPrefix("0.") ? master : stretch(master))
    }
}
