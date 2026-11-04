import Foundation
import Security
import CryptoKit

public final class SSHKey {
    public let type: String
    public let publicBlob: Data
    private var seed: Secret?
    private var secKey: SecKey?
    private var privateFields: Secret?
    public var fingerprint: String { publicBlob.fingerprint }
    public var publicLine: String { "\(type) \(publicBlob.base64EncodedString())" }

    private init(type: String, publicBlob: Data, seed: Data? = nil, secKey: SecKey? = nil, fields: Data? = nil) {
        self.type = type; self.publicBlob = publicBlob; self.seed = seed.map(Secret.init); self.secKey = secKey; self.privateFields = fields.map(Secret.init)
    }
    public func clear() { seed = nil; secKey = nil; privateFields = nil }
    public func sign(_ data: Data, flags: UInt32) throws -> Data {
        var algorithm = type; let signature: Data
        if let seed {
            var raw = seed.data(); defer { raw.wipe() }
            signature = try Curve25519.Signing.PrivateKey(rawRepresentation: raw).signature(for: data)
        } else if let secKey {
            let alg: SecKeyAlgorithm
            if type == "ssh-rsa" {
                if flags & 2 != 0 { alg = .rsaSignatureMessagePKCS1v15SHA256; algorithm = "rsa-sha2-256" }
                else if flags & 4 != 0 { alg = .rsaSignatureMessagePKCS1v15SHA512; algorithm = "rsa-sha2-512" }
                else { throw BwError("RSA SHA-1 signing is disabled") }
            } else { alg = Self.ecAlgorithm(type) }
            var error: Unmanaged<CFError>?
            guard let signed = SecKeyCreateSignature(secKey, alg, data as CFData, &error) else {
                throw error?.takeRetainedValue() as Error? ?? BwError("Signing failed")
            }
            if type.hasPrefix("ecdsa-") {
                var offset = 0; let sequence = try DER.read(signed as Data, at: &offset).1; offset = 0
                let r = try DER.read(sequence, at: &offset).1; let s = try DER.read(sequence, at: &offset).1
                var w = SSHWriter(); w.mpint(r); w.mpint(s); signature = w.data
            } else { signature = signed as Data }
        } else { throw BwError("Key is locked") }
        var w = SSHWriter(); w.text(algorithm); w.string(signature); return w.data
    }
    private static func ecAlgorithm(_ type: String) -> SecKeyAlgorithm {
        type.hasSuffix("nistp256") ? .ecdsaSignatureMessageX962SHA256 : type.hasSuffix("nistp384") ? .ecdsaSignatureMessageX962SHA384 : .ecdsaSignatureMessageX962SHA512
    }
    private static func createSec(_ raw: Data, type: CFString, isPrivate: Bool = true) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(raw as CFData, [kSecAttrKeyType: type, kSecAttrKeyClass: isPrivate ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic] as CFDictionary, &error) else {
            throw error?.takeRetainedValue() as Error? ?? BwError("Invalid key")
        }; return key
    }
    public static func parse(_ pem: String, passphrase: String = "") throws -> SSHKey {
        guard pem.utf8.count <= 1_048_576 else { throw BwError("Private key is too large") }
        if pem.contains("BEGIN ENCRYPTED PRIVATE KEY") {
            let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("---") }.joined()
            guard let encoded = Data(base64Encoded: body) else { throw BwError("Invalid PKCS#8 key") }
            var plain = try decryptPKCS8(encoded, passphrase: passphrase); defer { plain.wipe() }
            return try parse("-----BEGIN PRIVATE KEY-----\n" + plain.base64EncodedString() + "\n-----END PRIVATE KEY-----")
        }
        if pem.contains("BEGIN PRIVATE KEY") {
            let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("---") }.joined()
            if var encoded = Data(base64Encoded: body) {
                defer { encoded.wipe() }; var offset = 0
                let seq = try DER.read(encoded, at: &offset).1; offset = 0
                _ = try DER.read(seq, at: &offset); let algorithm = try DER.read(seq, at: &offset).1
                if algorithm == Data([6, 3, 0x2b, 0x65, 0x70]) {
                    var privateOctet = try DER.read(seq, at: &offset).1; defer { privateOctet.wipe() }; offset = 0
                    var seed = try DER.read(privateOctet, at: &offset).1; defer { seed.wipe() }
                    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed), pub = key.publicKey.rawRepresentation
                    var w = SSHWriter(); w.text("ssh-ed25519"); w.string(pub)
                    var fields = SSHWriter(); fields.text("ssh-ed25519"); fields.string(pub); fields.string(seed + pub)
                    return SSHKey(type: "ssh-ed25519", publicBlob: w.data, seed: seed, fields: fields.data)
                }
                var a = 0; let oid = try DER.read(algorithm, at: &a).1
                var privateOctet = try DER.read(seq, at: &offset).1; defer { privateOctet.wipe() }
                if oid == Data([0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1]) {
                    return try fromSec(createSec(privateOctet, type: kSecAttrKeyTypeRSA))
                }
                if oid == Data([0x2a,0x86,0x48,0xce,0x3d,2,1]) {
                    let curve = try DER.read(algorithm, at: &a).1
                    return try fromEC(privateOctet, curve: curve)
                }
            }
        }
        if !pem.contains("Proc-Type:"), pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN EC PRIVATE KEY") {
            let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("---") }.joined()
            guard var encoded = Data(base64Encoded: body) else { throw BwError("Invalid PEM encoding") }; defer { encoded.wipe() }
            if pem.contains("BEGIN RSA PRIVATE KEY") { return try fromSec(createSec(encoded, type: kSecAttrKeyTypeRSA)) }
            return try fromEC(encoded, curve: nil)
        }
        if pem.contains("BEGIN OPENSSH PRIVATE KEY") {
            let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("---") }.joined()
            guard var raw = Data(base64Encoded: body) else { throw BwError("Invalid OpenSSH key") }; defer { raw.wipe() }
            var r = SSHReader(raw)
            guard try r.bytes(15) == Data("openssh-key-v1\0".utf8) else { throw BwError("Invalid OpenSSH header") }
            let cipher = try r.text(); let kdf = try r.text(); let options = try r.string()
            guard try r.uint32() == 1 else { throw BwError("Only single-key OpenSSH files are supported") }
            let publicBlob = try r.string(); var fields = try r.string(); defer { fields.wipe() }
            if cipher != "none" {
                guard kdf == "bcrypt", cipher == "aes256-ctr" || cipher == "aes256-cbc", !passphrase.isEmpty else {
                    throw BwError(tr("需要私钥密码，或私钥加密算法不受支持。", "A passphrase is required, or the key cipher is unsupported."))
                }
                var o = SSHReader(options); let salt = try o.string(); let rounds = try o.uint32()
                var material = try Crypto.bcrypt(passphrase, salt: salt, rounds: rounds, count: 48); defer { material.wipe() }
                fields = try Crypto.aes(fields, key: Data(material.prefix(32)), iv: Data(material.suffix(16)), encrypt: false, ctr: cipher.hasSuffix("ctr"), padding: false)
            } else if kdf != "none" { throw BwError("Invalid OpenSSH KDF") }
            var f = SSHReader(fields)
            guard try f.uint32() == f.uint32() else { throw BwError(tr("私钥密码不正确。", "Incorrect private-key passphrase.")) }
            let start = f.offset; let type = try f.text(); let key: SSHKey
            if type == "ssh-ed25519" {
                let pub = try f.string(); var secret = try f.string(); defer { secret.wipe() }
                guard pub.count == 32, secret.count == 64,
                      try Curve25519.Signing.PrivateKey(rawRepresentation: secret.prefix(32)).publicKey.rawRepresentation == pub,
                      secret.suffix(32) == pub else { throw BwError("Ed25519 key mismatch") }
                key = SSHKey(type: type, publicBlob: publicBlob, seed: Data(secret.prefix(32)))
            } else if type == "ssh-rsa" {
                let n = try f.string(), e = try f.string(), d = try f.string(), iq = try f.string(), p = try f.string(), q = try f.string()
                var der = try DER.sequence(DER.integer(Data([0])), DER.integer(n), DER.integer(e), DER.integer(d), DER.integer(p), DER.integer(q),
                    DER.integer(DER.remainder(d, modulusMinusOne: p)), DER.integer(DER.remainder(d, modulusMinusOne: q)), DER.integer(iq))
                defer { der.wipe() }
                var expected = SSHWriter(); expected.text(type); expected.mpint(e); expected.mpint(n)
                guard expected.data == publicBlob else { throw BwError("RSA public key mismatch") }
                key = SSHKey(type: type, publicBlob: publicBlob, secKey: try createSec(der, type: kSecAttrKeyTypeRSA))
            } else if ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"].contains(type) {
                let curve = try f.text(), pub = try f.string(), scalar = try f.string()
                let size = type.hasSuffix("256") ? 32 : type.hasSuffix("384") ? 48 : 66
                let d = scalar.drop(while: { $0 == 0 }); guard d.count <= size, pub.count == 1 + size * 2, curve == String(type.dropFirst(11)) else { throw BwError("Invalid EC key") }
                var bytes = pub + Data(repeating: 0, count: size - d.count) + d; defer { bytes.wipe() }
                let sec = try createSec(bytes, type: kSecAttrKeyTypeECSECPrimeRandom)
                var error: Unmanaged<CFError>?
                guard let derived = SecKeyCopyPublicKey(sec).flatMap({ SecKeyCopyExternalRepresentation($0, &error) }), derived as Data == pub else { throw BwError("EC public key mismatch") }
                var expected = SSHWriter(); expected.text(type); expected.text(curve); expected.string(pub)
                guard expected.data == publicBlob else { throw BwError("EC key mismatch") }
                key = SSHKey(type: type, publicBlob: publicBlob, secKey: sec)
            } else { throw BwError("Unsupported SSH key: \(type)") }
            let end = f.offset
            key.privateFields = Secret(fields.subdata(in: start..<end))
            _ = try f.string() // comment
            let pad = try f.bytes(f.remaining)
            guard pad.count <= 16, pad.enumerated().allSatisfy({ $0.element == UInt8(truncatingIfNeeded: $0.offset + 1) }) else { throw BwError("Invalid OpenSSH padding") }
            var pubReader = SSHReader(publicBlob); guard try pubReader.text() == type else { throw BwError("Public key type mismatch") }
            return key
        }
        // Security.framework imports PKCS#1, PKCS#8 and SEC1 PEM, including encrypted PEM.
        var format = SecExternalFormat.formatUnknown; var itemType = SecExternalItemType.itemTypePrivateKey
        let password = passphrase as CFString
        var params = SecItemImportExportKeyParameters(); params.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        params.passphrase = Unmanaged.passUnretained(password)
        // Transient, extractable and non-sensitive, so it can be normalized to OpenSSH before encryption.
        // A nil attributes array defaults to SENSITIVE, which forbids raw private-key export.
        let attributes = [kSecAttrIsExtractable] as CFArray
        params.keyAttributes = Unmanaged.passUnretained(attributes)
        var items: CFArray?
        let status = SecItemImport(Data(pem.utf8) as CFData, nil, &format, &itemType, [], &params, nil, &items)
        guard status == errSecSuccess, let key = (items as? [SecKey])?.first else { throw BwError("PEM import failed (\(status))") }
        return try fromSec(key)
    }
    private static func decryptPKCS8(_ encoded: Data, passphrase: String) throws -> Data {
        func read(_ data: Data, _ offset: inout Int, tag: UInt8) throws -> Data {
            let (actual, value) = try DER.read(data, at: &offset); guard actual == tag else { throw BwError("Invalid PKCS#8 parameters") }; return value
        }
        var offset = 0; let sequence = try read(encoded, &offset, tag: 0x30); offset = 0
        let alg = try read(sequence, &offset, tag: 0x30), ciphertext = try read(sequence, &offset, tag: 4)
        var a = 0; let oid = try read(alg, &a, tag: 6)
        guard oid == Data([0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,13]) else { throw BwError("Only PBES2 encrypted PKCS#8 is supported") }
        let params = try read(alg, &a, tag: 0x30); a = 0
        let kdf = try read(params, &a, tag: 0x30), encryption = try read(params, &a, tag: 0x30)
        var k = 0
        guard try read(kdf, &k, tag: 6) == Data([0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,12]) else { throw BwError("Unsupported PKCS#8 KDF") }
        let kd = try read(kdf, &k, tag: 0x30); k = 0
        let salt = try read(kd, &k, tag: 4), roundsData = try read(kd, &k, tag: 2)
        guard roundsData.count <= 4 else { throw BwError("Excessive PKCS#8 KDF cost") }
        let rounds = roundsData.reduce(0) { $0 * 256 + Int($1) }
        var sha1 = true
        if k < kd.count, kd[k] == 2 { _ = try read(kd, &k, tag: 2) } // optional key length
        if k < kd.count {
            let prf = try read(kd, &k, tag: 0x30); var p = 0; let oid = try read(prf, &p, tag: 6)
            guard oid == Data([0x2a,0x86,0x48,0x86,0xf7,0x0d,2,7]) || oid == Data([0x2a,0x86,0x48,0x86,0xf7,0x0d,2,9]) else { throw BwError("Unsupported PKCS#8 PBKDF2 PRF") }
            sha1 = oid.last == 7
        }
        var e = 0; let cipherOID = try read(encryption, &e, tag: 6), iv = try read(encryption, &e, tag: 4)
        guard cipherOID.dropLast() == Data([0x60,0x86,0x48,1,0x65,3,4,1]), let mode = cipherOID.last, [2,22,42].contains(mode) else { throw BwError("Unsupported PKCS#8 cipher (use AES-CBC)") }
        let size = mode == 2 ? 16 : mode == 22 ? 24 : 32
        var password = Data(passphrase.utf8); defer { password.wipe() }
        var derived = try Crypto.pbkdf(password, salt: salt, rounds: rounds, count: size, sha1: sha1); defer { derived.wipe() }
        return try Crypto.aes(ciphertext, key: derived, iv: iv, encrypt: false)
    }
    private static func fromEC(_ encoded: Data, curve: Data?) throws -> SSHKey {
        var offset = 0; let sequence = try DER.read(encoded, at: &offset).1; offset = 0
        _ = try DER.read(sequence, at: &offset)
        var scalar = try DER.read(sequence, at: &offset).1; defer { scalar.wipe() }
        var curve = curve
        while offset < sequence.count {
            let (tag, value) = try DER.read(sequence, at: &offset)
            if tag == 0xa0 { var p = 0; curve = try DER.read(value, at: &p).1 }
        }
        if let explicit = curve, explicit.count > 32 {
            // Some macOS ssh-keygen versions export explicit SEC1 parameters. Match the complete
            // domain (p, a, b, generator, order, cofactor), rather than guessing from scalar length.
            var p = 0; _ = try DER.read(explicit, at: &p)
            let field = try DER.read(explicit, at: &p).1; var f = 0
            guard try DER.read(field, at: &f).1 == Data([0x2a,0x86,0x48,0xce,0x3d,1,1]) else { throw BwError("Unsupported EC field") }
            let prime = try DER.read(field, at: &f).1
            let coefficients = try DER.read(explicit, at: &p).1; var c = 0
            let a = try DER.read(coefficients, at: &c).1, b = try DER.read(coefficients, at: &c).1
            let generator = try DER.read(explicit, at: &p).1, order = try DER.read(explicit, at: &p).1
            let cofactor = p < explicit.count ? try DER.read(explicit, at: &p).1 : Data([1])
            var canonical = SSHWriter()
            for part in [Data(prime.drop(while: { $0 == 0 })), a, b, generator, Data(order.drop(while: { $0 == 0 })), Data(cofactor.drop(while: { $0 == 0 }))] { canonical.string(part) }
            let digest = canonical.data.sha256.map { String(format: "%02x", $0) }.joined()
            switch digest {
            case "02bb879cb2f89c19579105be662247db15ab45875cfc63a58745361d193ba248": curve = Data([0x2a,0x86,0x48,0xce,0x3d,3,1,7])
            case "e8fadbd7eba284a1e97e1feec24e908d72a93144f37228c894b97cce9bff6a5e": curve = Data([0x2b,0x81,4,0,0x22])
            case "d9d83ba9a27e78e82ba350762ca8c4c82d87cfc286b0a294445f7c6d8dbf37f8": curve = Data([0x2b,0x81,4,0,0x23])
            default: throw BwError("Unsupported explicit EC domain")
            }
        }
        let pub: Data
        switch curve {
        case Data([0x2a,0x86,0x48,0xce,0x3d,3,1,7]): pub = try P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
        case Data([0x2b,0x81,4,0,0x22]): pub = try P384.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
        case Data([0x2b,0x81,4,0,0x23]): pub = try P521.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
        default: throw BwError("Unsupported EC curve")
        }
        var raw = pub + scalar; defer { raw.wipe() }
        return try fromSec(createSec(raw, type: kSecAttrKeyTypeECSECPrimeRandom))
    }
    private static func fromSec(_ key: SecKey) throws -> SSHKey {
        var error: Unmanaged<CFError>?
        guard let pubKey = SecKeyCopyPublicKey(key), let publicData = SecKeyCopyExternalRepresentation(pubKey, &error),
              let privateData = SecKeyCopyExternalRepresentation(key, &error), let attrs = SecKeyCopyAttributes(key) as? [String: Any] else { throw BwError("Key export failed") }
        var raw = privateData as Data; defer { raw.wipe() }
        let pub = publicData as Data; var w = SSHWriter(); var fields = SSHWriter(); let type: String
        if attrs[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeRSA as String {
            type = "ssh-rsa"; var offset = 0; let seq = try DER.read(raw, at: &offset).1; offset = 0
            var ints = [Data](); while offset < seq.count { ints.append(try DER.read(seq, at: &offset).1) }
            guard ints.count == 9 else { throw BwError("Invalid RSA private key") }
            w.text(type); w.mpint(ints[2]); w.mpint(ints[1])
            fields.text(type); for index in [1, 2, 3, 8, 4, 5] { fields.mpint(ints[index]) }
        } else {
            let bits = attrs[kSecAttrKeySizeInBits as String] as? Int ?? 0
            guard [256, 384, 521].contains(bits) else { throw BwError("Unsupported key size") }
            let curve = "nistp\(bits)"; type = "ecdsa-sha2-\(curve)"
            w.text(type); w.text(curve); w.string(pub)
            fields.text(type); fields.text(curve); fields.string(pub); fields.mpint(Data(raw.suffix((bits + 7) / 8)))
        }
        return SSHKey(type: type, publicBlob: w.data, secKey: key, fields: fields.data)
    }
    public static func generate(rsa: Bool = false) throws -> SSHKey {
        if rsa {
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 3072] as CFDictionary, &error) else { throw error!.takeRetainedValue() }
            return try fromSec(key)
        }
        let key = Curve25519.Signing.PrivateKey(); let pub = key.publicKey.rawRepresentation
        var w = SSHWriter(); w.text("ssh-ed25519"); w.string(pub)
        var fields = SSHWriter(); fields.text("ssh-ed25519"); fields.string(pub); fields.string(key.rawRepresentation + pub)
        return SSHKey(type: "ssh-ed25519", publicBlob: w.data, seed: key.rawRepresentation, fields: fields.data)
    }
    public func exportOpenSSH() throws -> String {
        guard let privateFields else { throw BwError("Key is locked") }
        let random = try Crypto.random(4); var r = SSHReader(random); let check = try r.uint32()
        var fields = SSHWriter(); fields.uint32(check); fields.uint32(check)
        var body = fields.data + privateFields.data(); defer { body.wipe() }
        var comment = SSHWriter(); comment.text(""); body += comment.data
        let padding = 8 - body.count % 8; body.append(contentsOf: (1...padding).map(UInt8.init))
        var outer = SSHWriter(); outer.text("none"); outer.text("none"); outer.string(Data()); outer.uint32(1); outer.string(publicBlob); outer.string(body)
        var data = Data("openssh-key-v1\0".utf8) + outer.data; defer { data.wipe() }
        let b64 = data.base64EncodedString(); var lines = [String](); var start = b64.startIndex
        while start < b64.endIndex { let end = b64.index(start, offsetBy: 70, limitedBy: b64.endIndex) ?? b64.endIndex; lines.append(String(b64[start..<end])); start = end }
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines.joined(separator: "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
    }
    public static func verify(publicBlob: Data, signature: Data, data: Data) -> Bool {
        do {
            var k = SSHReader(publicBlob), s = SSHReader(signature)
            let type = try k.text(), algorithm = try s.text(), sig = try s.string()
            guard s.remaining == 0 else { return false }
            if type == "ssh-ed25519" {
                guard algorithm == type else { return false }
                return try Curve25519.Signing.PublicKey(rawRepresentation: k.string()).isValidSignature(sig, for: data)
            }
            let key: SecKey; let alg: SecKeyAlgorithm; let rawSignature: Data
            if type == "ssh-rsa" {
                let e = try k.string(), n = try k.string()
                guard algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512" else { return false }
                key = try createSec(DER.sequence(DER.integer(n), DER.integer(e)), type: kSecAttrKeyTypeRSA, isPrivate: false)
                alg = algorithm.hasSuffix("256") ? .rsaSignatureMessagePKCS1v15SHA256 : .rsaSignatureMessagePKCS1v15SHA512
                rawSignature = sig
            } else {
                guard algorithm == type, ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"].contains(type) else { return false }
                let curve = try k.text(); guard "ecdsa-sha2-" + curve == type else { return false }
                key = try createSec(k.string(), type: kSecAttrKeyTypeECSECPrimeRandom, isPrivate: false); alg = ecAlgorithm(type)
                var inner = SSHReader(sig); let r = try inner.string(), s = try inner.string(); guard inner.remaining == 0 else { return false }
                rawSignature = DER.sequence(DER.integer(r), DER.integer(s))
            }
            return SecKeyVerifySignature(key, alg, data as CFData, rawSignature as CFData, nil)
        } catch { return false }
    }
}
