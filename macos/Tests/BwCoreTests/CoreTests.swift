#if canImport(XCTest)
import XCTest
#endif
import Foundation
import CryptoKit
@testable import BwCore

final class CoreTests: XCTestCase {
    func testPINRestartSettingPreservesExistingPreferences() throws {
        var settings = Settings(); settings.grantMinutes = 42; settings.approvalTimeout = 120; settings.pinEnabled = true
        var legacy = try JSONSerialization.jsonObject(with: JSONEncoder().encode(settings)) as! [String: Any]
        legacy.removeValue(forKey: "pinRequirePrimaryAfterRestart")
        let migrated = try JSONDecoder().decode(Settings.self, from: JSONSerialization.data(withJSONObject: legacy))
        XCTAssertTrue(migrated.pinRequiresPrimaryUnlockAfterRestart)
        XCTAssertEqual(migrated.grantMinutes, 42); XCTAssertEqual(migrated.approvalTimeout, 120); XCTAssertTrue(migrated.pinEnabled)
        settings.pinRequiresPrimaryUnlockAfterRestart = false
        let restored = try JSONDecoder().decode(Settings.self, from: JSONEncoder().encode(settings))
        XCTAssertFalse(restored.pinRequiresPrimaryUnlockAfterRestart); XCTAssertEqual(restored.grantMinutes, 42)
    }
    @MainActor func testPINRestartRequirementToggleAndPersistentFailures() async throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try LocalStore(root: directory, encryptionKey: Crypto.random(32))
        let user = try Crypto.random(64), kdf = KDF(iterations: 5000)
        let master = try kdf.derive(password: "fixture", salt: "fixture@example.com")
        let snapshot: Object = ["profile": [:], "ciphers": []]
        let account = Account(server: try Server(), email: "fixture@example.com", salt: "fixture@example.com", kdf: kdf, accessToken: "", expires: Date(), encryptedUserKey: try Crypto.encrypt(user, key: Crypto.stretch(master)), userID: "fixture", snapshot: try JSONSerialization.data(withJSONObject: snapshot), syncedAt: Date())
        try store.save(account, name: "account")
        let initial = try Vault(store: store, settings: Settings(), transient: true)
        try await initial.unlock(password: "fixture"); try await initial.setPIN("123456")
        var stalePreferences = initial.settings
        stalePreferences.pinEnabled = false; stalePreferences.pinRequiresPrimaryUnlockAfterRestart = false
        let recovered = try Vault(store: store, settings: stalePreferences, transient: true)
        XCTAssertTrue(recovered.settings.pinEnabled); XCTAssertTrue(recovered.pinAvailable)
        try await recovered.unlockPIN("123456"); recovered.lock()
        var settings = initial.settings
        let required = try Vault(store: store, settings: settings, transient: true)
        do { try await required.unlockPIN("123456"); XCTFail("Default policy must require primary unlock after restart") } catch {}
        XCTAssertFalse(required.unlocked); XCTAssertFalse(required.pinAvailable)
        try await required.unlock(password: "fixture"); required.lock()
        XCTAssertTrue(required.pinAvailable)
        try await required.unlockPIN("123456"); XCTAssertTrue(required.unlocked)
        settings.pinRequiresPrimaryUnlockAfterRestart = false
        let direct = try Vault(store: store, settings: settings, transient: true)
        try await direct.unlockPIN("123456"); XCTAssertTrue(direct.unlocked)
        direct.lock(); direct.settings.pinRequiresPrimaryUnlockAfterRestart = true
        let requiredAgain = try Vault(store: store, settings: direct.settings, transient: true)
        do { try await requiredAgain.unlockPIN("123456"); XCTFail("Re-enabling the setting must restore the restart requirement") } catch {}
        XCTAssertFalse(requiredAgain.unlocked)
        for attempt in 1...5 {
            let restarted = try Vault(store: store, settings: settings, transient: true)
            do { try await restarted.unlockPIN("incorrect"); XCTFail("Incorrect PIN must fail") } catch {}
            XCTAssertFalse(restarted.unlocked)
            XCTAssertEqual(restarted.settings.pinEnabled, attempt < 5)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("pin.sealed").path))
        let exhausted = try Vault(store: store, settings: settings, transient: true)
        do { try await exhausted.unlockPIN("123456"); XCTFail("Five failures across restarts must clear the PIN") } catch {}
        XCTAssertFalse(exhausted.unlocked); XCTAssertFalse(exhausted.settings.pinEnabled); XCTAssertFalse(exhausted.pinAvailable)
    }
    func testNotificationActionsRespectLockAndForwarding() throws {
        let identity = PublicIdentity(id: "fixture", name: "Fixture", blob: Data([1]), type: "ssh-ed25519")
        let process = ProcessNode(pid: getpid(), started: 1, path: "/usr/bin/ssh")
        let context = SignContext(keyBlob: identity.blob, data: Data(), flags: 0, host: nil, forwarded: false)
        let request = PendingApproval(id: UUID(), identity: identity, context: context, chain: [process], target: process, destination: "fixture@example.com")
        XCTAssertEqual(request.notificationCategory(unlocked: true), "approval")
        XCTAssertEqual(request.notificationCategory(unlocked: false), "locked")
        XCTAssertEqual(request.notificationChoice(action: "approve", unlocked: true), .approve)
        XCTAssertEqual(request.notificationChoice(action: "grant", unlocked: true), .grant)
        XCTAssertEqual(request.notificationChoice(action: "deny", unlocked: false), .deny)
        XCTAssertTrue(request.notificationChoice(action: "approve", unlocked: false) == nil)
        XCTAssertTrue(request.notificationChoice(action: "grant", unlocked: false) == nil)
        XCTAssertTrue(request.notificationChoice(action: "unknown", unlocked: true) == nil)
        let forwarded = PendingApproval(id: UUID(), identity: identity, context: SignContext(keyBlob: identity.blob, data: Data(), flags: 0, host: nil, forwarded: true), chain: [process], target: process, destination: nil)
        XCTAssertEqual(forwarded.notificationCategory(unlocked: true), "approval-no-grant")
        XCTAssertTrue(forwarded.notificationChoice(action: "grant", unlocked: true) == nil)
        let list = PendingApproval(id: UUID(), identity: nil, context: nil, chain: [], target: nil, destination: nil)
        XCTAssertEqual(list.notificationCategory(unlocked: true), "approval-no-grant")
        XCTAssertTrue(list.notificationChoice(action: "grant", unlocked: true) == nil)
    }
    @MainActor func testLockedStartupUsesCanonicalUnlockTupleAndKeepsMainHidden() async throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try LocalStore(root: directory, encryptionKey: Crypto.random(32))
        let password = "  正确的密码 π  ", salt = "unlock-salt@example.com", kdf = KDF(iterations: 7000)
        let master = try kdf.derive(password: password, salt: salt), user = try Crypto.random(64)
        let wrapped = try Crypto.encrypt(user, key: Crypto.stretch(master)), ssh = try SSHKey.generate()
        let root: Object = ["profile": ["key": "stale legacy wrapper"], "userDecryption": ["masterPasswordUnlock": [
            "masterKeyWrappedUserKey": wrapped, "salt": salt, "kdf": ["kdfType": 0, "iterations": 7000]]],
            "ciphers": [["id": "one", "type": 5, "name": try Crypto.encrypt(Data("Fixture".utf8), key: user),
                "sshKey": ["privateKey": try Crypto.encrypt(Data(ssh.exportOpenSSH().utf8), key: user)]]]]
        let old = Account(server: try Server(), email: "x@example.com", salt: "wrong cached salt", kdf: KDF(iterations: 5000), accessToken: "", expires: Date(), encryptedUserKey: "stale cached wrapper", userID: "one", snapshot: try JSONSerialization.data(withJSONObject: root), syncedAt: Date())
        try store.save(old, name: "account")
        let vault = try Vault(store: store, settings: Settings(), transient: true)
        XCTAssertEqual(vault.screen, .unlock)
        do { try await vault.unlock(password: "incorrect"); XCTFail("Wrong password must fail") } catch {}
        XCTAssertEqual(vault.screen, .unlock); XCTAssertFalse(vault.unlocked)
        try await vault.unlock(password: password)
        XCTAssertEqual(vault.screen, .main); XCTAssertEqual(vault.identities.count, 1)
        let saved = try store.load(Account.self, name: "account")!
        XCTAssertEqual(saved.kdf, kdf); XCTAssertEqual(saved.salt, salt); XCTAssertEqual(saved.encryptedUserKey, wrapped)
        vault.lock(); XCTAssertEqual(vault.screen, .unlock)
        let restarted = try Vault(store: store, settings: Settings(), transient: true)
        XCTAssertEqual(restarted.identities.count, 1); XCTAssertEqual(restarted.screen, .unlock)
        try await restarted.unlock(password: password); XCTAssertEqual(restarted.screen, .main)
        try restarted.logout(); XCTAssertEqual(restarted.screen, .login)
    }
    func testUnlockMaterialDoesNotMixPartialModernParametersWithLegacyKey() throws {
        let fallback = MasterPasswordMaterial(encryptedKey: "legacy", kdf: KDF(iterations: 5000), salt: "original")
        let partial: Object = ["profile": ["key": "legacy"], "userDecryption": ["masterPasswordUnlock": ["salt": "different", "kdf": ["kdfType": 1, "iterations": 3, "memory": 16, "parallelism": 2]]]]
        XCTAssertEqual(try MasterPasswordMaterial.resolve(partial, fallback: fallback), fallback)
        let malformed: Object = ["userDecryption": ["masterPasswordUnlock": ["masterKeyWrappedUserKey": "new"]]]
        XCTAssertThrowsError(try MasterPasswordMaterial.resolve(malformed, fallback: fallback))
    }
    @MainActor func testUnlockAutomaticallyRepairsStaleLegacyKDF() async throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try LocalStore(root: directory, encryptionKey: Crypto.random(32)), user = try Crypto.random(64)
        let master = try KDF(iterations: 5000).derive(password: "fixture", salt: "x@example.com")
        let wrapped = try Crypto.encrypt(user, key: Crypto.stretch(master))
        let snapshot: Object = ["profile": ["id": "user", "key": wrapped], "ciphers": []]
        let stale = Account(server: try Server(), email: "x@example.com", salt: "stale", kdf: KDF(iterations: 7000), accessToken: "fixture", expires: Date().addingTimeInterval(3600), encryptedUserKey: wrapped, userID: "user", snapshot: try JSONSerialization.data(withJSONObject: snapshot), syncedAt: Date())
        try store.save(stale, name: "account")
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [StubURLProtocol.self]
        var requests = 0
        StubURLProtocol.handler = { request in
            requests += 1
            if request.url!.path.hasSuffix("prelogin/password") { return (200, ["kdfSettings": ["kdfType": 0, "iterations": 5000], "salt": "x@example.com"]) }
            return (200, snapshot)
        }
        defer { StubURLProtocol.handler = nil }
        let vault = try Vault(api: BitwardenAPI(session: URLSession(configuration: config)), store: store, settings: Settings(), transient: true)
        try await vault.unlock(password: "fixture"); XCTAssertEqual(vault.screen, .main)
        XCTAssertEqual(requests, 2)
        XCTAssertEqual(vault.account?.kdf, KDF(iterations: 5000)); XCTAssertEqual(vault.account?.salt, "x@example.com")
        vault.lock()
        StubURLProtocol.handler = { _ in requests += 1; return (503, [:]) }
        try await vault.unlock(password: "fixture"); XCTAssertEqual(vault.screen, .main)
        XCTAssertEqual(requests, 2) // Valid cached passwords remain usable offline.
        vault.lock()
        do { try await vault.unlock(password: "incorrect"); XCTFail("Wrong passwords must still fail") } catch {}
        XCTAssertEqual(vault.screen, .unlock); XCTAssertEqual(requests, 3)
        try await vault.unlock(password: "fixture"); XCTAssertEqual(vault.screen, .main)
        XCTAssertEqual(requests, 3) // Failed refresh did not corrupt the working cache.
    }
    @MainActor func testModernLoginSyncAndRestartShareOneUnlockTuple() async throws {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [StubURLProtocol.self]
        let api = BitwardenAPI(session: URLSession(configuration: config))
        let password = "fixture", authKDF = KDF(iterations: 5000), unlockKDF = KDF(iterations: 7000)
        let authMaster = try authKDF.derive(password: password, salt: "authentication-salt")
        let unlockMaster = try unlockKDF.derive(password: password, salt: "unlock-salt")
        let user = try Crypto.random(64), key = try SSHKey.generate()
        let legacy = try Crypto.encrypt(Crypto.random(64), key: Crypto.stretch(authMaster))
        let wrapped = try Crypto.encrypt(user, key: Crypto.stretch(unlockMaster))
        let snapshot: Object = ["profile": ["id": "user", "key": legacy], "userDecryption": ["masterPasswordUnlock": [
            "masterKeyWrappedUserKey": wrapped, "salt": "unlock-salt", "kdf": ["kdfType": 0, "iterations": 7000]]],
            "ciphers": [["id": "key", "type": 5, "name": try Crypto.encrypt(Data("Fixture".utf8), key: user),
                "sshKey": ["privateKey": try Crypto.encrypt(Data(key.exportOpenSSH().utf8), key: user)]]]]
        StubURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("prelogin/password") { return (200, ["kdfSettings": ["kdfType": 0, "iterations": 5000], "salt": "authentication-salt"]) }
            if request.url!.path.hasSuffix("connect/token") { return (200, ["access_token": "fixture", "key": legacy, "expires_in": 3600]) }
            return (200, snapshot)
        }
        defer { StubURLProtocol.handler = nil }
        let (account, decrypted) = try await api.login(server: Server(), email: "x@example.com", password: password, provider: nil, code: "", newDeviceOTP: "", clientID: "", clientSecret: "")
        XCTAssertEqual(decrypted.data(), user); XCTAssertEqual(account.kdf, unlockKDF); XCTAssertEqual(account.salt, "unlock-salt")
        let synced = try await api.sync(account)
        XCTAssertEqual(synced.encryptedUserKey, wrapped); XCTAssertEqual(synced.kdf, unlockKDF); XCTAssertEqual(synced.salt, "unlock-salt")
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try LocalStore(root: directory, encryptionKey: Crypto.random(32)); try store.save(synced, name: "account")
        let vault = try Vault(store: store, settings: Settings(), transient: true)
        XCTAssertEqual(vault.screen, .unlock); try await vault.unlock(password: password)
        XCTAssertEqual(vault.screen, .main); XCTAssertEqual(vault.identities.count, 1)
    }
    func testBitwardenReferenceVectors() throws {
        let password = "correct horse battery staple", salt = "user@example.com"
        let master = try KDF().derive(password: password, salt: salt)
        XCTAssertEqual(master.base64EncodedString(), "VdxKlOSIH/15LWy0Fz1xRXVs2V3cmyMQuw/JMRI8gkg=")
        XCTAssertEqual(try Crypto.pbkdf(master, salt: Data(password.utf8), rounds: 1).base64EncodedString(), "nfEypS52oCiXbQyehOT45BcIhAJYN/5ltdzSYVXHaWg=")
        let stretched = Crypto.stretch(master)
        XCTAssertEqual(stretched.prefix(32).base64EncodedString(), "k97T41uTRs9kxL3q1lcjhWxFhn7zw/soaWJp/CREOUs=")
        XCTAssertEqual(stretched.suffix(32).base64EncodedString(), "Ker/QWdMC7s48J+P3jx3AA4EDswOEJR5A5xptlrLobc=")
        XCTAssertThrowsError(try KDF(iterations: 100).derive(password: "x", salt: "y"))
        XCTAssertThrowsError(try KDF(type: 1, iterations: 3, memory: 2048).derive(password: "x", salt: "y"))
    }
    func testArgon2ReferenceVector() throws {
        // Determinism and salt separation; independent known-answer vector is checked below.
        let a = try Crypto.argon(Data("password".utf8), salt: Data("somesalt".utf8), rounds: 2, memory: 16, lanes: 1)
        XCTAssertEqual(a.count, 32)
        XCTAssertEqual(a, try Crypto.argon(Data("password".utf8), salt: Data("somesalt".utf8), rounds: 2, memory: 16, lanes: 1))
        XCTAssertNotEqual(a, try Crypto.argon(Data("password".utf8), salt: Data("otherSalt".utf8), rounds: 2, memory: 16, lanes: 1))
        XCTAssertEqual(try Crypto.argon(Data("password".utf8), salt: Data("somesalt".utf8), rounds: 2, memory: 64, lanes: 1).map { String(format: "%02x", $0) }.joined(), "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
    }
    func testEncryptionAuthenticatesBeforeDecrypting() throws {
        let key = try Crypto.random(64), message = Data("hello ssh".utf8)
        let enc = try Crypto.encrypt(message, key: key)
        XCTAssertEqual(try Crypto.decrypt(enc, key: key), message)
        var parts = enc.dropFirst(2).split(separator: "|").map(String.init)
        var changed = Data(base64Encoded: parts[1])!; changed[0] ^= 1; parts[1] = changed.base64EncodedString()
        XCTAssertThrowsError(try Crypto.decrypt("2." + parts.joined(separator: "|"), key: key))
        XCTAssertThrowsError(try Crypto.decrypt(enc, key: Crypto.random(64)))
        XCTAssertThrowsError(try Crypto.decrypt("7.AAAA", key: key))
        let iv = try Crypto.random(16), legacy = try Crypto.aes(message, key: Data(key.prefix(32)), iv: iv, encrypt: true)
        XCTAssertEqual(try Crypto.decrypt("0.\(iv.base64EncodedString())|\(legacy.base64EncodedString())", key: Data(key.prefix(32))), message)
    }
    func testSSHWireRejectsMalformedLengths() throws {
        var reader = SSHReader(Data([255, 255, 255, 255])); XCTAssertThrowsError(try reader.string())
        var w = SSHWriter(); w.mpint(Data([0x80])); var r = SSHReader(w.data); XCTAssertEqual(try r.string(), Data([0, 128]))
    }
    func testGeneratedKeysRoundTripAndWipe() throws {
        for rsa in [false, true] {
            let key = try SSHKey.generate(rsa: rsa), data = try Crypto.random(123)
            let parsed = try SSHKey.parse(key.exportOpenSSH())
            XCTAssertEqual(parsed.publicBlob, key.publicBlob)
            for flags: UInt32 in [2, 4] {
                let signature = try parsed.sign(data, flags: flags)
                XCTAssertTrue(SSHKey.verify(publicBlob: key.publicBlob, signature: signature, data: data))
                XCTAssertFalse(SSHKey.verify(publicBlob: key.publicBlob, signature: signature, data: data + Data([1])))
            }
            if rsa { XCTAssertThrowsError(try parsed.sign(data, flags: 0)) }
            parsed.clear(); XCTAssertThrowsError(try parsed.sign(data, flags: 4))
        }
    }
    func testOpenSSHPrivateKeysAndEncryptedImports() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        for (type, bits) in [("ed25519", 0), ("rsa", 2048), ("ecdsa", 256), ("ecdsa", 384), ("ecdsa", 521)] {
            for password in ["", "test passphrase"] {
                let path = directory.appendingPathComponent(UUID().uuidString)
                var args = ["-q", "-t", type, "-N", password, "-f", path.path]
                if bits > 0 { args += ["-b", String(bits)] }
                try run("/usr/bin/ssh-keygen", args)
                let pem = try String(contentsOf: path, encoding: .utf8)
                let key = try SSHKey.parse(pem, passphrase: password)
                let pub = try String(contentsOf: path.appendingPathExtension("pub"), encoding: .utf8).split(separator: " ")
                XCTAssertEqual(key.publicBlob.base64EncodedString(), String(pub[1]))
                let data = try Crypto.random(32)
                XCTAssertTrue(SSHKey.verify(publicBlob: key.publicBlob, signature: try key.sign(data, flags: 4), data: data))
                let roundTrip = try SSHKey.parse(key.exportOpenSSH()); XCTAssertEqual(roundTrip.publicBlob, key.publicBlob)
                if !password.isEmpty { XCTAssertThrowsError(try SSHKey.parse(pem, passphrase: "incorrect")) }
            }
        }
    }
    func testPEMAndPKCS8Imports() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        for (type, bits) in [("rsa", 2048), ("ecdsa", 384)] {
            let path = directory.appendingPathComponent(type)
            try run("/usr/bin/ssh-keygen", ["-q", "-t", type, "-b", String(bits), "-m", "PEM", "-N", "", "-f", path.path])
            let plain = try SSHKey.parse(String(contentsOf: path, encoding: .utf8))
            let pkcs8 = directory.appendingPathComponent(type + ".pkcs8")
            try run("/usr/bin/openssl", ["pkcs8", "-topk8", "-nocrypt", "-in", path.path, "-out", pkcs8.path])
            XCTAssertEqual(try SSHKey.parse(String(contentsOf: pkcs8, encoding: .utf8)).publicBlob, plain.publicBlob)
            try run("/usr/bin/openssl", ["pkcs8", "-topk8", "-v2", "aes-256-cbc", "-in", path.path, "-out", pkcs8.path, "-passout", "pass:fixture-password"])
            XCTAssertEqual(try SSHKey.parse(String(contentsOf: pkcs8, encoding: .utf8), passphrase: "fixture-password").publicBlob, plain.publicBlob)
        }
    }
    func testSessionBindRejectsTamperingAndUnknownSession() async throws {
        let key = try SSHKey.generate(), session = try Crypto.random(32), other = try Crypto.random(32)
        let signature = try key.sign(session, flags: 0)
        var w = SSHWriter(); w.string(key.publicBlob); w.string(session); w.string(signature); w.byte(0)
        var binding = SessionBinding(); XCTAssertTrue(binding.bind(w.data))
        var auth = SSHWriter(); auth.string(session); auth.byte(50); auth.text("git"); auth.text("ssh-connection"); auth.text("publickey")
        XCTAssertEqual(binding.host(for: auth.data), key.fingerprint)
        var invalid = SSHWriter(); invalid.string(key.publicBlob); invalid.string(other); invalid.string(signature); invalid.byte(1)
        XCTAssertFalse(binding.bind(invalid.data)); XCTAssertFalse(binding.forwarded)
        var unknownAuth = SSHWriter(); unknownAuth.string(other); unknownAuth.byte(50); unknownAuth.text("git"); unknownAuth.text("ssh-connection"); unknownAuth.text("publickey")
        var sign = SSHWriter(); sign.byte(13); sign.string(key.publicBlob); sign.string(unknownAuth.data); sign.uint32(0)
        let response = await SocketServer.handle(sign.data, chain: [], binding: &binding, identities: { [] }, sign: { _ in XCTFail("Unbound session must never reach approval"); return nil })
        XCTAssertEqual(response, Data([5]))
    }
    func testVaultDecryptsOnlySSHItemsAndPreservesErrors() throws {
        let key = try SSHKey.generate(), user = try Crypto.random(64), item = try Crypto.random(64)
        let cipher: Object = ["id": "key1", "type": 5, "name": try Crypto.encrypt(Data("Example".utf8), key: item),
                              "key": try Crypto.encrypt(item, key: user), "sshKey": ["privateKey": try Crypto.encrypt(Data(key.exportOpenSSH().utf8), key: item)]]
        var deleted = cipher; deleted["id"] = "deleted"; deleted["deletedDate"] = "2026-01-01"
        var bad = cipher; bad["id"] = "bad"; bad["key"] = "2.invalid"
        let root: Object = ["profile": [:], "ciphers": [cipher, deleted, bad, ["type": 1, "id": "password"]]]
        let account = Account(server: try Server(), email: "x@example.com", salt: "x@example.com", kdf: KDF(), accessToken: "", expires: Date(), encryptedUserKey: "", userID: "x", snapshot: try JSONSerialization.data(withJSONObject: root), syncedAt: Date())
        let loaded = try VaultDecryptor.load(account, userKey: Secret(user))
        XCTAssertEqual(loaded.identities.map(\.name), ["Example"]); XCTAssertEqual(loaded.errors.count, 1)
        XCTAssertEqual(loaded.keys["key1"]?.publicBlob, key.publicBlob)
    }
    func testSSHConfigurationRoundTripAndIdempotence() throws {
        let original = "Host github.com\n  User git\n  Port 2222\n"
        let configured = try SSHConfiguration.configured(original, executable: "/Applications/bwssh.app/Contents/MacOS/bwssh", socket: "/tmp/agent.sock", onDemand: true)
        XCTAssertEqual(try SSHConfiguration.configured(configured, executable: "/Applications/bwssh.app/Contents/MacOS/bwssh", socket: "/tmp/agent.sock", onDemand: true), configured)
        XCTAssertEqual(try SSHConfiguration.removingBlock(configured), original)
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("config")
        let parseable = try SSHConfiguration.configured(original, executable: "/usr/bin/true", socket: "/tmp/agent.sock", onDemand: true)
        try parseable.write(to: file, atomically: true, encoding: .utf8)
        let output = try run("/usr/bin/ssh", ["-G", "-F", file.path, "github.com"])
        XCTAssertTrue(output.contains("identityagent /tmp/agent.sock")); XCTAssertTrue(output.contains("port 2222")); XCTAssertTrue(output.contains("user git"))
        XCTAssertThrowsError(try SSHConfiguration.removingBlock(SSHConfiguration.begin + "\nbroken"))
    }
    func testActualOpenSSHAgentSigning() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("agent.sock").path
        let keys = try [SSHKey.generate(), SSHKey.generate(rsa: true)] + [256, 384, 521].map { bits in
            let file = directory.appendingPathComponent("ec\(bits)")
            try run("/usr/bin/ssh-keygen", ["-q", "-t", "ecdsa", "-b", String(bits), "-N", "", "-f", file.path])
            return try SSHKey.parse(String(contentsOf: file, encoding: .utf8))
        }
        let identities = keys.enumerated().map { PublicIdentity(id: String($0.offset), name: "test-\($0.offset)", blob: $0.element.publicBlob, type: $0.element.type) }
        let server = SocketServer(path: path) { data, chain, binding in
            XCTAssertFalse(chain.isEmpty)
            return await SocketServer.handle(data, chain: chain, binding: &binding, identities: { identities }, sign: { context in
                try? keys.first(where: { $0.publicBlob == context.keyBlob })?.sign(context.data, flags: context.flags)
            })
        }
        try server.start(); defer { server.stop() }
        var info = stat(); XCTAssertEqual(lstat(path, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
        XCTAssertTrue(SocketServer.isRunning(path: path))
        let env = ["SSH_AUTH_SOCK": path]
        let listed = try run("/usr/bin/ssh-add", ["-L"], env: env)
        XCTAssertEqual(listed.split(separator: "\n").count, 5)
        for (index, key) in keys.enumerated() {
            let pub = directory.appendingPathComponent("pub\(index)")
            try key.publicLine.write(to: pub, atomically: true, encoding: .utf8)
            if key.type != "ssh-rsa" { _ = try run("/usr/bin/ssh-add", ["-T", pub.path], env: env) }
            let message = directory.appendingPathComponent("message\(index)")
            try "signed by bwssh\n".write(to: message, atomically: true, encoding: .utf8)
            try run("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", pub.path, "-n", "git", message.path], env: env)
            let allowed = directory.appendingPathComponent("allowed\(index)")
            try "fixture \(key.publicLine)\n".write(to: allowed, atomically: true, encoding: .utf8)
            let verified = try run("/usr/bin/ssh-keygen", ["-Y", "verify", "-f", allowed.path, "-I", "fixture", "-n", "git", "-s", message.path + ".sig"], input: Data("signed by bwssh\n".utf8))
            XCTAssertTrue(verified.contains("Good"))
        }
    }
    func testEncryptedStorageAuthenticatesFilenameAndPermissions() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let key = try Crypto.random(32), store = try LocalStore(root: directory, encryptionKey: key)
        try store.save(["token": "secret-token"], name: "account")
        let url = directory.appendingPathComponent("account.sealed"), raw = try Data(contentsOf: url)
        XCTAssertFalse(String(decoding: raw, as: UTF8.self).contains("secret-token"))
        XCTAssertEqual(try store.load([String: String].self, name: "account"), ["token": "secret-token"])
        var info = stat(); XCTAssertEqual(lstat(url.path, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
        try raw.write(to: directory.appendingPathComponent("other.sealed")); XCTAssertThrowsError(try store.load([String: String].self, name: "other"))
        let wrong = try LocalStore(root: directory, encryptionKey: Crypto.random(32)); XCTAssertThrowsError(try wrong.load([String: String].self, name: "account"))
    }
    @MainActor func testApprovalPoliciesCancellationAndLock() async throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try LocalStore(root: directory, encryptionKey: Crypto.random(32))
        let key = try SSHKey.generate(), user = try Crypto.random(64), master = try KDF(iterations: 5000).derive(password: "fixture", salt: "x@example.com")
        let root: Object = ["profile": [:], "ciphers": [["id": "key1", "type": 5, "name": try Crypto.encrypt(Data("Fixture".utf8), key: user),
            "sshKey": ["privateKey": try Crypto.encrypt(Data(key.exportOpenSSH().utf8), key: user)]]]]
        let account = Account(server: try Server(), email: "x@example.com", salt: "x@example.com", kdf: KDF(iterations: 5000), accessToken: "", expires: Date(), encryptedUserKey: try Crypto.encrypt(user, key: Crypto.stretch(master)), userID: "x", snapshot: try JSONSerialization.data(withJSONObject: root), syncedAt: Date())
        try store.save(account, name: "account")
        let vault = try Vault(store: store, settings: Settings()), agent = try Agent(vault: vault, store: store)
        try await vault.unlock(password: "fixture"); XCTAssertTrue(vault.unlocked)
        let chain = ProcessNode.chain(getpid()), context = SignContext(keyBlob: key.publicBlob, data: Data("hello".utf8), flags: 0, host: "SHA256:host", forwarded: false)
        var prompts = 0
        agent.onPrompt = { request in prompts += 1; agent.resolve(request.id, choice: .deny) }
        let denied = await agent.sign(context, chain: chain); XCTAssertTrue(denied == nil); XCTAssertEqual(prompts, 1)
        agent.onPrompt = { request in prompts += 1; agent.resolve(request.id, choice: .approve) }
        vault.settings.promptMode = "remember"
        let approved = await agent.sign(context, chain: chain); XCTAssertTrue(approved != nil)
        _ = await agent.sign(context, chain: chain); XCTAssertEqual(prompts, 2)
        let otherHost = SignContext(keyBlob: key.publicBlob, data: context.data, flags: 0, host: "SHA256:other", forwarded: false)
        _ = await agent.sign(otherHost, chain: chain); XCTAssertEqual(prompts, 3)
        agent.revokeAll(); vault.settings.promptMode = "always"
        agent.onPrompt = { request in prompts += 1; agent.resolve(request.id, choice: .grant) }
        _ = await agent.sign(context, chain: chain); XCTAssertEqual(agent.grants.count, 1)
        _ = await agent.sign(context, chain: chain); XCTAssertEqual(prompts, 4)
        let forwarded = SignContext(keyBlob: key.publicBlob, data: context.data, flags: 0, host: "SHA256:host", forwarded: true)
        _ = await agent.sign(forwarded, chain: chain); XCTAssertEqual(prompts, 5)
        vault.lock(); XCTAssertFalse(vault.unlocked); XCTAssertTrue(agent.grants.isEmpty)
        XCTAssertThrowsError(try vault.sign(id: "key1", data: context.data, flags: 0))
        try await vault.unlock(password: "fixture")
        agent.onPrompt = { _ in }
        let pending = Task { await agent.sign(context, chain: chain) }
        for _ in 0..<100 { if !agent.pending.isEmpty { break }; await Task.yield() }
        XCTAssertEqual(agent.pending.count, 1); let expiredID = agent.pending.first!.id; pending.cancel(); let cancelled = await pending.value
        XCTAssertTrue(cancelled == nil); XCTAssertTrue(agent.pending.isEmpty)
        agent.resolve(expiredID, choice: .grant) // A late notification response cannot resurrect a cancelled request.
        XCTAssertTrue(agent.pending.isEmpty); XCTAssertTrue(agent.grants.isEmpty)
        vault.settings.promptMode = "never"; let automatic = await agent.sign(context, chain: chain); XCTAssertTrue(automatic != nil)
        vault.lock(); vault.settings.promptMode = "always"
        agent.onPrompt = { request in agent.resolve(request.id, choice: .approve) }
        let locked = await agent.sign(context, chain: chain); XCTAssertTrue(locked == nil)
        XCTAssertEqual(agent.audit.count, 10)
        let restored = try Vault(store: store, settings: Settings()); XCTAssertFalse(restored.unlocked); XCTAssertEqual(restored.identities.count, 1)
    }
    func testEd25519PKCS8Import() throws {
        let seed = try Crypto.random(32)
        let encoded = DER.sequence(DER.integer(Data([0])), DER.sequence(Data([6, 3, 0x2b, 0x65, 0x70])), DER.wrap(4, DER.wrap(4, seed)))
        let key = try SSHKey.parse("-----BEGIN PRIVATE KEY-----\n" + encoded.base64EncodedString() + "\n-----END PRIVATE KEY-----")
        XCTAssertEqual(key.type, "ssh-ed25519")
        var expected = SSHWriter(); expected.text("ssh-ed25519"); expected.string(try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation)
        XCTAssertEqual(key.publicBlob, expected.data)
    }
    func testBitwardenLoginAndLegacyFallback() async throws {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [StubURLProtocol.self]
        let api = BitwardenAPI(session: URLSession(configuration: config)), server = try Server("https://vault.example.com")
        let user = try Crypto.random(64), master = try KDF(iterations: 5000).derive(password: "fixture", salt: "x@example.com")
        let encrypted = try Crypto.encrypt(user, key: Crypto.stretch(master))
        for legacy in [false, true] {
            var calls = [String]()
            StubURLProtocol.handler = { request in
                let path = request.url!.path; calls.append(path)
                XCTAssertEqual(request.value(forHTTPHeaderField: "Device-Type"), "7")
                if path == "/identity/accounts/prelogin/password" {
                    return legacy ? (404, [:]) : (200, ["kdfSettings": ["kdfType": 0, "iterations": 5000], "salt": "x@example.com"])
                }
                if path == "/identity/accounts/prelogin" { return (200, ["kdf": 0, "kdfIterations": 5000]) }
                if path == "/identity/connect/token" {
                    XCTAssertEqual(request.value(forHTTPHeaderField: "Auth-Email"), "eEBleGFtcGxlLmNvbQ")
                    return (200, ["access_token": "access", "refresh_token": "refresh", "expires_in": 3600, "Key": encrypted])
                }
                XCTAssertEqual(path, "/api/sync"); XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer access")
                return (200, ["Profile": ["Id": "user1", "Key": encrypted], "Ciphers": []])
            }
            let (account, key) = try await api.login(server: server, email: "x@example.com", password: "fixture", provider: nil, code: "", newDeviceOTP: "", clientID: "", clientSecret: "")
            XCTAssertEqual(key.data(), user); XCTAssertEqual(account.userID, "user1"); XCTAssertEqual(account.refreshToken, "refresh")
            XCTAssertEqual(calls.count, legacy ? 4 : 3)
        }
        StubURLProtocol.handler = nil
    }
    func testBitwardenTwoFactorChallenge() async throws {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [StubURLProtocol.self]
        let api = BitwardenAPI(session: URLSession(configuration: config))
        StubURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("prelogin/password") { return (200, ["kdfSettings": ["kdfType": 0, "iterations": 5000]]) }
            return (400, ["TwoFactorProviders2": ["0": [:], "1": ["Email": "x***@example.com"]], "SsoEmail2faSessionToken": "fixture-session"])
        }
        defer { StubURLProtocol.handler = nil }
        do {
            _ = try await api.login(server: Server(), email: "x@example.com", password: "fixture", provider: nil, code: "", newDeviceOTP: "", clientID: "", clientSecret: "")
            XCTFail("Expected a two-factor challenge")
        } catch let c as LoginChallenge { XCTAssertEqual(Set(c.providers), Set([0, 1])); XCTAssertFalse(c.newDevice); XCTAssertEqual(c.session, "fixture-session") }
    }
    func testAPIKeySessionRenewsAfterExpiration() async throws {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [StubURLProtocol.self]
        let api = BitwardenAPI(session: URLSession(configuration: config))
        var account = Account(server: try Server(), email: "x@example.com", salt: "x@example.com", kdf: KDF(), accessToken: "expired", expires: .distantPast, encryptedUserKey: "", userID: "x", snapshot: Data(), syncedAt: Date())
        account.apiClientID = "user.fixture"; account.apiClientSecret = "fixture-api-secret"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/connect/token")
            return (200, ["access_token": "renewed", "expires_in": 3600])
        }
        defer { StubURLProtocol.handler = nil }
        let refreshed = try await api.refreshed(account)
        XCTAssertEqual(refreshed.accessToken, "renewed"); XCTAssertEqual(refreshed.apiClientID, account.apiClientID)
        XCTAssertTrue(refreshed.expires > Date())
    }
    @MainActor func testRenamePreservesEncryptedMetadataAndAttachments() async throws {
        let key = try Crypto.random(64)
        let original: Object = ["Type": 5, "Name": "old ciphertext", "Notes": "notes ciphertext", "Fields": [["Name": "field ciphertext", "Value": "value ciphertext"]],
            "FolderId": "folder", "Favorite": true, "RevisionDate": "revision", "Key": "wrapped key", "SshKey": ["PrivateKey": "private ciphertext", "PublicKey": "public ciphertext", "KeyFingerprint": "fp ciphertext"],
            "Attachments": [["Id": "attachment", "FileName": "file ciphertext", "Key": "attachment key"]]]
        let renamed = try Vault.renameRequest(original, userID: "user", key: key, name: "new name")
        XCTAssertEqual(renamed.text("notes"), original.text("notes")); XCTAssertEqual(renamed.text("folderId"), "folder")
        XCTAssertEqual(renamed.object("sshKey").text("privateKey"), "private ciphertext")
        XCTAssertEqual(renamed.object("attachments2").object("attachment").text("fileName"), "file ciphertext")
        XCTAssertEqual(renamed.text("lastKnownRevisionDate"), "revision")
        XCTAssertEqual(try Crypto.decrypt(renamed.text("name")!, key: key), Data("new name".utf8))
    }
    func temporaryDirectory() throws -> URL {
        let directory = URL(fileURLWithPath: "/tmp/bwssh-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true); return directory
    }
    @discardableResult func run(_ executable: String, _ arguments: [String], env: [String: String] = [:], input: Data? = nil) throws -> String {
        let p = Process(), out = Pipe(); p.executableURL = URL(fileURLWithPath: executable); p.arguments = arguments
        p.environment = ProcessInfo.processInfo.environment.merging(env) { _, new in new }; p.standardOutput = out; p.standardError = out
        if let input { let pipe = Pipe(); p.standardInput = pipe; try p.run(); pipe.fileHandleForWriting.write(input); try pipe.fileHandleForWriting.close() }
        else { p.standardInput = FileHandle.nullDevice; try p.run() }
        let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit(); let text = String(decoding: data, as: UTF8.self)
        guard p.terminationStatus == 0 else { throw BwError("\(executable) \(arguments) failed (\(p.terminationStatus), reason \(p.terminationReason.rawValue)): \(text)") }; return text
    }
}

final class StubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, Object))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw BwError("Missing HTTP fixture") }
            let (status, object) = try handler(request)
            let data = try JSONSerialization.data(withJSONObject: object)
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data); client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
