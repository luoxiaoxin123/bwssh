import Foundation
import Combine
import Security
import LocalAuthentication

public struct PublicIdentity: Codable, Identifiable, Equatable {
    public var id: String
    public var name: String
    public var blob: Data
    public var type: String
    public var fingerprint: String { blob.fingerprint }
    public var publicLine: String { "\(type) \(blob.base64EncodedString()) \(name.replacingOccurrences(of: "\n", with: " "))" }
}

struct LoadedVault {
    var identities: [PublicIdentity]
    var keys: [String: SSHKey]
    var errors: [String]
}

enum VaultDecryptor {
    static func root(_ account: Account) throws -> Object {
        guard let root = try JSONSerialization.jsonObject(with: account.snapshot) as? Object else { throw BwError("Invalid vault snapshot") }; return root
    }
    static func organizationKeys(_ root: Object, userKey: Data) throws -> [String: Data] {
        let profile = root.object("profile"); let orgs = profile.objects("organizations")
        guard !orgs.isEmpty else { return [:] }
        let encrypted = profile.object("accountKeys").object("publicKeyEncryptionKeyPair").text("wrappedPrivateKey") ?? profile.text("privateKey")
        guard let encrypted else { throw BwError("Missing organization private key") }
        var raw = try Crypto.decrypt(encrypted, key: userKey); defer { raw.wipe() }
        // Bitwarden's account private key is PKCS#8. Security expects PKCS#1.
        var offset = 0; let sequence = try DER.read(raw, at: &offset).1; offset = 0
        _ = try DER.read(sequence, at: &offset); _ = try DER.read(sequence, at: &offset)
        var pkcs1 = try DER.read(sequence, at: &offset).1; defer { pkcs1.wipe() }
        var error: Unmanaged<CFError>?
        guard let rsa = SecKeyCreateWithData(pkcs1 as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, &error) else { throw BwError("Invalid account RSA key") }
        var keys = [String: Data]()
        for org in orgs {
            guard let id = org.text("id"), let value = org.text("key"), let dot = value.firstIndex(of: "."),
                  let type = Int(value[..<dot]), [3, 4, 5, 6].contains(type), let payload = value[value.index(after: dot)...].split(separator: "|").first,
                  let data = Data(base64Encoded: String(payload)) else { continue }
            if let key = SecKeyCreateDecryptedData(rsa, type == 3 || type == 5 ? .rsaEncryptionOAEPSHA256 : .rsaEncryptionOAEPSHA1, data as CFData, &error) { keys[id] = key as Data }
        }; return keys
    }
    static func resolve(_ cipher: Object, userKey: Data, orgs: [String: Data]) throws -> Data {
        let base: Data
        if let org = cipher.text("organizationId") { guard let key = orgs[org] else { throw BwError("Missing organization key") }; base = key }
        else { base = userKey }
        return try cipher.text("key").map { try Crypto.decrypt($0, key: base) } ?? base
    }
    static func load(_ account: Account, userKey: Secret) throws -> LoadedVault {
        let root = try root(account); var raw = userKey.data(); defer { raw.wipe() }
        var errors = [String](); var orgs = [String: Data]()
        do { orgs = try organizationKeys(root, userKey: raw) } catch { errors.append(error.localizedDescription) }
        defer { for id in Array(orgs.keys) { orgs[id]?.wipe() } }
        var result = LoadedVault(identities: [], keys: [:], errors: [])
        for cipher in root.objects("ciphers") where cipher.number("type") == 5 && cipher.text("deletedDate") == nil && cipher.text("archivedDate") == nil {
            guard let id = cipher.text("id"), let encrypted = cipher.object("sshKey").text("privateKey") else { continue }
            do {
                var key = try resolve(cipher, userKey: raw, orgs: orgs); defer { key.wipe() }
                let name = try cipher.text("name").map { String(decoding: try Crypto.decrypt($0, key: key), as: UTF8.self) } ?? "SSH key"
                var pem = try Crypto.decrypt(encrypted, key: key); defer { pem.wipe() }
                let ssh = try SSHKey.parse(String(decoding: pem, as: UTF8.self))
                result.keys[id] = ssh; result.identities.append(PublicIdentity(id: id, name: name, blob: ssh.publicBlob, type: ssh.type))
            } catch { errors.append("\(id): \(error.localizedDescription)") }
        }
        result.errors = errors; return result
    }
}

private struct PinEnvelope: Codable { var salt: Data; var encrypted: String; var attempts: Int }

public enum VaultScreen: Equatable { case login, unlock, main }

@MainActor public final class Vault: ObservableObject {
    @Published public private(set) var account: Account?
    @Published public private(set) var identities: [PublicIdentity] = []
    @Published public private(set) var unlocked = false
    @Published public private(set) var errors: [String] = []
    @Published public var settings: Settings
    @Published public var busy = false
    @Published public var message = ""
    public var pinAvailable: Bool { settings.pinEnabled && (!settings.pinRequiresPrimaryUnlockAfterRestart || pinWrappingKey != nil) }
    public var screen: VaultScreen { account == nil ? .login : unlocked ? .main : .unlock }
    public var onLock: (() -> Void)?
    public var onKeysChanged: (() -> Void)?
    public let api: BitwardenAPI
    private let store: LocalStore
    private var userKey: Secret?
    private var keys = [String: SSHKey]()
    @Published private var pinWrappingKey: Secret?
    private var epoch = 0
    private let transient: Bool
    public init(api: BitwardenAPI = BitwardenAPI(), store: LocalStore? = nil, settings: Settings = Settings.load(), transient: Bool = false) throws {
        self.api = api; self.store = try store ?? LocalStore(); self.settings = settings
        self.transient = transient
        account = try self.store.load(Account.self, name: "account")
        if account != nil {
            identities = try self.store.load([PublicIdentity].self, name: "public-keys") ?? []
            // The encrypted PIN file is authoritative when preferences and stored data disagree.
            self.settings.pinEnabled = try self.store.load(PinEnvelope.self, name: "pin") != nil
        }
    }
    public func saveSettings() {
        guard !transient else { return }
        do { try settings.save() } catch { message = error.localizedDescription }
    }
    public func perform(_ action: @escaping () async throws -> Void) {
        guard !busy else { return }; busy = true; message = ""
        Task { defer { busy = false }; do { try await action() } catch { message = error.localizedDescription } }
    }
    public func login(server: Server, email: String, password: String, provider: Int?, code: String, otp: String, clientID: String, clientSecret: String) async throws {
        let generation = epoch
        let (account, key) = try await api.login(server: server, email: email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), password: password, provider: provider, code: code, newDeviceOTP: otp, clientID: clientID, clientSecret: clientSecret)
        guard epoch == generation else { throw CancellationError() }
        let loaded = try await Task.detached { try VaultDecryptor.load(account, userKey: key) }.value
        guard epoch == generation else { throw CancellationError() }
        try clearQuickUnlock()
        try store.save(account, name: "account"); try store.save(loaded.identities, name: "public-keys")
        self.account = account; apply(loaded, key: key)
    }
    public func unlock(password: String) async throws {
        guard var account else { throw BwError("Sign in first") }; let generation = epoch
        let result: (Secret, MasterPasswordMaterial)
        do { result = try await Self.passwordKey(password, account: account) }
        catch {
            let cachedError = error
            guard generation == epoch else { throw CancellationError() }
            guard !account.accessToken.isEmpty || account.refreshToken != nil else { throw cachedError }
            // Keep offline unlock fast. Only a failed cached unwrap attempts one metadata repair.
            do {
                let (kdf, salt) = try await api.prelogin(server: account.server, email: account.email)
                guard generation == epoch else { throw CancellationError() }
                account.kdf = kdf; account.salt = salt
                account = try await api.sync(account)
                guard generation == epoch else { throw CancellationError() }
                result = try await Self.passwordKey(password, account: account)
            } catch {
                guard generation == epoch, !Task.isCancelled else { throw CancellationError() }
                throw cachedError
            }
        }
        guard generation == epoch else { throw CancellationError() }
        try await unlock(key: result.0, generation: generation, restorePIN: true)
        result.1.apply(to: &account)
        try store.save(account, name: "account"); self.account = account
    }
    private static func passwordKey(_ password: String, account: Account) async throws -> (Secret, MasterPasswordMaterial) {
        let material = try MasterPasswordMaterial.cached(account)
        let key = try await Task.detached {
            var master = try material.kdf.derive(password: password, salt: material.salt); defer { master.wipe() }
            var raw = try Crypto.decryptUserKey(material.encryptedKey, master: master); defer { raw.wipe() }
            return Secret(raw)
        }.value
        return (key, material)
    }
    private func unlock(key: Secret, generation: Int, restorePIN: Bool) async throws {
        guard let account else { throw BwError("Sign in first") }
        let loaded = try await Task.detached { try VaultDecryptor.load(account, userKey: key) }.value
        guard epoch == generation else { throw CancellationError() }
        try store.save(loaded.identities, name: "public-keys"); apply(loaded, key: key)
        if restorePIN, settings.pinEnabled, let saved = try store.load(PinEnvelope.self, name: "pin") {
            // Restore PIN availability for this process when the restart requirement is enabled.
            pinWrappingKey = Secret(try Crypto.random(32))
            var saved = saved; saved.attempts = 0; try store.save(saved, name: "pin")
        }
    }
    private func apply(_ loaded: LoadedVault, key: Secret) {
        for key in keys.values { key.clear() }
        keys = loaded.keys; identities = loaded.identities; errors = loaded.errors; userKey = key; unlocked = true
        onKeysChanged?()
    }
    public func lock() {
        epoch += 1; for key in keys.values { key.clear() }; keys.removeAll(); userKey = nil; unlocked = false
        onLock?()
    }
    public func logout() throws {
        lock(); try clearQuickUnlock()
        try store.delete("account"); try store.delete("public-keys"); account = nil; identities = []; errors = []
    }
    public func sync() async throws {
        guard let account else { throw BwError("Sign in first") }; let generation = epoch
        let updated = try await api.sync(account)
        guard epoch == generation else { throw CancellationError() }
        if let userKey {
            let loaded = try await Task.detached { try VaultDecryptor.load(updated, userKey: userKey) }.value
            guard epoch == generation else { throw CancellationError() }
            try store.save(loaded.identities, name: "public-keys"); apply(loaded, key: userKey)
        }
        try store.save(updated, name: "account"); self.account = updated
        onLock?() // synchronizing may remove a key or change its access; clear all cached decisions.
    }
    public func sign(id: String, data: Data, flags: UInt32) throws -> Data {
        guard unlocked, let key = keys[id] else { throw BwError("Vault is locked or key unavailable") }
        return try key.sign(data, flags: flags)
    }
    public func enableTouchID() throws {
        guard !transient else { throw BwError("Unavailable in UI preview") }
        guard let userKey else { throw BwError("Unlock first") }
        var error: NSError?; let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { throw error ?? BwError("Touch ID is unavailable") as NSError }
        var raw = userKey.data(); defer { raw.wipe() }
        try Keychain.put(raw, name: "touch-id", biometric: true); settings.touchIDEnabled = true; try settings.save()
    }
    public func unlockTouchID() async throws {
        guard !transient else { throw BwError("Unavailable in UI preview") }
        let generation = epoch
        let context = LAContext(); context.localizedReason = tr("解锁 bwssh 密码库", "Unlock the bwssh vault")
        let key = try await Task.detached { () throws -> Secret in
            guard var data = try Keychain.get("touch-id", context: context) else { throw BwError("Touch ID is not configured") }
            defer { data.wipe() }; return Secret(data)
        }.value
        try await unlock(key: key, generation: generation, restorePIN: true)
    }
    public func setPIN(_ pin: String) async throws {
        guard let userKey, pin.count >= 4, pin.count <= 128 else { throw BwError(tr("先解锁，PIN 至少 4 位。", "Unlock first. Use a PIN of at least 4 characters.")) }
        let salt = try Crypto.random(16)
        var derived = try await Task.detached { try Crypto.argon(Data(pin.utf8), salt: salt) }.value; defer { derived.wipe() }
        guard self.userKey === userKey, unlocked else { throw CancellationError() }
        var raw = userKey.data(); defer { raw.wipe() }
        let envelope = PinEnvelope(salt: salt, encrypted: try Crypto.encrypt(raw, key: Crypto.stretch(derived)), attempts: 0)
        try store.save(envelope, name: "pin"); pinWrappingKey = Secret(try Crypto.random(32))
        settings.pinEnabled = true; if !transient { try settings.save() }
    }
    public func unlockPIN(_ pin: String) async throws {
        guard settings.pinEnabled else { throw BwError(tr("尚未设置 PIN。", "PIN is not configured.")) }
        guard !settings.pinRequiresPrimaryUnlockAfterRestart || pinWrappingKey != nil else { throw BwError(tr("本次启动后请先用主密码或 Touch ID 解锁一次。", "Use the master password or Touch ID once after starting the app.")) }
        guard var envelope = try store.load(PinEnvelope.self, name: "pin") else { throw BwError("PIN is not configured") }
        let generation = epoch
        envelope.attempts += 1; try store.save(envelope, name: "pin")
        do {
            let key = try await Task.detached { () throws -> Secret in
                var derived = try Crypto.argon(Data(pin.utf8), salt: envelope.salt); defer { derived.wipe() }
                var raw = try Crypto.decrypt(envelope.encrypted, key: Crypto.stretch(derived)); defer { raw.wipe() }; return Secret(raw)
            }.value
            try await unlock(key: key, generation: generation, restorePIN: false)
            envelope.attempts = 0; try store.save(envelope, name: "pin")
        } catch {
            if envelope.attempts >= 5 { try store.delete("pin"); settings.pinEnabled = false; pinWrappingKey = nil; if !transient { try settings.save() } }
            throw error
        }
    }
    private func clearQuickUnlock() throws {
        if transient { settings.pinEnabled = false; settings.touchIDEnabled = false; pinWrappingKey = nil; return }
        try Keychain.delete("touch-id"); try store.delete("pin"); pinWrappingKey = nil
        settings.pinEnabled = false; settings.touchIDEnabled = false; try settings.save()
    }
    public func disableQuickUnlock() throws { try clearQuickUnlock() }
    public func add(name: String, pem: String, passphrase: String, rsa: Bool?) async throws {
        guard let userKey, var account, unlocked else { throw BwError("Unlock first") }
        let generation = epoch
        let key = try await Task.detached { try rsa.map { try SSHKey.generate(rsa: $0) } ?? SSHKey.parse(pem, passphrase: passphrase) }.value
        defer { key.clear() }
        account = try await api.refreshed(account)
        guard generation == epoch else { throw CancellationError() }
        var itemKey = try Crypto.random(64), rawUser = userKey.data(); defer { itemKey.wipe(); rawUser.wipe() }
        let body: Object = ["type": 5, "organizationId": NSNull(), "folderId": NSNull(), "favorite": false, "reprompt": 0,
            "encryptedFor": account.userID, "key": try Crypto.encrypt(itemKey, key: rawUser), "name": try Crypto.encrypt(Data(name.utf8), key: itemKey),
            "notes": NSNull(), "sshKey": ["privateKey": try Crypto.encrypt(Data(key.exportOpenSSH().utf8), key: itemKey),
            "publicKey": try Crypto.encrypt(Data(key.publicLine.utf8), key: itemKey), "keyFingerprint": try Crypto.encrypt(Data(key.fingerprint.utf8), key: itemKey)]]
        self.account = account; try store.save(account, name: "account")
        try await api.mutate(account, method: "POST", path: "/ciphers", body: body); try await sync()
    }
    public func rename(_ id: String, name: String) async throws {
        guard let userKey, var account, unlocked else { throw BwError("Unlock first") }; let generation = epoch
        let root = try VaultDecryptor.root(account)
        guard let cipher = root.objects("ciphers").first(where: { $0.text("id") == id }) else { throw BwError("Sync first") }
        var rawUser = userKey.data(); defer { rawUser.wipe() }
        var orgs = try VaultDecryptor.organizationKeys(root, userKey: rawUser); defer { for id in Array(orgs.keys) { orgs[id]?.wipe() } }
        var key = try VaultDecryptor.resolve(cipher, userKey: rawUser, orgs: orgs); defer { key.wipe() }
        let body = try Self.renameRequest(cipher, userID: account.userID, key: key, name: name)
        account = try await api.refreshed(account); guard generation == epoch else { throw CancellationError() }
        self.account = account; try store.save(account, name: "account")
        try await api.mutate(account, method: "PUT", path: "/ciphers/\(id)", body: body); try await sync()
    }
    static func renameRequest(_ cipher: Object, userID: String, key: Data, name: String) throws -> Object {
        var body: Object = ["type": 5, "encryptedFor": userID, "name": try Crypto.encrypt(Data(name.utf8), key: key),
            "lastKnownRevisionDate": cipher.field("revisionDate") ?? NSNull()]
        for field in ["organizationId", "folderId", "favorite", "reprompt", "key", "notes", "fields", "passwordHistory", "archivedDate"] {
            body[field] = cipher.field(field) ?? NSNull()
        }
        body["favorite"] = cipher.field("favorite") ?? false; body["reprompt"] = cipher.field("reprompt") ?? 0
        let ssh = cipher.object("sshKey")
        body["sshKey"] = ["privateKey": ssh.field("privateKey") ?? NSNull(), "publicKey": ssh.field("publicKey") ?? NSNull(), "keyFingerprint": ssh.field("keyFingerprint") ?? NSNull()]
        var attachments: Object = [:]
        for attachment in cipher.objects("attachments") {
            if let id = attachment.text("id") { attachments[id] = ["fileName": attachment.field("fileName") ?? NSNull(), "key": attachment.field("key") ?? NSNull()] }
        }
        if !attachments.isEmpty { body["attachments2"] = attachments }
        return body
    }
    public func trash(_ id: String) async throws {
        guard unlocked, var account else { throw BwError("Unlock first") }; let generation = epoch
        account = try await api.refreshed(account); guard generation == epoch else { throw CancellationError() }
        self.account = account; try store.save(account, name: "account")
        try await api.mutate(account, method: "PUT", path: "/ciphers/\(id)/delete", body: nil); try await sync()
    }
}
