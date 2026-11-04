import Foundation
import Security
import CryptoKit
import LocalAuthentication

public enum Paths {
    public static var root: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/bwssh", isDirectory: true) }
    public static var socket: String { root.appendingPathComponent("agent.sock").path }
    public static func prepare(_ directory: URL = root) throws {
        var info = stat()
        if lstat(directory.path, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == getuid() else { throw BwError("Unsafe bwssh directory") }
        } else {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        guard chmod(directory.path, 0o700) == 0 else { throw BwError("Cannot protect bwssh directory") }
    }
    public static func write(_ data: Data, to url: URL) throws {
        try prepare(url.deletingLastPathComponent())
        try data.write(to: url, options: .atomic)
        guard chmod(url.path, 0o600) == 0 else { throw BwError("Cannot protect local file") }
    }
}

public enum Keychain {
    private static func query(_ name: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.bwssh.macos", kSecAttrAccount as String: name]
    }
    public static func put(_ data: Data, name: String, biometric: Bool = false) throws {
        var q = query(name); var attrs: [String: Any] = [kSecValueData as String: data]
        if biometric {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error) else {
                throw error?.takeRetainedValue() as Error? ?? BwError("Touch ID is unavailable")
            }
            attrs[kSecAttrAccessControl as String] = access
        } else { attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }
        let status = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound { q.merge(attrs) { _, new in new }; try check(SecItemAdd(q as CFDictionary, nil)) }
        else { try check(status) }
    }
    public static func get(_ name: String, context: LAContext? = nil) throws -> Data? {
        var q = query(name); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { q[kSecUseAuthenticationContext as String] = context }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }; try check(status); return result as? Data
    }
    public static func delete(_ name: String) throws {
        let status = SecItemDelete(query(name) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }
    public static func exists(_ name: String) -> Bool {
        var q = query(name); let context = LAContext(); context.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = context
        let result = SecItemCopyMatching(q as CFDictionary, nil)
        return result == errSecSuccess || result == errSecInteractionNotAllowed
    }
    private static func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw BwError((SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)") }
    }
}

/// All persisted account, tokens, public-key metadata and snapshots are encrypted with a Keychain-held key.
public final class LocalStore {
    private let key: SymmetricKey
    private let root: URL
    public init(root: URL = Paths.root, encryptionKey: Data? = nil) throws {
        self.root = root
        let raw: Data
        if let encryptionKey { raw = encryptionKey }
        else if let saved = try Keychain.get("storage-key") { raw = saved }
        else { raw = try Crypto.random(32); try Keychain.put(raw, name: "storage-key") }
        key = SymmetricKey(data: raw)
    }
    public func save<T: Encodable>(_ value: T, name: String) throws {
        var data = try JSONEncoder().encode(value); defer { data.wipe() }
        let sealed = try AES.GCM.seal(data, using: key, authenticating: Data(name.utf8))
        try Paths.write(sealed.combined!, to: root.appendingPathComponent(name + ".sealed"))
    }
    public func load<T: Decodable>(_ type: T.Type, name: String) throws -> T? {
        let url = root.appendingPathComponent(name + ".sealed")
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        var data = try AES.GCM.open(AES.GCM.SealedBox(combined: Data(contentsOf: url)), using: key, authenticating: Data(name.utf8))
        defer { data.wipe() }; return try JSONDecoder().decode(type, from: data)
    }
    public func delete(_ name: String) throws {
        let url = root.appendingPathComponent(name + ".sealed")
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }
}

public struct Settings: Codable, Equatable {
    public var promptMode = "always"
    public var grantMinutes = 15
    public var approvalTimeout = 60
    public var idleMinutes = 15
    public var lockOnSleep = true
    public var lockOnScreenLock = true
    public var syncMinutes = 30
    public var pinEnabled = false
    // Optional backing storage keeps existing settings files compatible; missing means enabled.
    private var pinRequirePrimaryAfterRestart: Bool?
    public var pinRequiresPrimaryUnlockAfterRestart: Bool {
        get { pinRequirePrimaryAfterRestart ?? true }
        set { pinRequirePrimaryAfterRestart = newValue }
    }
    public var touchIDEnabled = false
    public init() {}
    public static func load() -> Settings {
        (try? JSONDecoder().decode(Settings.self, from: Data(contentsOf: Paths.root.appendingPathComponent("settings.json")))) ?? Settings()
    }
    public mutating func save() throws {
        if !["always", "remember", "never"].contains(promptMode) { promptMode = "always" }
        grantMinutes = min(max(grantMinutes, 1), 1440); approvalTimeout = min(max(approvalTimeout, 15), 300)
        idleMinutes = min(max(idleMinutes, 0), 1440); syncMinutes = min(max(syncMinutes, 0), 1440)
        try Paths.write(JSONEncoder().encode(self), to: Paths.root.appendingPathComponent("settings.json"))
    }
}
