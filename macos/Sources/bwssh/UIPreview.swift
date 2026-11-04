#if DEBUG
import Foundation
import BwCore

/// Synthetic UI fixtures. Never loads the user's Keychain, account, socket or audit history.
@MainActor func previewVault() async throws -> (Vault, Agent, URL) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("bwssh-preview-" + UUID().uuidString)
    let store = try LocalStore(root: directory, encryptionKey: Crypto.random(32))
    let state = ProcessInfo.processInfo.environment["BWSSH_UI_PREVIEW_STATE"] ?? "unlocked"
    if state == "login" {
        let vault = try Vault(store: store, settings: Settings(), transient: true)
        return (vault, try Agent(vault: vault, store: store), directory)
    }
    let user = try Crypto.random(64), kdf = KDF(iterations: 5000)
    let master = try kdf.derive(password: "preview", salt: "preview@example.com")
    var ciphers: [[String: Any]] = []
    for name in ["GitHub", "Development server", "Production · Tokyo", "Backup server", "Personal projects"] {
        let key = try SSHKey.generate()
        ciphers.append(["id": UUID().uuidString, "type": 5, "name": try Crypto.encrypt(Data(name.utf8), key: user),
            "sshKey": ["privateKey": try Crypto.encrypt(Data(key.exportOpenSSH().utf8), key: user)]])
    }
    let root: [String: Any] = ["profile": [:], "ciphers": ciphers]
    let account = Account(server: try Server(), email: "preview@example.com", salt: "preview@example.com", kdf: kdf, accessToken: "", expires: Date(), encryptedUserKey: try Crypto.encrypt(user, key: Crypto.stretch(master)), userID: "preview", snapshot: try JSONSerialization.data(withJSONObject: root), syncedAt: Date())
    try store.save(account, name: "account")
    let vault = try Vault(store: store, settings: Settings(), transient: true)
    try await vault.unlock(password: "preview")
    if state == "locked" { vault.lock() }
    let agent = try Agent(vault: vault, store: store); agent.status = tr("Agent 正在监听", "Agent listening")
    return (vault, agent, directory)
}
#endif
