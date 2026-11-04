#if DEBUG
import AppKit
import BwCore

// An isolated fixture for exercising the real --ensure-agent / LaunchServices path.
// These keys and paths are never used by a release build.
var smokeSocket: String? {
    guard let path = Bundle.main.object(forInfoDictionaryKey: "BWSSHSmokeSocket") as? String,
          path.hasPrefix("/tmp/bwssh-smoke-"), path.hasSuffix("/agent.sock") else { return nil }
    return path
}

@MainActor func runSmokeAgent(path: String) throws {
    let root = URL(fileURLWithPath: path).deletingLastPathComponent()
    let store = try LocalStore(root: root.appendingPathComponent("data"), encryptionKey: Crypto.random(32))
    let vault = try Vault(store: store, settings: Settings(), transient: true)
    let agent = try Agent(vault: vault, store: store)
    let server = SocketServer(path: path, agent: agent)
    try server.start()
    try String(getpid()).write(to: root.appendingPathComponent("pid"), atomically: true, encoding: .utf8)
    let app = NSApplication.shared; app.setActivationPolicy(.prohibited)
    DispatchQueue.main.asyncAfter(deadline: .now() + 30) { server.stop(); app.terminate(nil) }
    withExtendedLifetime(server) { app.run() }
}
#endif
