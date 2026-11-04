import AppKit
import BwCore

if CommandLine.arguments.contains("--version") {
    print("bwssh 1.0.0 (native macOS)")
} else if CommandLine.arguments.contains("--ensure-agent") {
    if SocketServer.isRunning() { exit(0) }
    let bundle = Bundle.main.bundleURL
    guard bundle.pathExtension == "app" else { fputs("Install bwssh.app before using on-demand launch.\n", stderr); exit(1) }
    let opener = Process(); opener.executableURL = URL(fileURLWithPath: "/usr/bin/open"); opener.arguments = ["-g", bundle.path, "--args", "--background"]
    do { try opener.run(); opener.waitUntilExit() } catch { fputs("Cannot start bwssh.\n", stderr); exit(1) }
    for _ in 0..<200 { if SocketServer.isRunning() { exit(0) }; Thread.sleep(forTimeInterval: 0.05) }
    fputs("bwssh agent did not become ready within 10 seconds.\n", stderr); exit(1)
} else {
    let app = NSApplication.shared
    if let id = Bundle.main.bundleIdentifier, NSRunningApplication.runningApplications(withBundleIdentifier: id).contains(where: { $0.processIdentifier != getpid() }) {
        NSRunningApplication.runningApplications(withBundleIdentifier: id).first(where: { $0.processIdentifier != getpid() })?.activate(options: [.activateIgnoringOtherApps]); exit(0)
    }
    MainActor.assumeIsolated { do {
        let vault = try Vault(); let agent = try Agent(vault: vault); let host = AppHost(vault: vault, agent: agent)
        app.delegate = host
        withExtendedLifetime(host) { app.run() }
    } catch {
        let alert = NSAlert(); alert.messageText = "bwssh"; alert.informativeText = error.localizedDescription; alert.alertStyle = .critical; alert.runModal(); exit(1)
    } }
}
