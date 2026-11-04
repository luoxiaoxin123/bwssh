import AppKit
import BwCore

if CommandLine.arguments.contains("--version") {
    print("bwssh \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0.1") (native macOS)")
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
    #if DEBUG
    if CommandLine.arguments.contains("--ui-preview") || ProcessInfo.processInfo.environment["BWSSH_UI_PREVIEW"] == "1" {
        _ = MainActor.assumeIsolated {
            Task { @MainActor in
                do {
                    let (vault, agent, directory) = try await previewVault()
                    let host = AppHost(vault: vault, agent: agent)
                    app.delegate = host; host.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
                    // The application delegate is weak. Retain the preview host until process exit.
                    previewHost = host; previewDirectory = directory
                } catch { fputs("UI preview failed: \(error)\n", stderr); app.terminate(nil) }
            }
        }
        app.run()
        exit(0)
    }
    #endif
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

#if DEBUG
private var previewHost: AppHost?
private var previewDirectory: URL?
#endif
