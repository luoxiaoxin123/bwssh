import AppKit
import SwiftUI
import Combine
import UserNotifications
import ServiceManagement
import BwCore

@MainActor final class AppHost: NSObject, NSApplicationDelegate, NSWindowDelegate, UNUserNotificationCenterDelegate {
    let vault: Vault
    let agent: Agent
    private var server: SocketServer?
    private var statusItem: NSStatusItem?
    private var window: NSWindow?
    private var approvalPanel: NSPanel?
    private var observations = Set<AnyCancellable>()
    private var timer: Timer?
    private var workspaceObservers: [NSObjectProtocol] = []
    private var screenObserver: NSObjectProtocol?
    private var lastUnlock = Date()
    private var wasUnlocked = false
    init(vault: Vault, agent: Agent) { self.vault = vault; self.agent = agent }
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        let menu = NSMenu(); let appMenu = NSMenuItem(); let submenu = NSMenu()
        submenu.addItem(withTitle: tr("关于 bwssh", "About bwssh"), action: #selector(about), keyEquivalent: "")
        submenu.addItem(.separator()); submenu.addItem(withTitle: tr("退出 bwssh", "Quit bwssh"), action: #selector(quit), keyEquivalent: "q")
        appMenu.submenu = submenu; menu.addItem(appMenu); NSApp.mainMenu = menu
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        vault.$unlocked.combineLatest(vault.$identities).sink { [weak self] _, _ in
            DispatchQueue.main.async { self?.rebuildMenu() }
        }.store(in: &observations)
        agent.onPrompt = { [weak self] request in self?.showApproval(); self?.notify(request) }
        agent.onDismiss = { [weak self] id in
            UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [id.uuidString])
            UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [id.uuidString])
            if self?.agent.pending.isEmpty == true { self?.approvalPanel?.orderOut(nil) }
        }
        configureNotifications()
        do { let server = SocketServer(agent: agent); try server.start(); self.server = server; agent.status = tr("Agent 正在监听", "Agent listening") }
        catch { agent.status = error.localizedDescription; showWindow() }
        let center = NSWorkspace.shared.notificationCenter
        workspaceObservers.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in if self?.vault.settings.lockOnSleep == true { self?.vault.lock() } }
        })
        workspaceObservers.append(center.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in if self?.vault.settings.lockOnScreenLock == true { self?.vault.lock() } }
        })
        screenObserver = DistributedNotificationCenter.default().addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in if self?.vault.settings.lockOnScreenLock == true { self?.vault.lock() } }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in Task { @MainActor in self?.tick() } }
        rebuildMenu()
        if !CommandLine.arguments.contains("--background") { showWindow() }
    }
    private func configureNotifications() {
        guard Bundle.main.bundleIdentifier == "com.bwssh.macos" else { return }
        let center = UNUserNotificationCenter.current(); center.delegate = self
        let approve = UNNotificationAction(identifier: "approve", title: tr("批准", "Approve"), options: [.authenticationRequired])
        let grant = UNNotificationAction(identifier: "grant", title: tr("限时放行", "Allow temporarily"), options: [.authenticationRequired])
        let unlock = UNNotificationAction(identifier: "unlock", title: tr("解锁并批准", "Unlock and approve"), options: [.foreground, .authenticationRequired])
        let deny = UNNotificationAction(identifier: "deny", title: tr("拒绝", "Deny"), options: [.destructive])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: "approval", actions: [approve, grant, deny], intentIdentifiers: []),
            UNNotificationCategory(identifier: "locked", actions: [unlock, deny], intentIdentifiers: [])
        ])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }
    private func notify(_ request: PendingApproval) {
        guard Bundle.main.bundleIdentifier == "com.bwssh.macos" else { return }
        let content = UNMutableNotificationContent()
        content.title = "bwssh · " + (request.context?.operation ?? tr("解锁密码库", "Unlock vault"))
        content.body = [request.identity?.name, request.process, request.destination, request.context?.host].compactMap { $0 }.joined(separator: "\n")
        content.categoryIdentifier = vault.unlocked ? "approval" : "locked"
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: request.id.uuidString, content: content, trigger: nil))
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) { completionHandler([.banner, .sound]) }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        Task { @MainActor in
            defer { completionHandler() }
            guard let id = UUID(uuidString: response.notification.request.identifier), agent.pending.contains(where: { $0.id == id }) else { return }
            switch response.actionIdentifier {
            case "deny": agent.resolve(id, choice: .deny)
            case "approve" where vault.unlocked: agent.resolve(id, choice: .approve)
            case "grant" where vault.unlocked: agent.resolve(id, choice: .grant)
            case "unlock" where vault.settings.touchIDEnabled:
                do { try await vault.unlockTouchID(); agent.resolve(id, choice: .approve) }
                catch { vault.message = error.localizedDescription; showApproval() }
            default: showApproval(); NSApp.activate(ignoringOtherApps: true)
            }
        }
    }
    private func tick() {
        if vault.unlocked && !wasUnlocked { lastUnlock = Date() }; wasUnlocked = vault.unlocked
        if vault.unlocked, vault.settings.idleMinutes > 0 {
            let threshold = Double(vault.settings.idleMinutes * 60)
            if Date().timeIntervalSince(lastUnlock) >= threshold,
               CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: .null) >= threshold { vault.lock() }
        }
        if !vault.busy, vault.settings.syncMinutes > 0, let account = vault.account,
           Date().timeIntervalSince(account.syncedAt) >= Double(vault.settings.syncMinutes * 60) {
            // Back off after network errors instead of retrying every tick.
            if Date().timeIntervalSince(lastSyncAttempt) >= 60 { lastSyncAttempt = Date(); vault.perform { try await self.vault.sync() } }
        }
    }
    private var lastSyncAttempt = Date.distantPast
    private func rebuildMenu() {
        let icon = vault.unlocked ? "key.fill" : "lock.fill"
        statusItem?.button?.image = NSImage(systemSymbolName: icon, accessibilityDescription: "bwssh")
        let menu = NSMenu(); let state = vault.unlocked ? tr("已解锁", "Unlocked") : tr("已锁定", "Locked")
        menu.addItem(withTitle: "bwssh · \(state) · \(vault.identities.count)", action: nil, keyEquivalent: "")
        menu.addItem(.separator())
        let items: [(String, Selector)] = [(tr("打开 bwssh…", "Open bwssh…"), #selector(showWindow)), (tr("锁定密码库", "Lock vault"), #selector(lockVault)),
            (tr("同步", "Sync"), #selector(syncVault)), (tr("撤销所有临时授权", "Revoke all grants"), #selector(revoke)), (tr("退出", "Quit"), #selector(quit))]
        for (title, action) in items { let item = menu.addItem(withTitle: title, action: action, keyEquivalent: ""); item.target = self }
        statusItem?.menu = menu
    }
    @objc func showWindow() {
        if window == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 940, height: 650), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            window.title = "bwssh"; window.minSize = NSSize(width: 760, height: 540); window.isReleasedWhenClosed = false
            window.contentView = NSHostingView(rootView: MainView(vault: vault, agent: agent)); window.delegate = self; window.center(); self.window = window
        }
        window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    private func showApproval() {
        if approvalPanel == nil {
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 480, height: 520), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            panel.title = tr("bwssh · 密钥使用审批", "bwssh · Key approval"); panel.isReleasedWhenClosed = false
            panel.level = .floating; panel.hidesOnDeactivate = false; panel.delegate = self
            panel.contentView = NSHostingView(rootView: ApprovalsView(vault: vault, agent: agent)); panel.center(); approvalPanel = panel
        }
        approvalPanel?.orderFrontRegardless()
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil); if sender === approvalPanel { agent.cancelAll() }; return false
    }
    @objc private func lockVault() { vault.lock() }
    @objc private func syncVault() { vault.perform { try await self.vault.sync() } }
    @objc private func revoke() { agent.revokeAll() }
    @objc private func about() { NSApp.orderFrontStandardAboutPanel(options: [.applicationName: "bwssh", .applicationVersion: "1.0.0", .credits: NSAttributedString(string: tr("原生 macOS Bitwarden SSH agent", "Native macOS Bitwarden SSH agent"))]) }
    @objc private func quit() { vault.lock(); server?.stop(); NSApp.terminate(nil) }
    func applicationWillTerminate(_ notification: Notification) { vault.lock(); server?.stop(); timer?.invalidate() }
}
