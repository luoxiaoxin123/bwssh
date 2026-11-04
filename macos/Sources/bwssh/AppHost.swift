import AppKit
import SwiftUI
import Combine
import UserNotifications
import ServiceManagement
import BwCore

@MainActor final class AppHost: NSObject, NSApplicationDelegate, NSWindowDelegate, UNUserNotificationCenterDelegate, NSToolbarDelegate, NSToolbarItemValidation, NSSearchFieldDelegate {
    let vault: Vault
    let agent: Agent
    private var server: SocketServer?
    private var statusItem: NSStatusItem?
    private var window: NSWindow?
    private var approvalPanel: NSPanel?
    private var settingsWindow: NSWindow?
    private var mainToolbar: NSToolbar?
    private var toolbarPage = "keys"
    private var searchItem: NSSearchToolbarItem?
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
        submenu.addItem(.separator())
        let settingsItem = submenu.addItem(withTitle: tr("设置…", "Settings…"), action: #selector(showSettings), keyEquivalent: ",")
        settingsItem.target = self
        submenu.addItem(.separator())
        submenu.addItem(withTitle: tr("隐藏 bwssh", "Hide bwssh"), action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        submenu.addItem(withTitle: tr("显示全部", "Show All"), action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        submenu.addItem(.separator()); submenu.addItem(withTitle: tr("退出 bwssh", "Quit bwssh"), action: #selector(quit), keyEquivalent: "q")
        appMenu.submenu = submenu; menu.addItem(appMenu); NSApp.mainMenu = menu
        NotificationCenter.default.publisher(for: .bwsshOpenSettings).sink { [weak self] _ in self?.showSettings() }.store(in: &observations)
        NotificationCenter.default.publisher(for: .bwsshPageChanged).sink { [weak self] note in
            guard let page = note.object as? String else { return }; self?.configureToolbar(page: page)
        }.store(in: &observations)
        vault.$busy.sink { [weak self] _ in DispatchQueue.main.async { self?.mainToolbar?.validateVisibleItems() } }.store(in: &observations)
        let file = NSMenuItem(title: tr("文件", "File"), action: nil, keyEquivalent: "")
        let fileMenu = NSMenu(title: file.title)
        for (title, action, key) in [(tr("添加密钥…", "Add key…"), #selector(addKey), "n"), (tr("同步密码库", "Sync vault"), #selector(syncVault), "r"), (tr("搜索", "Find"), #selector(focusSearch), "f")] {
            let command = fileMenu.addItem(withTitle: title, action: action, keyEquivalent: key); command.target = self
        }
        fileMenu.addItem(.separator())
        fileMenu.addItem(withTitle: tr("关闭窗口", "Close Window"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        file.submenu = fileMenu; menu.addItem(file)
        let edit = NSMenuItem(title: tr("编辑", "Edit"), action: nil, keyEquivalent: "")
        let editMenu = NSMenu(title: edit.title)
        editMenu.addItem(withTitle: tr("剪切", "Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: tr("复制", "Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: tr("粘贴", "Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: tr("全选", "Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        edit.submenu = editMenu; menu.addItem(edit)
        #if DEBUG
        if CommandLine.arguments.contains("--ui-preview") || ProcessInfo.processInfo.environment["BWSSH_UI_PREVIEW"] == "1" {
            let item = NSMenuItem(title: "Preview", action: nil, keyEquivalent: "")
            let preview = NSMenu(title: "Preview")
            for (title, selector) in [("Light appearance", #selector(previewLight)), ("Dark appearance", #selector(previewDark)), ("Compact window", #selector(previewCompact))] {
                let command = preview.addItem(withTitle: title, action: selector, keyEquivalent: ""); command.target = self
            }
            item.submenu = preview; menu.addItem(item)
            showWindow(); return
        }
        #endif
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
            (tr("同步", "Sync"), #selector(syncVault)), (tr("撤销所有临时授权", "Revoke all grants"), #selector(revoke)), (tr("设置…", "Settings…"), #selector(showSettings)), (tr("退出", "Quit"), #selector(quit))]
        for (title, action) in items { let item = menu.addItem(withTitle: title, action: action, keyEquivalent: ""); item.target = self }
        statusItem?.menu = menu
        mainToolbar?.validateVisibleItems()
    }
    @objc func showWindow() {
        if window == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 660), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            window.title = "bwssh"; window.minSize = NSSize(width: 800, height: 520); window.isReleasedWhenClosed = false
            window.toolbarStyle = .unified; window.titlebarAppearsTransparent = true; window.tabbingMode = .disallowed
            self.window = window; window.title = tr("SSH 密钥", "SSH keys")
            let toolbar = NSToolbar(identifier: "bwssh.main")
            toolbar.delegate = self; toolbar.displayMode = .iconOnly; toolbar.allowsUserCustomization = false
            window.toolbar = toolbar; mainToolbar = toolbar
            let canvas = NSView(); window.contentView = canvas
            let content = NSHostingView(rootView: MainView(vault: vault, agent: agent))
            content.sizingOptions = []; content.translatesAutoresizingMaskIntoConstraints = false; canvas.addSubview(content)
            let layout = window.contentLayoutGuide as! NSLayoutGuide
            NSLayoutConstraint.activate([
                content.leadingAnchor.constraint(equalTo: canvas.leadingAnchor), content.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
                content.topAnchor.constraint(equalTo: layout.topAnchor), content.bottomAnchor.constraint(equalTo: canvas.bottomAnchor)
            ])
            window.delegate = self; window.center(); self.window = window
        }
        window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    private func identifiers(for page: String) -> [NSToolbarItem.Identifier] {
        if page == "login" { return [] }
        let common: [NSToolbarItem.Identifier] = [NSToolbarItem.Identifier("sidebar"), .flexibleSpace]
        if page == "keys" { return common + ["sync", "lock", "add", "search"].map { NSToolbarItem.Identifier($0) } }
        if page == "audit" { return common + ["clear", "search"].map { NSToolbarItem.Identifier($0) } }
        return common
    }
    private func configureToolbar(page: String) {
        guard toolbarPage != page || mainToolbar?.items.isEmpty == true else { return }
        toolbarPage = page
        switch page {
        case "keys": window?.title = tr("SSH 密钥", "SSH keys")
        case "audit": window?.title = tr("审计日志", "Audit log")
        case "diagnostics": window?.title = tr("连接与诊断", "Connections")
        default: window?.title = "bwssh"
        }
        guard let mainToolbar else { return }
        while !mainToolbar.items.isEmpty { mainToolbar.removeItem(at: 0) }
        for (index, id) in identifiers(for: page).enumerated() { mainToolbar.insertItem(withItemIdentifier: id, at: index) }
        searchItem?.searchField.stringValue = ""
        NotificationCenter.default.post(name: .bwsshSearch, object: "")
    }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.flexibleSpace] + ["sidebar", "sync", "lock", "add", "search", "clear"].map { NSToolbarItem.Identifier($0) }
    }
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { identifiers(for: toolbarPage) }
    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier id: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        if id.rawValue == "search" {
            let item = NSSearchToolbarItem(itemIdentifier: id); item.searchField.delegate = self
            item.searchField.placeholderString = toolbarPage == "audit" ? tr("搜索使用记录", "Search activity") : tr("搜索密钥", "Search keys")
            item.searchField.setAccessibilityLabel(item.searchField.placeholderString)
            item.searchField.sendsSearchStringImmediately = true; item.preferredWidthForSearchField = 210
            searchItem = item; return item
        }
        let item = NSToolbarItem(itemIdentifier: id)
        let title: String, symbol: String, action: Selector
        switch id.rawValue {
        case "sidebar": title = tr("显示或隐藏侧边栏", "Toggle sidebar"); symbol = "sidebar.left"; action = #selector(toggleSidebar)
        case "sync": title = tr("同步密码库", "Sync vault"); symbol = "arrow.clockwise"; action = #selector(syncVault)
        case "lock": title = tr("锁定密码库", "Lock vault"); symbol = "lock"; action = #selector(lockVault)
        case "add": title = tr("添加密钥", "Add key"); symbol = "plus"; action = #selector(addKey)
        case "clear": title = tr("清空审计日志", "Clear history"); symbol = "trash"; action = #selector(clearAudit)
        default: return nil
        }
        item.label = title; item.paletteLabel = title; item.toolTip = title
        item.isNavigational = id.rawValue == "sidebar"
        item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: title); item.target = self; item.action = action
        return item
    }
    func validateToolbarItem(_ item: NSToolbarItem) -> Bool {
        switch item.itemIdentifier.rawValue {
        case "sync": return vault.account != nil && !vault.busy
        case "lock": return vault.unlocked
        case "add": return vault.unlocked && !vault.busy
        case "clear": return !agent.audit.isEmpty
        default: return true
        }
    }
    func controlTextDidChange(_ notification: Notification) {
        guard let field = notification.object as? NSSearchField else { return }
        NotificationCenter.default.post(name: .bwsshSearch, object: field.stringValue)
    }
    @objc private func toggleSidebar() { NotificationCenter.default.post(name: .bwsshToggleSidebar, object: nil) }
    @objc private func addKey() { guard toolbarPage == "keys" else { return }; NotificationCenter.default.post(name: .bwsshAddKey, object: nil) }
    @objc private func clearAudit() { NotificationCenter.default.post(name: .bwsshClearAudit, object: nil) }
    @objc private func focusSearch() { window?.makeKeyAndOrderFront(nil); if let search = searchItem?.searchField { window?.makeFirstResponder(search) } }
    @objc func showSettings() {
        if settingsWindow == nil {
            let settings = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 680), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            settings.title = tr("bwssh 设置", "bwssh Settings"); settings.minSize = NSSize(width: 560, height: 480)
            settings.isReleasedWhenClosed = false; settings.tabbingMode = .disallowed
            settings.contentView = NSHostingView(rootView: SettingsView(vault: vault)); settings.delegate = self; settings.center(); settingsWindow = settings
        }
        settingsWindow?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
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
    #if DEBUG
    @objc private func previewLight() { NSApp.appearance = NSAppearance(named: .aqua) }
    @objc private func previewDark() { NSApp.appearance = NSAppearance(named: .darkAqua) }
    @objc private func previewCompact() { window?.setContentSize(NSSize(width: 800, height: 520)) }
    #endif
    @objc private func syncVault() { vault.perform { try await self.vault.sync() } }
    @objc private func revoke() { agent.revokeAll() }
    @objc private func about() { NSApp.orderFrontStandardAboutPanel(options: [.applicationName: "bwssh", .applicationVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0.1", .credits: NSAttributedString(string: tr("原生 macOS Bitwarden SSH agent", "Native macOS Bitwarden SSH agent"))]) }
    @objc private func quit() { vault.lock(); server?.stop(); NSApp.terminate(nil) }
    func applicationWillTerminate(_ notification: Notification) { vault.lock(); server?.stop(); timer?.invalidate() }
}
