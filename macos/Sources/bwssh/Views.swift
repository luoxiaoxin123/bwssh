import SwiftUI
import AppKit
import ServiceManagement
import LocalAuthentication
import BwCore

extension Notification.Name {
    static let bwsshOpenSettings = Notification.Name("bwssh.openSettings")
    static let bwsshPageChanged = Notification.Name("bwssh.pageChanged")
    static let bwsshSearch = Notification.Name("bwssh.search")
    static let bwsshAddKey = Notification.Name("bwssh.addKey")
    static let bwsshClearAudit = Notification.Name("bwssh.clearAudit")
    static let bwsshToggleSidebar = Notification.Name("bwssh.toggleSidebar")
}

struct InlineMessage: View {
    let text: String
    var dismiss: () -> Void
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
            Text(text).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            Button(action: dismiss) { Image(systemName: "xmark") }.buttonStyle(.plain)
                .help(tr("关闭提示", "Dismiss message")).accessibilityLabel(tr("关闭提示", "Dismiss message"))
        }.padding(12).background(Color(nsColor: .controlBackgroundColor))
        Divider()
    }
}

struct MainView: View {
    @ObservedObject var vault: Vault
    @ObservedObject var agent: Agent
    @State private var selection: String? = "keys"
    @State private var visibility = NavigationSplitViewVisibility.all
    private var title: String {
        switch selection {
        case "audit": return tr("审计日志", "Audit log")
        case "diagnostics": return tr("连接与诊断", "Connections")
        default: return tr("SSH 密钥", "SSH keys")
        }
    }
    private var page: String {
        switch vault.screen { case .login: return "login"; case .unlock: return "unlock"; case .main: return selection ?? "keys" }
    }
    var body: some View {
        GeometryReader { geometry in
          Group {
            if vault.account == nil {
                VStack(spacing: 0) {
                    if !vault.message.isEmpty { InlineMessage(text: vault.message) { vault.message = "" } }
                    LoginView(vault: vault)
                }.navigationTitle("bwssh")
            } else if !vault.unlocked {
                LockedLoginPage(vault: vault)
            } else {
                NavigationSplitView(columnVisibility: $visibility) {
                    List(selection: $selection) {
                        Section(tr("密码库", "Vault")) {
                            Label(tr("SSH 密钥", "SSH keys"), systemImage: "key.horizontal").badge(vault.identities.count).tag("keys")
                            Label(tr("审计日志", "Audit log"), systemImage: "clock.arrow.circlepath").tag("audit")
                        }
                        Section(tr("工具", "Tools")) {
                            Label(tr("连接与诊断", "Connections"), systemImage: "network").tag("diagnostics")
                        }
                    }.listStyle(.sidebar)
                    .safeAreaInset(edge: .bottom, spacing: 0) {
                        VStack(alignment: .leading, spacing: 10) {
                            Divider()
                            HStack(spacing: 8) {
                                Image(systemName: vault.unlocked ? "lock.open" : "lock")
                                    .foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(vault.unlocked ? tr("密码库已解锁", "Vault unlocked") : tr("密码库已锁定", "Vault locked")).font(.callout)
                                    Text(vault.account?.email ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                }
                                Spacer(minLength: 0)
                                Button { NotificationCenter.default.post(name: .bwsshOpenSettings, object: nil) } label: { Image(systemName: "gearshape") }
                                    .buttonStyle(.plain).help(tr("设置…", "Settings…")).accessibilityLabel(tr("设置", "Settings"))
                            }.padding(.bottom, 12)
                        }.padding(.horizontal, 14)
                    }
                    .navigationTitle("bwssh")
                    .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 270)
                } detail: {
                    VStack(spacing: 0) {
                        if !vault.message.isEmpty { InlineMessage(text: vault.message) { vault.message = "" } }
                        switch selection {
                        case "audit": AuditView(agent: agent)
                        case "diagnostics": DiagnosticsView(vault: vault, agent: agent)
                        default: KeysView(vault: vault, agent: agent)
                        }
                    }.navigationTitle(title)
                }
            }
          }.frame(width: geometry.size.width, height: geometry.size.height)
        }
        .frame(minWidth: 740, minHeight: 480)
        .onAppear { NotificationCenter.default.post(name: .bwsshPageChanged, object: page) }
        .onChange(of: page) { page in NotificationCenter.default.post(name: .bwsshPageChanged, object: page) }
        .onReceive(NotificationCenter.default.publisher(for: .bwsshToggleSidebar)) { _ in visibility = visibility == .detailOnly ? .all : .detailOnly }
    }
}

struct LoginView: View {
    @ObservedObject var vault: Vault
    @State private var server = "https://bitwarden.com"
    @State private var custom = ""
    @State private var email = ""
    @State private var password = ""
    @State private var apiKey = false
    @State private var clientID = ""
    @State private var clientSecret = ""
    @State private var provider = 0
    @State private var code = ""
    @State private var otp = ""
    @State private var challenge: LoginChallenge?
    @State private var localMessage = ""
    init(vault: Vault, email: String = "", server: String = "https://bitwarden.com") {
        self.vault = vault
        _email = State(initialValue: email)
        _server = State(initialValue: ["https://bitwarden.com", "https://bitwarden.eu"].contains(server) ? server : "custom")
        _custom = State(initialValue: server)
    }
    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                VStack(spacing: 10) {
                    Image(systemName: "key.horizontal").font(.system(size: 42, weight: .light)).foregroundStyle(.tint)
                    Text(tr("登录 Bitwarden", "Sign in to Bitwarden")).font(.title2.weight(.semibold))
                    Text(tr("将密码库中的 SSH 密钥连接到此 Mac。", "Connect your vault’s SSH keys to this Mac.")).font(.callout).foregroundStyle(.secondary)
                }.padding(.top, 30)
                Form {
                    Section {
                        Picker(tr("服务器", "Server"), selection: $server) {
                            Text("bitwarden.com").tag("https://bitwarden.com"); Text("bitwarden.eu").tag("https://bitwarden.eu"); Text(tr("自托管", "Self-hosted")).tag("custom")
                        }
                        if server == "custom" { TextField(tr("服务器地址", "Server URL"), text: $custom, prompt: Text("https://vault.example.com")) }
                        TextField(tr("邮箱", "Email"), text: $email, prompt: Text("you@example.com"))
                        RevealPasswordField(tr("主密码", "Master password"), text: $password).onSubmit(login)
                    }
                    Section {
                        Toggle(tr("使用 API Key 登录", "Sign in with API key"), isOn: $apiKey)
                        if apiKey { TextField("Client ID", text: $clientID); RevealPasswordField("Client secret", text: $clientSecret) }
                    } footer: {
                        if apiKey { Text(tr("主密码仅用于在此 Mac 上解密密码库。", "Your master password decrypts the vault on this Mac.")) }
                    }
                    if let challenge {
                        Section(tr("验证身份", "Verify your identity")) {
                            if challenge.newDevice { TextField(tr("设备验证码", "Device code"), text: $otp) }
                            else {
                                Picker(tr("验证方式", "Method"), selection: $provider) {
                                    ForEach(challenge.providers.filter { [0, 1, 3].contains($0) }, id: \.self) { p in
                                        Text(p == 0 ? tr("验证器", "Authenticator") : p == 1 ? tr("邮件", "Email") : "YubiKey OTP").tag(p)
                                    }
                                }
                                TextField(tr("验证码", "Verification code"), text: $code)
                                if provider == 1 { Button(tr("发送邮件验证码", "Send email code")) { sendEmail() } }
                                if challenge.providers.allSatisfy({ ![0, 1, 3].contains($0) }) { Text(tr("该验证方式暂不支持。请使用 API Key。", "This method is unsupported. Use an API key.")).foregroundStyle(.orange) }
                            }
                        }
                    }
                }.formStyle(.grouped).scrollContentBackground(.hidden).textFieldStyle(.roundedBorder).fixedSize(horizontal: false, vertical: true)
                if !localMessage.isEmpty { Text(localMessage).font(.callout).foregroundStyle(.secondary).textSelection(.enabled) }
                HStack(spacing: 8) {
                    if vault.busy { ProgressView().controlSize(.small) }
                    Button(tr("登录并解锁", "Sign in and unlock"), action: login).buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                        .disabled(vault.busy || email.isEmpty || password.isEmpty)
                }
                Text(tr("主密码不会保存在此 Mac 上。", "Your master password isn’t saved on this Mac.")).font(.caption).foregroundStyle(.secondary)
            }.padding(.horizontal, 24).padding(.bottom, 32).frame(maxWidth: 500).frame(maxWidth: .infinity)
        }.background(Color(nsColor: .windowBackgroundColor))
    }
    private func login() {
        vault.perform {
            do {
                let env = try Server(server == "custom" ? custom : server)
                try await vault.login(server: env, email: email, password: password, provider: challenge == nil ? nil : provider, code: code, otp: otp, clientID: apiKey ? clientID : "", clientSecret: apiKey ? clientSecret : "")
                password = ""; clientSecret = ""; code = ""; otp = ""
            } catch let c as LoginChallenge { challenge = c; provider = c.providers.first(where: { [0, 1, 3].contains($0) }) ?? 0; localMessage = c.localizedDescription }
        }
    }
    private func sendEmail() {
        vault.perform {
            try await vault.api.sendEmailCode(server: Server(server == "custom" ? custom : server), email: email, password: password, challengeSession: challenge?.session)
            localMessage = tr("验证码已发送。", "Verification code sent.")
        }
    }
}

struct UnlockView: View {
    @ObservedObject var vault: Vault
    var onUnlocked: () -> Void = {}
    var standalone = false
    @State private var password = ""
    @State private var pinMode = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !standalone { Label(tr("密码库已锁定", "Vault locked"), systemImage: "lock.fill").font(.headline) }
            RevealPasswordField(pinMode ? "PIN" : tr("主密码", "Master password"), text: $password).textFieldStyle(.roundedBorder).onSubmit(unlock)
            HStack {
                Button(tr("解锁", "Unlock"), action: unlock).buttonStyle(.borderedProminent).disabled(vault.busy || password.isEmpty)
                if vault.settings.touchIDEnabled {
                    Button { vault.perform { try await vault.unlockTouchID(); onUnlocked() } } label: { Label("Touch ID", systemImage: "touchid") }.disabled(vault.busy)
                }
                if vault.settings.pinEnabled { Button(pinMode ? tr("使用主密码", "Use password") : tr("使用 PIN", "Use PIN")) { pinMode.toggle(); password = "" } }
            }
        }.padding(standalone ? 0 : 16).background(standalone ? Color.clear : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
    }
    private func unlock() {
        vault.perform {
            if pinMode { try await vault.unlockPIN(password) } else { try await vault.unlock(password: password) }
            password = ""; onUnlocked()
        }
    }
}

struct KeysView: View {
    @ObservedObject var vault: Vault
    @ObservedObject var agent: Agent
    @State private var adding = false
    @State private var renameID: String?
    @State private var renameName = ""
    @State private var deleting: PublicIdentity?
    @State private var selectedID: String?
    @State private var query = ""
    private var filtered: [PublicIdentity] {
        vault.identities.filter { query.isEmpty || $0.name.localizedCaseInsensitiveContains(query) || $0.type.localizedCaseInsensitiveContains(query) || $0.fingerprint.localizedCaseInsensitiveContains(query) }
    }
    private var selected: PublicIdentity? { vault.identities.first { $0.id == selectedID } }
    var body: some View {
        VStack(spacing: 0) {
            if vault.identities.isEmpty {
                EmptyContent(symbol: "key.horizontal", title: tr("尚无 SSH 密钥", "No SSH keys"), detail: tr("添加密钥，或同步 Bitwarden 密码库。", "Add a key or sync your Bitwarden vault.")) {
                    Button(tr("添加密钥…", "Add key…")) { adding = true }.disabled(!vault.unlocked || vault.busy)
                }
            } else {
                Table(filtered, selection: $selectedID) {
                    TableColumn(tr("名称", "Name")) { key in
                        Label(key.name, systemImage: "key.horizontal").lineLimit(1)
                            .contextMenu { keyMenu(key) }
                    }.width(min: 160, ideal: 250)
                    TableColumn(tr("算法", "Algorithm")) { key in Text(algorithm(key.type)).foregroundStyle(.secondary) }.width(min: 100, ideal: 120, max: 150)
                    TableColumn(tr("指纹", "Fingerprint")) { key in
                        Text(key.fingerprint).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }.width(min: 160, ideal: 240)
                }
                .frame(minHeight: 120, maxHeight: .infinity)
                .tableStyle(.inset(alternatesRowBackgrounds: false))
                .layoutPriority(-1)
                .contextMenu {
                    if let selected { keyMenu(selected) }
                }
                .overlay { if filtered.isEmpty { EmptyContent(symbol: "magnifyingglass", title: tr("没有匹配的密钥", "No matching keys"), detail: tr("尝试其他名称、算法或指纹。", "Try another name, algorithm or fingerprint.")) { EmptyView() }.allowsHitTesting(false) } }
                Divider()
                Group {
                    if let selected {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "key.horizontal").font(.title2).foregroundStyle(.secondary).frame(width: 30, height: 32)
                            VStack(alignment: .leading, spacing: 6) {
                                HStack { Text(selected.name).font(.headline); Text(algorithm(selected.type)).font(.caption).foregroundStyle(.secondary) }
                                Text(selected.fingerprint).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            Button(tr("复制公钥", "Copy public key")) { copy(selected) }.controlSize(.small)
                        }.padding(16)
                    } else {
                        Text(tr("选择一把密钥以查看详情", "Select a key to see its details")).font(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(16)
                    }
                }.frame(height: 88).background(Color(nsColor: .windowBackgroundColor))

            }
            if !agent.grants.isEmpty {
                Divider()
                DisclosureGroup(tr("临时授权", "Temporary grants") + " (\(agent.grants.count))") {
                    ForEach(agent.grants) { grant in
                        HStack { Text(grant.name).lineLimit(1); Spacer(); Text(grant.expires, style: .time).foregroundStyle(.secondary); Button(tr("撤销", "Revoke")) { agent.revoke(grant.id) } }.font(.caption).padding(.vertical, 3)
                    }
                }.padding(12)
            }
            if !vault.errors.isEmpty {
                DisclosureGroup(tr("部分密钥无法加载", "Some keys could not be loaded")) { Text(vault.errors.joined(separator: "\n")).font(.caption).foregroundStyle(.orange).textSelection(.enabled) }.padding(12)
            }
            Divider()
            HStack {
                Text(tr("\(filtered.count) 把密钥", "\(filtered.count) keys"))
                Spacer()
                if vault.busy { ProgressView().controlSize(.mini); Text(tr("处理中…", "Working…")) }
                else if let time = vault.account?.syncedAt { Text(tr("同步于 ", "Synced ") + time.formatted(date: .omitted, time: .shortened)) }
            }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 14).frame(height: 30)
                .background(Color(nsColor: .windowBackgroundColor))
        }
        .onReceive(NotificationCenter.default.publisher(for: .bwsshSearch)) { query = $0.object as? String ?? "" }
        .onReceive(NotificationCenter.default.publisher(for: .bwsshAddKey)) { _ in if vault.unlocked && !vault.busy { adding = true } }
        .onChange(of: vault.identities) { keys in if let selectedID, !keys.contains(where: { $0.id == selectedID }) { self.selectedID = nil } }
        .sheet(isPresented: $adding) { AddKeyView(vault: vault) }
        .alert(tr("重命名密钥", "Rename key"), isPresented: Binding(get: { renameID != nil }, set: { if !$0 { renameID = nil } })) {
            TextField(tr("名称", "Name"), text: $renameName)
            Button(tr("保存", "Save")) { if let id = renameID { vault.perform { try await vault.rename(id, name: renameName) } }; renameID = nil }
            Button(tr("取消", "Cancel"), role: .cancel) { renameID = nil }
        }
        .confirmationDialog(tr("将密钥移到 Bitwarden 回收站？", "Move this key to the Bitwarden trash?"), isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button(tr("移到回收站", "Move to trash"), role: .destructive) { if let id = deleting?.id { vault.perform { try await vault.trash(id) } }; deleting = nil }
        }
    }
    @ViewBuilder private func keyMenu(_ key: PublicIdentity) -> some View {
        Button(tr("复制公钥", "Copy public key")) { copy(key) }
        Divider()
        Button(tr("重命名…", "Rename…")) { renameID = key.id; renameName = key.name }.disabled(!vault.unlocked || vault.busy)
        Button(tr("移到回收站…", "Move to trash…"), role: .destructive) { deleting = key }.disabled(!vault.unlocked || vault.busy)
    }
    private func copy(_ key: PublicIdentity) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(key.publicLine, forType: .string) }
    private func algorithm(_ type: String) -> String {
        switch type {
        case "ssh-ed25519": return "Ed25519"
        case "ssh-rsa": return "RSA"
        default: return type.replacingOccurrences(of: "ecdsa-sha2-nistp", with: "ECDSA P-")
        }
    }
}

struct EmptyContent<Action: View>: View {
    let symbol: String
    let title: String
    let detail: String
    @ViewBuilder var action: () -> Action
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol).font(.system(size: 36, weight: .light)).foregroundStyle(.tertiary).padding(.bottom, 4)
            Text(title).font(.headline)
            Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            action().padding(.top, 6)
        }.padding(32).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct AddKeyView: View {
    @ObservedObject var vault: Vault
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var kind = "ed25519"
    @State private var pem = ""
    @State private var passphrase = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(tr("添加 SSH 密钥", "Add SSH key")).font(.title2.bold())
            TextField(tr("密钥名称", "Key name"), text: $name).textFieldStyle(.roundedBorder)
            Picker(tr("类型", "Type"), selection: $kind) { Text("Ed25519").tag("ed25519"); Text("RSA 3072").tag("rsa"); Text(tr("导入私钥", "Import private key")).tag("import") }
            if kind == "import" {
                TextEditor(text: $pem).font(.system(.caption, design: .monospaced)).frame(height: 180).border(.quaternary)
                HStack { Button(tr("选择私钥文件…", "Choose private key…"), action: choose); RevealPasswordField(tr("私钥密码（可选）", "Passphrase (optional)"), text: $passphrase) }
            }
            if !vault.message.isEmpty { Text(vault.message).foregroundStyle(.orange).font(.caption) }
            HStack {
                Spacer(); Button(tr("取消", "Cancel")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(tr("保存到密码库", "Save to vault")) {
                    vault.perform { try await vault.add(name: name, pem: pem, passphrase: passphrase, rsa: kind == "import" ? nil : kind == "rsa"); pem = ""; passphrase = ""; dismiss() }
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(vault.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (kind == "import" && pem.isEmpty))
            }
        }.padding(24).frame(width: 520)
        .onDisappear { pem = ""; passphrase = "" }
    }
    private func choose() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { do { pem = try String(contentsOf: url, encoding: .utf8) } catch { vault.message = error.localizedDescription } }
    }
}

struct AuditView: View {
    @ObservedObject var agent: Agent
    @State private var query = ""
    @State private var confirming = false
    @State private var selectedID: UUID?
    private var filtered: [AuditEntry] {
        agent.audit.filter { query.isEmpty || "\($0.process) \($0.key) \($0.destination ?? "") \($0.host ?? "") \($0.decision)".localizedCaseInsensitiveContains(query) }
    }
    private var selected: AuditEntry? { agent.audit.first { $0.id == selectedID } }
    var body: some View {
        VStack(spacing: 0) {
            if agent.audit.isEmpty {
                EmptyContent(symbol: "clock.arrow.circlepath", title: tr("暂无使用记录", "No activity yet"), detail: tr("密钥签名的请求与审批结果会显示在这里。", "Key requests and approval decisions appear here.")) { EmptyView() }
            } else {
                Table(filtered, selection: $selectedID) {
                    TableColumn(tr("时间", "Time")) { entry in Text(entry.time.formatted(date: .abbreviated, time: .shortened)).foregroundStyle(.secondary) }.width(min: 120, ideal: 145, max: 170)
                    TableColumn(tr("密钥", "Key"), value: \.key).width(min: 100, ideal: 140)
                    TableColumn(tr("操作", "Operation"), value: \.operation).width(min: 90, ideal: 120)
                    TableColumn(tr("结果", "Decision")) { entry in Text(entry.decision).lineLimit(1).help(entry.decision) }.width(min: 100, ideal: 160)
                }.tableStyle(.inset(alternatesRowBackgrounds: false)).frame(minHeight: 120, maxHeight: .infinity).layoutPriority(-1)
                Divider()
                Group {
                    if let selected {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(selected.process).font(.system(.callout, design: .monospaced)).textSelection(.enabled).lineLimit(2)
                            HStack {
                                Text("PID \(selected.pid)")
                                if let destination = selected.destination { Text(destination) }
                                if selected.forwarded { Label(tr("转发", "Forwarded"), systemImage: "network") }
                            }.font(.caption).foregroundStyle(.secondary)
                            if let host = selected.host { Text(host).font(.system(.caption, design: .monospaced)).textSelection(.enabled).foregroundStyle(.secondary).lineLimit(1) }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
                    } else {
                        Text(tr("选择记录以查看程序与主机详情", "Select an event to see process and host details")).font(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(16)
                    }
                }.frame(height: 112).background(Color(nsColor: .windowBackgroundColor))

            }
            Divider()
            HStack { Text(tr("\(filtered.count) 条记录", "\(filtered.count) events")); Spacer(); Text(tr("仅保存在此 Mac", "Stored on this Mac")) }
                .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 14).frame(height: 30).background(Color(nsColor: .windowBackgroundColor))
        }
        .onReceive(NotificationCenter.default.publisher(for: .bwsshSearch)) { query = $0.object as? String ?? "" }
        .onReceive(NotificationCenter.default.publisher(for: .bwsshClearAudit)) { _ in if !agent.audit.isEmpty { confirming = true } }
        .confirmationDialog(tr("清空本机审计日志？", "Clear local audit history?"), isPresented: $confirming) {
            Button(tr("清空", "Clear"), role: .destructive) { do { try agent.clearAudit() } catch { agent.status = error.localizedDescription } }
        }
    }
}

struct DiagnosticsView: View {
    @ObservedObject var vault: Vault
    @ObservedObject var agent: Agent
    @State private var result = ""
    var body: some View {
        Form {
            Section {
                LabeledContent("SSH agent") {
                    Label(agent.status, systemImage: "circle.fill").font(.callout).symbolRenderingMode(.hierarchical)
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text(tr("Socket 路径", "Socket path")).font(.callout)
                    Text(Paths.socket).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Button(tr("测试连接…", "Test connection…"), action: test)
            } header: { Text(tr("连接状态", "Connection status")) }
            Section {
                LabeledContent(tr("SSH 与 Git 连接", "SSH and Git")) { Button(tr("配置 SSH…", "Configure SSH…")) { setup(false) } }
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(tr("终端环境变量", "Terminal environment")).font(.callout)
                        Spacer()
                        Button(tr("复制", "Copy")) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString("export SSH_AUTH_SOCK=" + SSHConfiguration.shellQuote(Paths.socket), forType: .string) }.controlSize(.small)
                    }
                    Text("export SSH_AUTH_SOCK=" + SSHConfiguration.shellQuote(Paths.socket))
                        .font(.system(.caption, design: .monospaced)).textSelection(.enabled).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            } header: { Text(tr("终端与 Git", "Terminal and Git")) } footer: {
                Text(tr("配置会备份 ~/.ssh/config 并添加 IdentityAgent。将环境变量加入 ~/.zshrc，供 ssh-add 和 Git 提交签名使用。", "Setup backs up ~/.ssh/config and adds IdentityAgent. Add the environment variable to ~/.zshrc for ssh-add and Git commit signing.")).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            }
            Section {
                LabeledContent(tr("运行 SSH 时启动 bwssh", "Launch bwssh when using SSH")) { Button(tr("设置…", "Set up…")) { setup(true) } }
                Button(tr("移除 bwssh 的 SSH 配置…", "Remove bwssh SSH configuration…")) {
                    do { try SSHConfiguration.uninstall(); result = tr("已移除 bwssh 的 SSH 配置。", "Removed bwssh SSH configuration.") } catch { result = error.localizedDescription }
                }
            } header: { Text(tr("按需启动", "On-demand launch")) } footer: {
                Text(tr("请先将应用移到“应用程序”。ssh、scp、sftp 和 git push 可自动启动应用；ssh-add 与 Git 提交签名需先手动打开。", "Move the app to Applications first. ssh, scp, sftp and git push can launch it automatically. Open the app first for ssh-add and Git commit signing.")).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            }
            if !result.isEmpty {
                Section(tr("测试与操作结果", "Results")) { Text(result).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
            }
        }.formStyle(.grouped).scrollContentBackground(.hidden).frame(maxWidth: 720).frame(maxWidth: .infinity)
            .background(Color(nsColor: .windowBackgroundColor))
    }
    private func setup(_ onDemand: Bool) {
        do {
            guard let executable = Bundle.main.executablePath, Bundle.main.bundleURL.pathExtension == "app" else { throw BwError(tr("请先运行打包后的 bwssh.app。", "Run the packaged bwssh.app first.")) }
            try SSHConfiguration.install(executable: executable, onDemand: onDemand); result = tr("已设置。原配置备份为 ~/.ssh/config.bwssh.bak。", "Configured. Original saved as ~/.ssh/config.bwssh.bak.")
        } catch { result = error.localizedDescription }
    }
    private func test() {
        result = tr("测试中…", "Testing…")
        Task {
            result = await Task.detached {
                let process = Process(), pipe = Pipe(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add"); process.arguments = ["-L"]
                process.environment = ProcessInfo.processInfo.environment.merging(["SSH_AUTH_SOCK": Paths.socket]) { _, new in new }
                process.standardOutput = pipe; process.standardError = pipe
                do { try process.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit(); return "Exit \(process.terminationStatus)\n" + String(decoding: data, as: UTF8.self) }
                catch { return error.localizedDescription }
            }.value
        }
    }
}

struct SettingsView: View {
    @ObservedObject var vault: Vault
    @State private var pin = ""
    @State private var loginItem = SMAppService.mainApp.status == .enabled
    @State private var logout = false
    private var supportsBiometry: Bool { LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) }
    var body: some View {
        VStack(spacing: 0) {
            if !vault.message.isEmpty { InlineMessage(text: vault.message) { vault.message = "" } }
            Form {
                Section {
                    Picker(tr("使用密钥时", "When using a key"), selection: $vault.settings.promptMode) {
                        Text(tr("每次询问", "Always ask")).tag("always")
                        Text(tr("锁定前记住主机", "Remember host until lock")).tag("remember")
                        Text(tr("自动批准", "Approve automatically")).tag("never")
                    }
                    duration(tr("临时授权时长", "Temporary access"), value: $vault.settings.grantMinutes, range: 1...1440)
                    LabeledContent(tr("等待审批", "Approval timeout")) {
                        NumericSettingField(tr("等待审批", "Approval timeout"), value: $vault.settings.approvalTimeout, range: 15...300, unit: tr("秒", "seconds"))
                    }

                } header: { Text(tr("密钥使用审批", "Key approval")) } footer: {
                    Text(tr("临时授权仅适用于同一个程序会话；锁定密码库会撤销所有授权。", "Temporary access applies to one process session. Locking the vault revokes all access grants.")).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
                }
                Section {
                    duration(tr("空闲后锁定", "Lock after idle"), value: $vault.settings.idleMinutes, range: 0...1440, step: 5)
                    Toggle(tr("锁定屏幕时锁定密码库", "Lock vault when the screen locks"), isOn: $vault.settings.lockOnScreenLock)
                    Toggle(tr("Mac 睡眠时锁定密码库", "Lock vault when Mac sleeps"), isOn: $vault.settings.lockOnSleep)
                    duration(tr("自动同步间隔", "Sync interval"), value: $vault.settings.syncMinutes, range: 0...1440, step: 5)
                } header: { Text(tr("锁定与同步", "Lock and sync")) }
                Section {
                    LabeledContent("Touch ID") {
                        if supportsBiometry {
                            if vault.settings.touchIDEnabled { Text(tr("已开启", "Enabled")).foregroundStyle(.secondary) }
                            else { Button(tr("设置 Touch ID…", "Set up Touch ID…")) { do { try vault.enableTouchID() } catch { vault.message = error.localizedDescription } }.disabled(!vault.unlocked) }
                        } else { Text(tr("此 Mac 不可用", "Unavailable on this Mac")).foregroundStyle(.secondary) }
                    }
                    LabeledContent("PIN") {
                        HStack(spacing: 8) {
                            RevealPasswordField(tr("至少 4 位", "At least 4 characters"), text: $pin).labelsHidden().accessibilityLabel(tr("新 PIN", "New PIN")).frame(width: 145).textFieldStyle(.roundedBorder)
                            Button(vault.settings.pinEnabled ? tr("更改…", "Change…") : tr("设置…", "Set up…")) { vault.perform { try await vault.setPIN(pin); pin = "" } }
                                .disabled(!vault.unlocked || pin.count < 4 || vault.busy)
                        }
                    }
                    Toggle(tr("每次启动后先用主密码或 Touch ID 解锁", "Require master password or Touch ID after each launch"), isOn: $vault.settings.pinRequiresPrimaryUnlockAfterRestart)
                        .disabled(!vault.unlocked || vault.busy)
                    if vault.settings.touchIDEnabled || vault.settings.pinEnabled {
                        Button(tr("关闭快速解锁…", "Disable quick unlock…")) { do { try vault.disableQuickUnlock() } catch { vault.message = error.localizedDescription } }
                    }
                } header: { Text(tr("快速解锁", "Quick unlock")) } footer: {
                    Text(tr(vault.settings.pinRequiresPrimaryUnlockAfterRestart
                        ? "开启时，每次启动后先用主密码或 Touch ID 解锁，之后可用 PIN。连续输错 5 次会清除 PIN。"
                        : "关闭时，重启 bwssh 后可直接使用 PIN 解锁。连续输错 5 次会清除 PIN。",
                        vault.settings.pinRequiresPrimaryUnlockAfterRestart
                        ? "When enabled, unlock once with the master password or Touch ID after each launch before using PIN. Five failed attempts clear the PIN."
                        : "When disabled, PIN can unlock bwssh immediately after restarting. Five failed attempts clear the PIN.")).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
                }
                Section {
                    Toggle(tr("登录 macOS 时打开 bwssh", "Open bwssh at login"), isOn: $loginItem).onChange(of: loginItem) { enabled in
                        #if DEBUG
                        if ProcessInfo.processInfo.environment["BWSSH_UI_PREVIEW"] == "1" || CommandLine.arguments.contains("--ui-preview") { return }
                        #endif
                        do { if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } }
                        catch { vault.message = error.localizedDescription; loginItem = SMAppService.mainApp.status == .enabled }
                    }
                } header: { Text(tr("启动", "Startup")) }
                if let account = vault.account {
                    Section {
                        LabeledContent(tr("账号", "Account"), value: account.email)
                        LabeledContent(tr("服务器", "Server"), value: account.server.base)
                        Button(tr("退出账号…", "Sign out…"), role: .destructive) { logout = true }
                    } header: { Text(tr("Bitwarden 账号", "Bitwarden account")) }
                }
            }.formStyle(.grouped).scrollContentBackground(.hidden)
        }
        .frame(maxWidth: 680).frame(maxWidth: .infinity).background(Color(nsColor: .windowBackgroundColor))
        .onChange(of: vault.settings) { _ in vault.saveSettings() }
        .confirmationDialog(tr("退出账号并清除本机密码库？", "Sign out and remove the local vault?"), isPresented: $logout) {
            Button(tr("退出账号", "Sign out"), role: .destructive) { do { try vault.logout() } catch { vault.message = error.localizedDescription } }
        }
    }
    private func duration(_ label: String, value: Binding<Int>, range: ClosedRange<Int>, step: Int = 1) -> some View {
        LabeledContent(label) { NumericSettingField(label, value: value, range: range, unit: tr("分钟", "minutes")) }
    }

}

@MainActor final class ApprovalNotice: ObservableObject { @Published var text = "" }

struct ApprovalsView: View {
    @ObservedObject var vault: Vault
    @ObservedObject var agent: Agent
    @ObservedObject var notice: ApprovalNotice
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if !notice.text.isEmpty { Text(notice.text).font(.caption).foregroundStyle(.secondary) }
                ForEach(agent.pending) { request in
                    VStack(alignment: .leading, spacing: 14) {
                        Label(request.context?.operation ?? tr("解锁密码库", "Unlock vault"), systemImage: "key.fill").font(.title2.bold())
                        if let key = request.identity { Text(key.name).font(.headline); Text(key.fingerprint).font(.system(.caption2, design: .monospaced)).textSelection(.enabled) }
                        Text(request.process.isEmpty ? tr("未知程序", "Unknown process") : request.process).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        if let destination = request.destination { LabeledContent(tr("目标（来自命令行）", "Destination (command line)"), value: destination) }
                        if let host = request.context?.host { Text(tr("已验证主机密钥：", "Verified host key: ") + host).font(.caption).textSelection(.enabled) }
                        else if request.context != nil { Text(tr("此请求没有已验证的目标主机信息。", "This request has no verified destination host.")).font(.caption).foregroundStyle(.secondary) }
                        if request.context?.forwarded == true { Label(tr("转发请求：不授予程序限时权限", "Forwarded request: process grants are disabled"), systemImage: "network").font(.caption) }
                        if !vault.unlocked {
                            UnlockView(vault: vault) { agent.resolve(request.id, choice: .approve) }
                            if !vault.message.isEmpty { Text(vault.message).font(.caption).foregroundStyle(.orange) }
                        }
                        HStack {
                            Button(tr("拒绝", "Deny"), role: .destructive) { agent.resolve(request.id, choice: .deny) }
                            Spacer()
                            if vault.unlocked {
                                if request.allowsTemporaryGrant {
                                    Button("\(vault.settings.grantMinutes) " + tr("分钟内放行", "min allow")) { agent.resolve(request.id, choice: .grant) }
                                }
                                Button(tr("批准", "Approve")) { agent.resolve(request.id, choice: .approve) }.buttonStyle(.borderedProminent)
                            }
                        }
                    }.padding(18).background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
                }
                if agent.pending.isEmpty { Text(tr("没有待审批的请求", "No pending requests")).foregroundStyle(.secondary) }
            }.padding(18)
        }.frame(width: 440, height: vault.unlocked ? 300 : 390)
    }
}
