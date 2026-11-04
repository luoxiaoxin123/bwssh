import SwiftUI
import AppKit
import ServiceManagement
import BwCore

struct MainView: View {
    @ObservedObject var vault: Vault
    @ObservedObject var agent: Agent
    @State private var selection = "keys"
    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label(tr("SSH 密钥", "SSH keys"), systemImage: "key").tag("keys")
                Label(tr("审计日志", "Audit log"), systemImage: "list.bullet.rectangle").tag("audit")
                Label(tr("诊断", "Diagnostics"), systemImage: "stethoscope").tag("diagnostics")
                Label(tr("设置", "Settings"), systemImage: "gearshape").tag("settings")
            }
            .listStyle(.sidebar)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 6) {
                    Label(vault.unlocked ? tr("已解锁", "Unlocked") : tr("已锁定", "Locked"), systemImage: vault.unlocked ? "lock.open" : "lock")
                    if let account = vault.account { Text(account.email).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                }.padding().frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 195, max: 250)
        } detail: {
            VStack(spacing: 0) {
                if !vault.message.isEmpty {
                    HStack { Image(systemName: "exclamationmark.triangle"); Text(vault.message).textSelection(.enabled); Spacer(); Button { vault.message = "" } label: { Image(systemName: "xmark") }.buttonStyle(.plain) }
                        .font(.callout).padding(12).background(Color.orange.opacity(0.12))
                }
                if vault.account == nil { LoginView(vault: vault) }
                else {
                    switch selection {
                    case "audit": AuditView(agent: agent)
                    case "diagnostics": DiagnosticsView(vault: vault, agent: agent)
                    case "settings": SettingsView(vault: vault)
                    default: KeysView(vault: vault, agent: agent)
                    }
                }
            }
            .overlay(alignment: .topTrailing) { if vault.busy { ProgressView().controlSize(.small).padding() } }
        }
        .frame(minWidth: 720, minHeight: 500)
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
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Image(systemName: "key.horizontal.fill").font(.system(size: 38)).foregroundStyle(.tint)
                Text(tr("连接你的密码库", "Connect your vault")).font(.largeTitle.bold())
                Text(tr("从 Bitwarden 安全地使用 SSH 密钥。", "Use your SSH keys securely from Bitwarden.")).foregroundStyle(.secondary)
                Picker(tr("服务器", "Server"), selection: $server) {
                    Text("bitwarden.com").tag("https://bitwarden.com"); Text("bitwarden.eu").tag("https://bitwarden.eu"); Text(tr("自托管", "Self-hosted")).tag("custom")
                }
                if server == "custom" { TextField("https://vault.example.com", text: $custom) }
                TextField(tr("邮箱", "Email"), text: $email)
                SecureField(tr("主密码", "Master password"), text: $password).onSubmit(login)
                Toggle(tr("使用 API Key 登录", "Sign in with API key"), isOn: $apiKey)
                if apiKey {
                    TextField("client_id (user.…)", text: $clientID); SecureField("client_secret", text: $clientSecret)
                    Text(tr("主密码用于在本机解密密码库。", "The master password decrypts the vault locally.")).font(.caption).foregroundStyle(.secondary)
                }
                if let challenge {
                    if challenge.newDevice { TextField(tr("新设备邮件验证码", "New-device email code"), text: $otp) }
                    else {
                        Picker(tr("两步验证", "Two-factor method"), selection: $provider) {
                            ForEach(challenge.providers.filter { [0, 1, 3].contains($0) }, id: \.self) { p in Text(p == 0 ? tr("验证器", "Authenticator") : p == 1 ? tr("邮件", "Email") : "YubiKey OTP").tag(p) }
                        }
                        TextField(tr("验证码", "Verification code"), text: $code)
                        if provider == 1 { Button(tr("发送邮件验证码", "Send email code")) { sendEmail() } }
                        if challenge.providers.allSatisfy({ ![0, 1, 3].contains($0) }) { Text(tr("该账户的两步验证方式暂不支持。请使用 API Key。", "This two-factor method is unsupported. Use an API key.")).foregroundStyle(.orange) }
                    }
                }
                if !localMessage.isEmpty { Text(localMessage).foregroundStyle(.orange).textSelection(.enabled) }
                Button(tr("登录并解锁", "Sign in and unlock"), action: login).buttonStyle(.borderedProminent).controlSize(.large).disabled(vault.busy || email.isEmpty || password.isEmpty)
            }.textFieldStyle(.roundedBorder).padding(40).frame(maxWidth: 520)
        }.frame(maxWidth: .infinity)
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
    @State private var password = ""
    @State private var pinMode = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(tr("密码库已锁定", "Vault locked"), systemImage: "lock.fill").font(.headline)
            SecureField(pinMode ? "PIN" : tr("主密码", "Master password"), text: $password).textFieldStyle(.roundedBorder).onSubmit(unlock)
            HStack {
                Button(tr("解锁", "Unlock"), action: unlock).buttonStyle(.borderedProminent).disabled(vault.busy || password.isEmpty)
                if vault.settings.touchIDEnabled {
                    Button { vault.perform { try await vault.unlockTouchID(); onUnlocked() } } label: { Label("Touch ID", systemImage: "touchid") }.disabled(vault.busy)
                }
                if vault.settings.pinEnabled { Button(pinMode ? tr("使用主密码", "Use password") : tr("使用 PIN", "Use PIN")) { pinMode.toggle(); password = "" } }
            }
        }.padding().background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
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
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text(tr("SSH 密钥", "SSH keys")).font(.largeTitle.bold()); Spacer()
                Button { vault.perform { try await vault.sync() } } label: { Image(systemName: "arrow.clockwise") }.help(tr("同步", "Sync")).disabled(vault.busy)
                if vault.unlocked { Button { vault.lock() } label: { Image(systemName: "lock") } }
                Button { adding = true } label: { Label(tr("添加密钥", "Add key"), systemImage: "plus") }.disabled(!vault.unlocked || vault.busy)
            }
            if !vault.unlocked { UnlockView(vault: vault) }
            if vault.identities.isEmpty {
                VStack(spacing: 12) { Image(systemName: "key").font(.system(size: 42)).foregroundStyle(.secondary); Text(tr("密码库中还没有 SSH 密钥", "No SSH keys in this vault")); Text(tr("生成或导入密钥后即可连接。", "Generate or import a key to get started.")).font(.caption).foregroundStyle(.secondary) }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(vault.identities) { key in
                    HStack(spacing: 12) {
                        Image(systemName: "key.fill").foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(key.name).font(.headline)
                            Text(key.type).font(.caption).foregroundStyle(.secondary)
                            Text(key.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        }
                        Spacer()
                        Menu {
                            Button(tr("复制公钥", "Copy public key")) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(key.publicLine, forType: .string) }
                            Button(tr("重命名", "Rename")) { renameID = key.id; renameName = key.name }.disabled(!vault.unlocked)
                            Button(tr("移到回收站", "Move to trash"), role: .destructive) { deleting = key }.disabled(!vault.unlocked)
                        } label: { Image(systemName: "ellipsis") }.menuStyle(.borderlessButton).frame(width: 28)
                    }.padding(.vertical, 8)
                }.listStyle(.inset)
            }
            if !agent.grants.isEmpty {
                GroupBox(tr("临时授权", "Temporary grants")) {
                    ForEach(agent.grants) { grant in HStack { VStack(alignment: .leading) { Text(grant.name); Text(grant.expires, style: .time).foregroundStyle(.secondary) }; Spacer(); Button(tr("撤销", "Revoke")) { agent.revoke(grant.id) } }.font(.caption).padding(4) }
                }
            }
            if !vault.errors.isEmpty { DisclosureGroup(tr("部分密钥无法加载", "Some keys could not be loaded")) { Text(vault.errors.joined(separator: "\n")).font(.caption).foregroundStyle(.orange).textSelection(.enabled) } }
            if let time = vault.account?.syncedAt { Text(tr("上次同步：", "Last sync: ") + time.formatted()).font(.caption).foregroundStyle(.secondary) }
        }.padding(24)
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
                HStack { Button(tr("选择私钥文件…", "Choose private key…"), action: choose); SecureField(tr("私钥密码（可选）", "Passphrase (optional)"), text: $passphrase) }
            }
            if !vault.message.isEmpty { Text(vault.message).foregroundStyle(.orange).font(.caption) }
            HStack {
                Spacer(); Button(tr("取消", "Cancel")) { dismiss() }
                Button(tr("保存到密码库", "Save to vault")) {
                    vault.perform { try await vault.add(name: name, pem: pem, passphrase: passphrase, rsa: kind == "import" ? nil : kind == "rsa"); pem = ""; passphrase = ""; dismiss() }
                }.buttonStyle(.borderedProminent).disabled(vault.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (kind == "import" && pem.isEmpty))
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
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text(tr("审计日志", "Audit log")).font(.largeTitle.bold()); Spacer(); Button(tr("清空", "Clear")) { confirming = true } }
            TextField(tr("筛选程序、主机、密钥或结果", "Filter by process, host, key or decision"), text: $query).textFieldStyle(.roundedBorder)
            List(agent.audit.filter { query.isEmpty || "\($0.process) \($0.key) \($0.destination ?? "") \($0.host ?? "") \($0.decision)".localizedCaseInsensitiveContains(query) }) { entry in
                VStack(alignment: .leading, spacing: 6) {
                    HStack { Text(entry.key).bold(); Text(entry.operation).foregroundStyle(.secondary); Spacer(); Text(entry.decision).font(.caption) }
                    Text(entry.process + " · PID \(entry.pid)").font(.system(.caption, design: .monospaced))
                    HStack { Text(entry.time.formatted()); if let destination = entry.destination { Text(destination) }; if entry.forwarded { Text(tr("转发请求", "Forwarded")) } }.font(.caption).foregroundStyle(.secondary)
                    if let host = entry.host { Text(host).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary) }
                }.textSelection(.enabled).padding(.vertical, 6)
            }.listStyle(.inset)
        }.padding(24)
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
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(tr("诊断", "Diagnostics")).font(.largeTitle.bold())
                GroupBox("SSH agent") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(agent.status)
                        Text(Paths.socket).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button(tr("测试 ssh-add -L", "Test ssh-add -L"), action: test)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox(tr("连接终端与 Git", "Connect terminal and Git")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(tr("设置会在 ~/.ssh/config 开头加入 IdentityAgent，保留原配置并创建备份。", "Setup adds IdentityAgent at the start of ~/.ssh/config and creates a backup of the original file."))
                        Button(tr("配置 SSH", "Configure SSH")) { setup(false) }
                        Text("export SSH_AUTH_SOCK=" + SSHConfiguration.shellQuote(Paths.socket)).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Text(tr("将上面的 export 加到 ~/.zshrc（或当前 shell 配置），让 ssh-add 和 Git SSH 签名找到 agent。", "Add this export to ~/.zshrc (or your shell configuration) so ssh-add and Git SSH signing can find the agent.")).font(.caption).foregroundStyle(.secondary)
                        Button(tr("复制环境变量", "Copy environment variable")) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString("export SSH_AUTH_SOCK=" + SSHConfiguration.shellQuote(Paths.socket), forType: .string) }
                    }.padding(8)
                }
                GroupBox(tr("按需启动", "On-demand launch")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(tr("执行 ssh、scp、sftp 或 git push 时自动启动 bwssh。ssh-add 与 Git 提交签名需要先打开应用。请先将应用移到 /Applications，移动后重新设置。", "Automatically launch bwssh for ssh, scp, sftp and git push. Open the app first for ssh-add and Git commit signing. Move the app to /Applications before setup; run setup again after moving it."))
                        HStack { Button(tr("一键设置", "Set up")) { setup(true) }; Button(tr("撤销 SSH 配置", "Remove SSH configuration")) { do { try SSHConfiguration.uninstall(); result = tr("已撤销 bwssh 配置。", "Removed bwssh configuration.") } catch { result = error.localizedDescription } } }
                    }.padding(8)
                }
                if !result.isEmpty { Text(result).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
            }.padding(24)
        }
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
    var body: some View {
        Form {
            Section(tr("审批", "Approval")) {
                Picker(tr("批准方式", "Prompt mode"), selection: $vault.settings.promptMode) {
                    Text(tr("每次都询问", "Always ask")).tag("always")
                    Text(tr("锁定前记住主机", "Remember host until lock")).tag("remember")
                    Text(tr("从不询问", "Never ask")).tag("never")
                }
                Stepper(tr("程序授权：", "Process grant: ") + "\(vault.settings.grantMinutes) min", value: $vault.settings.grantMinutes, in: 1...1440)
                Stepper(tr("审批超时：", "Approval timeout: ") + "\(vault.settings.approvalTimeout) s", value: $vault.settings.approvalTimeout, in: 15...300, step: 15)
            }
            Section(tr("自动锁定与同步", "Lock and sync")) {
                Stepper(tr("空闲自动锁定：", "Lock after idle: ") + "\(vault.settings.idleMinutes) min (0 = off)", value: $vault.settings.idleMinutes, in: 0...1440, step: 5)
                Toggle(tr("锁屏时锁定", "Lock on screen lock"), isOn: $vault.settings.lockOnScreenLock)
                Toggle(tr("睡眠时锁定", "Lock on sleep"), isOn: $vault.settings.lockOnSleep)
                Stepper(tr("同步间隔：", "Sync interval: ") + "\(vault.settings.syncMinutes) min (0 = off)", value: $vault.settings.syncMinutes, in: 0...1440, step: 5)
            }
            Section(tr("快速解锁", "Quick unlock")) {
                HStack {
                    Label(vault.settings.touchIDEnabled ? tr("Touch ID 已开启", "Touch ID enabled") : tr("Touch ID 未开启", "Touch ID disabled"), systemImage: "touchid")
                    Spacer(); Button(tr("开启 Touch ID", "Enable Touch ID")) { do { try vault.enableTouchID() } catch { vault.message = error.localizedDescription } }.disabled(!vault.unlocked)
                }
                HStack { SecureField(tr("设置新 PIN（至少 4 位）", "New PIN (at least 4 characters)"), text: $pin); Button(tr("设置 PIN", "Set PIN")) { vault.perform { try await vault.setPIN(pin); pin = "" } }.disabled(!vault.unlocked || pin.count < 4 || vault.busy) }
                Text(tr("PIN 连续输错 5 次后清除；每次启动后需先用主密码或 Touch ID 解锁。", "PIN is cleared after 5 failed attempts. Use the master password or Touch ID once after each app launch.")).font(.caption).foregroundStyle(.secondary)
                Button(tr("关闭快速解锁", "Disable quick unlock")) { do { try vault.disableQuickUnlock() } catch { vault.message = error.localizedDescription } }
            }
            Section(tr("启动", "Startup")) {
                Toggle(tr("登录 macOS 时启动", "Start at login"), isOn: $loginItem).onChange(of: loginItem) { enabled in
                    do { if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } }
                    catch { vault.message = error.localizedDescription; loginItem = SMAppService.mainApp.status == .enabled }
                }
            }
            Section { Button(tr("退出账号", "Sign out"), role: .destructive) { logout = true } }
        }.formStyle(.grouped).onChange(of: vault.settings) { _ in vault.saveSettings() }
        .confirmationDialog(tr("退出账号并清除本机密码库？", "Sign out and remove the local vault?"), isPresented: $logout) {
            Button(tr("退出账号", "Sign out"), role: .destructive) { do { try vault.logout() } catch { vault.message = error.localizedDescription } }
        }
    }
}

struct ApprovalsView: View {
    @ObservedObject var vault: Vault
    @ObservedObject var agent: Agent
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
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
                                if request.identity != nil, request.context?.forwarded != true {
                                    Button("\(vault.settings.grantMinutes) " + tr("分钟内放行", "min allow")) { agent.resolve(request.id, choice: .grant) }
                                }
                                Button(tr("批准", "Approve")) { agent.resolve(request.id, choice: .approve) }.buttonStyle(.borderedProminent)
                            }
                        }
                    }.padding(18).background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
                }
                if agent.pending.isEmpty { Text(tr("没有待审批的请求", "No pending requests")).foregroundStyle(.secondary) }
            }.padding(18)
        }.frame(minWidth: 440, minHeight: 240)
    }
}
