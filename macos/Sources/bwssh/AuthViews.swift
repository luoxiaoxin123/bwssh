import SwiftUI
import BwCore

struct RevealPasswordField: View {
    let title: String
    @Binding var text: String
    @State private var visible = false
    @FocusState private var focus: Field?
    private enum Field { case secure, plain }
    init(_ title: String, text: Binding<String>) { self.title = title; _text = text }
    var body: some View {
        HStack(spacing: 6) {
            Group {
                if visible { TextField("", text: $text, prompt: Text(title)).focused($focus, equals: .plain) }
                else { SecureField("", text: $text, prompt: Text(title)).focused($focus, equals: .secure) }
            }.textFieldStyle(.plain).labelsHidden().accessibilityLabel(title)
            Button {
                visible.toggle(); focus = visible ? .plain : .secure
            } label: { Image(systemName: visible ? "eye.slash" : "eye").frame(width: 22, height: 20) }
            .buttonStyle(.plain).foregroundStyle(.secondary)
            .help(visible ? tr("隐藏密码", "Hide password") : tr("显示密码", "Show password"))
            .accessibilityLabel(visible ? tr("隐藏密码", "Hide password") : tr("显示密码", "Show password"))
        }
        .padding(.horizontal, 8).padding(.vertical, 4)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(focus == nil ? Color(nsColor: .separatorColor) : .accentColor, lineWidth: focus == nil ? 0.5 : 2))
        .onDisappear { visible = false }
    }
}

struct LockedLoginPage: View {
    @ObservedObject var vault: Vault
    @State private var signInAgain = false
    var body: some View {
        if signInAgain {
            VStack(spacing: 0) {
                HStack { Button(tr("返回解锁", "Back to unlock")) { signInAgain = false }; Spacer() }.padding(16)
                if !vault.message.isEmpty { InlineMessage(text: vault.message) { vault.message = "" } }
                LoginView(vault: vault, email: vault.account?.email ?? "", server: vault.account?.server.base ?? "https://bitwarden.com")
            }
        } else {
            ScrollView {
                VStack(spacing: 20) {
                    Image(systemName: "lock.shield").font(.system(size: 44, weight: .light)).foregroundStyle(.tint)
                    Text(tr("解锁密码库", "Unlock your vault")).font(.title2.weight(.semibold))
                    VStack(spacing: 5) {
                        Text(vault.account?.email ?? "").font(.callout)
                        Text(vault.account?.server.base ?? "").font(.caption).foregroundStyle(.secondary)
                    }
                    UnlockView(vault: vault, standalone: true)
                    if !vault.message.isEmpty {
                        Text(vault.message).font(.callout).foregroundStyle(.red).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                    if vault.busy { ProgressView().controlSize(.small) }
                    Divider().padding(.vertical, 4)
                    HStack {
                        Button(tr("刷新解锁信息", "Refresh unlock information")) { vault.perform { try await vault.refreshUnlockInformation() } }.disabled(vault.busy)
                        Spacer()
                        Button(tr("重新登录…", "Sign in again…")) { vault.message = ""; signInAgain = true }.disabled(vault.busy)
                    }.font(.callout)
                }.padding(32).frame(width: 420).frame(maxWidth: .infinity).padding(.top, 56)
            }.background(Color(nsColor: .windowBackgroundColor))
        }
    }
}

struct NumericSettingField: View {
    let title: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    let unit: String
    @State private var draft: String
    @FocusState private var focused: Bool
    init(_ title: String, value: Binding<Int>, range: ClosedRange<Int>, unit: String) {
        self.title = title; _value = value; self.range = range; self.unit = unit
        _draft = State(initialValue: String(value.wrappedValue))
    }
    private var parsed: Int? {
        let trimmed = draft.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed.utf8.allSatisfy({ (48...57).contains($0) }), let n = Int(trimmed), range.contains(n) else { return nil }; return n
    }
    var body: some View {
        VStack(alignment: .trailing, spacing: 3) {
            HStack(spacing: 7) {
                TextField("", text: $draft).labelsHidden().accessibilityLabel(title)
                    .textFieldStyle(.roundedBorder).multilineTextAlignment(.trailing).monospacedDigit().frame(width: 72).focused($focused)
                    .help(tr("输入整数：", "Enter an integer: ") + "\(range.lowerBound)–\(range.upperBound)")
                Text(unit).foregroundStyle(.secondary)
            }
            if parsed == nil { Text(tr("未保存：请输入 ", "Not saved: enter ") + "\(range.lowerBound)–\(range.upperBound)").font(.caption).foregroundStyle(.red) }
        }
        .onChange(of: draft) { _ in if let parsed { value = parsed } }
        .onChange(of: value) { new in if !focused { draft = String(new) } }
    }
}
