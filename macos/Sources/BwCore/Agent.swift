import Foundation
import Combine
import CBwCrypto

public struct ProcessNode: Identifiable, Equatable {
    public let pid: Int32
    public let started: UInt64
    public let path: String
    public var name: String { URL(fileURLWithPath: path).lastPathComponent }
    public var id: String { "\(pid):\(started):\(path)" }
    public static func chain(_ pid: Int32) -> [ProcessNode] {
        var result = [ProcessNode](); var current = pid; var visited = Set<Int32>()
        for _ in 0..<24 {
            guard current > 1, visited.insert(current).inserted else { break }
            var parent: Int32 = 0, started: UInt64 = 0; var path = [CChar](repeating: 0, count: 4096)
            guard bw_process(current, &parent, &started, &path, path.count) == 0 else { break }
            result.append(ProcessNode(pid: current, started: started, path: String(cString: path))); current = parent
        }; return result
    }
    public static func arguments(_ pid: Int32) -> [String] {
        var output = [CChar](repeating: 0, count: 65536); let n = bw_arguments(pid, &output, output.count)
        guard n > 0 else { return [] }
        return Data(output.prefix(Int(n)).map { UInt8(bitPattern: $0) }).split(separator: 0).map { String(decoding: $0, as: UTF8.self) }
    }
    public static func destination(_ chain: [ProcessNode]) -> String? {
        guard let ssh = chain.first(where: { ["ssh", "scp", "sftp"].contains($0.name) }) else { return nil }
        let args = arguments(ssh.pid)
        guard ssh.name == "ssh" else { return nil }
        let takesValue: Set<Character> = Set("BbcDEeFIiJLlmOopQRSWw")
        var skip = false
        for arg in args.dropFirst() {
            if skip { skip = false; continue }
            if arg == "--" { continue }
            if arg.hasPrefix("-") {
                if arg.count == 2, let option = arg.last, takesValue.contains(option) { skip = true }
                continue
            }
            return arg
        }; return nil
    }
}

public struct SignContext {
    public let keyBlob: Data
    public let data: Data
    public let flags: UInt32
    public let host: String?
    public let forwarded: Bool
    public var namespace: String? {
        guard data.starts(with: Data("SSHSIG".utf8)) else { return nil }
        var r = SSHReader(Data(data.dropFirst(6))); return try? r.text()
    }
    public var operation: String {
        if let namespace { return namespace == "git" ? tr("Git 提交签名", "Git commit signing") : tr("文件签名", "File signing") + " (\(namespace))" }
        return Self.userAuth(data) != nil ? tr("SSH 登录", "SSH login") : tr("签名", "Signing")
    }
    static func userAuth(_ data: Data) -> (Data, String)? {
        do {
            var r = SSHReader(data); let session = try r.string(); guard try r.byte() == 50 else { return nil }
            let user = try r.text(); guard try r.text() == "ssh-connection", try r.text().hasPrefix("publickey") else { return nil }
            return (session, user)
        } catch { return nil }
    }
    var rememberScope: String? {
        if let host { return (forwarded ? "forwarded:" : "local:") + host }
        if namespace != nil, !forwarded { return "local-signature:\(namespace!)" }
        return nil // Unbound authentication requests cannot prove a destination.
    }
}

struct SessionBinding {
    var bindings: [(Data, String)] = []
    var forwarded = false
    mutating func bind(_ payload: Data) -> Bool {
        do {
            var r = SSHReader(payload); let host = try r.string(), session = try r.string(), signature = try r.string(); let forwarding = try r.byte()
            guard r.remaining == 0, forwarding <= 1, !session.isEmpty, bindings.count < 16,
                  SSHKey.verify(publicBlob: host, signature: signature, data: session) else { return false }
            if let existing = bindings.first(where: { $0.0 == session }) { return existing.1 == host.fingerprint && (forwarding == 0 || forwarded) }
            bindings.append((session, host.fingerprint)); forwarded = forwarded || forwarding == 1; return true
        } catch { return false }
    }
    func host(for data: Data) -> String? {
        guard let (session, _) = SignContext.userAuth(data) else { return nil }
        return bindings.first(where: { $0.0 == session })?.1
    }
}

public struct AuditEntry: Codable, Identifiable {
    public var id = UUID()
    public var time = Date()
    public let key: String
    public let fingerprint: String
    public let process: String
    public let pid: Int32
    public let destination: String?
    public let host: String?
    public let operation: String
    public let forwarded: Bool
    public let decision: String
}

public struct PendingApproval: Identifiable {
    public let id: UUID
    public let identity: PublicIdentity?
    public let context: SignContext?
    public let chain: [ProcessNode]
    public let target: ProcessNode?
    public let destination: String?
    public let created = Date()
    public var process: String { chain.reversed().map(\.name).joined(separator: " → ") }
}

public struct ProcessGrant: Identifiable {
    public let id: String
    public let name: String
    public let expires: Date
}

public enum ApprovalChoice { case approve, grant, deny }

@MainActor public final class Agent: ObservableObject {
    @Published public private(set) var pending: [PendingApproval] = []
    @Published public private(set) var audit: [AuditEntry] = []
    @Published public private(set) var grants: [ProcessGrant] = []
    @Published public var status = ""
    public let vault: Vault
    public var onPrompt: ((PendingApproval) -> Void)?
    public var onDismiss: ((UUID) -> Void)?
    private var continuations: [UUID: CheckedContinuation<ApprovalChoice, Never>] = [:]
    private var timeouts: [UUID: Task<Void, Never>] = [:]
    private var remembered = Set<String>()
    private let store: LocalStore
    public init(vault: Vault, store: LocalStore? = nil) throws {
        self.vault = vault; self.store = try store ?? LocalStore(); audit = try self.store.load([AuditEntry].self, name: "audit") ?? []
        vault.onLock = { [weak self] in self?.revokeAll(); self?.cancelAll() }
    }
    public func revokeAll() { remembered.removeAll(); grants.removeAll() }
    public func revoke(_ id: String) { grants.removeAll { $0.id == id } }
    public func clearAudit() throws { try store.save([AuditEntry](), name: "audit"); audit = [] }
    public func cancelAll() { for id in Array(continuations.keys) { resolve(id, choice: .deny) } }
    public func resolve(_ id: UUID, choice: ApprovalChoice) {
        guard let continuation = continuations.removeValue(forKey: id) else { return }
        timeouts.removeValue(forKey: id)?.cancel(); pending.removeAll { $0.id == id }; onDismiss?(id)
        continuation.resume(returning: choice)
    }
    private func prompt(_ request: PendingApproval) async -> ApprovalChoice {
        guard pending.count < 16, !Task.isCancelled else { return .deny }
        return await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { continuation in
                continuations[request.id] = continuation; pending.append(request)
                let timeout = vault.settings.approvalTimeout
                timeouts[request.id] = Task { [weak self] in
                    do { try await Task.sleep(nanoseconds: UInt64(max(15, min(timeout, 300))) * 1_000_000_000) } catch { return }
                    self?.resolve(request.id, choice: .deny)
                }
                onPrompt?(request)
            }
        }, onCancel: { Task { @MainActor [weak self] in self?.resolve(request.id, choice: .deny) } })
    }
    public func identities(chain: [ProcessNode]) async -> [PublicIdentity] {
        guard vault.account != nil else { return [] }
        if vault.identities.isEmpty, !vault.unlocked {
            _ = await prompt(PendingApproval(id: UUID(), identity: nil, context: nil, chain: chain, target: nil, destination: ProcessNode.destination(chain)))
        }
        return vault.identities
    }
    public func sign(_ context: SignContext, chain: [ProcessNode]) async -> Data? {
        guard let identity = vault.identities.first(where: { $0.blob == context.keyBlob }) else { return nil }
        let target = chain.first(where: { ["claude", "codex", "cursor", "aider"].contains($0.name.lowercased()) }) ?? chain.first
        let p = PendingApproval(id: UUID(), identity: identity, context: context, chain: chain, target: target, destination: ProcessNode.destination(chain))
        let rememberedID = context.rememberScope.map { identity.id + ":" + $0 }
        let grantID = target.map { identity.id + ":" + $0.id }
        grants.removeAll { $0.expires <= Date() }
        var decision = tr("已拒绝", "Denied"); var choice: ApprovalChoice = .deny
        if vault.unlocked && vault.settings.promptMode == "never" { choice = .approve; decision = tr("自动批准", "Auto-approved") }
        else if vault.unlocked, vault.settings.promptMode == "remember", let rememberedID, remembered.contains(rememberedID) { choice = .approve; decision = tr("锁定前记住", "Remembered until lock") }
        else if vault.unlocked, !context.forwarded, let grantID, grants.contains(where: { $0.id == grantID }) { choice = .approve; decision = tr("程序授权期内", "Process grant") }
        else { choice = await prompt(p); if choice != .deny { decision = tr("已批准", "Approved") } }
        var signature: Data?
        if choice != .deny, vault.unlocked, !Task.isCancelled,
           let current = vault.identities.first(where: { $0.id == identity.id }), current.blob == identity.blob {
            do {
                signature = try vault.sign(id: identity.id, data: context.data, flags: context.flags)
                if choice == .grant, !context.forwarded, let grantID, let target,
                   ProcessNode.chain(target.pid).first?.id == target.id {
                    let expires = Date().addingTimeInterval(Double(min(max(vault.settings.grantMinutes, 1), 1440)) * 60)
                    grants.removeAll { $0.id == grantID }; grants.append(ProcessGrant(id: grantID, name: "\(target.name) · \(identity.name) · PID \(target.pid)", expires: expires))
                }
                if vault.settings.promptMode == "remember", let rememberedID { remembered.insert(rememberedID) }
            } catch { decision = error.localizedDescription }
        } else if choice != .deny { decision = tr("密码库已锁定", "Vault locked") }
        audit.insert(AuditEntry(key: identity.name, fingerprint: identity.fingerprint, process: p.process, pid: chain.first?.pid ?? -1, destination: p.destination, host: context.host,
            operation: context.operation, forwarded: context.forwarded, decision: decision), at: 0)
        audit = Array(audit.prefix(2000))
        do { try store.save(audit, name: "audit") } catch { status = tr("审计保存失败：", "Audit could not be saved: ") + error.localizedDescription; return nil }
        return signature
    }
}
