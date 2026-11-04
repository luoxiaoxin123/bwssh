import Foundation
import Darwin
import CBwCrypto

public final class SocketServer {
    private var source: DispatchSourceRead?
    private var fd: Int32 = -1
    private let queue = DispatchQueue(label: "com.bwssh.socket")
    private let workers = DispatchQueue(label: "com.bwssh.clients", attributes: .concurrent)
    private let gate = NSLock()
    private var clients = Set<Int32>()
    private var ownedInode: UInt64?
    private let path: String
    private let handler: (Data, [ProcessNode], inout SessionBinding) async -> Data
    public init(path: String = Paths.socket, agent: Agent) {
        self.path = path
        handler = { [weak agent] message, chain, binding in
            guard let agent else { return Data([5]) }
            return await Self.handle(message, chain: chain, binding: &binding, identities: { await agent.identities(chain: chain) }, sign: { await agent.sign($0, chain: chain) })
        }
    }
    init(path: String, handler: @escaping (Data, [ProcessNode], inout SessionBinding) async -> Data) { self.path = path; self.handler = handler }
    public static func isRunning(path: String = Paths.socket) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { return false }; defer { close(fd) }
        guard var address = try? address(path) else { return false }
        return withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0 } }
    }
    private static func address(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw BwError("Agent socket path exceeds macOS's 103-byte limit") }
        withUnsafeMutableBytes(of: &address.sun_path) { target in target.copyBytes(from: bytes + [0]) }
        return address
    }
    public func start() throws {
        guard source == nil else { return }; try Paths.prepare(URL(fileURLWithPath: path).deletingLastPathComponent())
        var existing = stat()
        if lstat(path, &existing) == 0 {
            guard existing.st_uid == getuid(), existing.st_mode & S_IFMT == S_IFSOCK else { throw BwError("Unsafe or conflicting agent socket") }
            guard !Self.isRunning(path: path) else { throw BwError(tr("bwssh agent 已在运行。", "The bwssh agent is already running.")) }
            guard unlink(path) == 0 else { throw BwError("Cannot remove stale socket") }
        }
        let listener = socket(AF_UNIX, SOCK_STREAM, 0); guard listener >= 0 else { throw BwError("Cannot create agent socket") }
        var address = try Self.address(path)
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard bound == 0 else { close(listener); throw BwError("Cannot bind agent socket: \(String(cString: strerror(errno)))") }
        guard chmod(path, 0o600) == 0, listen(listener, 16) == 0 else { close(listener); unlink(path); throw BwError("Cannot protect/listen on agent socket") }
        _ = fcntl(listener, F_SETFL, O_NONBLOCK); _ = fcntl(listener, F_SETFD, FD_CLOEXEC)
        var info = stat(); _ = lstat(path, &info); ownedInode = UInt64(info.st_ino)
        fd = listener
        let source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptClients(listener) }
        source.setCancelHandler { close(listener) }
        self.source = source; source.resume()
    }
    public func stop() {
        source?.cancel(); source = nil; fd = -1
        gate.lock(); for client in clients { shutdown(client, SHUT_RDWR) }; gate.unlock()
        var info = stat()
        if let ownedInode, lstat(path, &info) == 0, UInt64(info.st_ino) == ownedInode { unlink(path) }
        ownedInode = nil
    }
    deinit { stop() }
    private func acceptClients(_ listener: Int32) {
        while true {
            let client = accept(listener, nil, nil); if client < 0 { break }
            var uid: uid_t = 0, gid: gid_t = 0
            let pid = bw_peer_pid(client)
            gate.lock(); let capacity = clients.count < 32
            if capacity, getpeereid(client, &uid, &gid) == 0, uid == getuid(), pid > 0 { clients.insert(client); gate.unlock() }
            else { gate.unlock(); close(client); continue }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            // Darwin accept() inherits O_NONBLOCK from the listener. Worker reads are blocking,
            // bounded by SO_RCVTIMEO; leaving this flag set closes connections between frames.
            _ = fcntl(client, F_SETFL, fcntl(client, F_GETFL) & ~O_NONBLOCK)
            var noSig: Int32 = 1; _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSig, socklen_t(MemoryLayout.size(ofValue: noSig)))
            var timeout = timeval(tv_sec: 120, tv_usec: 0); _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
            timeout.tv_sec = 5; _ = setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
            workers.async { [self] in
                defer { gate.lock(); clients.remove(client); gate.unlock(); close(client) }
                let chain = ProcessNode.chain(pid); guard !chain.isEmpty else { return }
                serve(client, chain: chain)
            }
        }
    }
    private func read(_ fd: Int32, count: Int) -> Data? {
        var data = Data(count: count); var offset = 0
        while offset < count {
            let n = data.withUnsafeMutableBytes { recv(fd, $0.baseAddress!.advanced(by: offset), count - offset, 0) }
            if n < 0 && errno == EINTR { continue }; guard n > 0 else { return nil }; offset += n
        }; return data
    }
    private final class Reply: @unchecked Sendable {
        let lock = NSLock(); var value = Data([5]); var binding = SessionBinding()
        func set(_ value: Data, _ binding: SessionBinding) { lock.lock(); self.value = value; self.binding = binding; lock.unlock() }
        func get() -> (Data, SessionBinding) { lock.lock(); defer { lock.unlock() }; return (value, binding) }
    }
    private func serve(_ fd: Int32, chain: [ProcessNode]) {
        var binding = SessionBinding()
        while let header = read(fd, count: 4) {
            let count = header.reduce(0) { ($0 << 8) | Int($1) }
            guard count > 0, count <= 256 * 1024, let message = read(fd, count: count) else { return }
            let signal = DispatchSemaphore(value: 0), reply = Reply(), initial = binding
            let task = Task { var current = initial; let result = await handler(message, chain, &current); reply.set(result, current); signal.signal() }
            let deadline = Date().addingTimeInterval(310)
            while signal.wait(timeout: .now() + .milliseconds(100)) == .timedOut {
                var pollFD = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                _ = poll(&pollFD, 1, 0)
                var byte: UInt8 = 0
                let disconnected = pollFD.revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 || (pollFD.revents & Int16(POLLIN) != 0 && recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
                if disconnected || Date() > deadline { task.cancel(); return }
            }
            let (result, next) = reply.get(); binding = next
            var w = SSHWriter(); w.uint32(UInt32(result.count)); let frame = w.data + result
            var offset = 0
            while offset < frame.count {
                let n = frame.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), frame.count - offset, 0) }
                if n < 0 && errno == EINTR { continue }; guard n > 0 else { return }; offset += n
            }
        }
    }
    static func handle(_ data: Data, chain: [ProcessNode], binding: inout SessionBinding,
                       identities: () async -> [PublicIdentity], sign: (SignContext) async -> Data?) async -> Data {
        do {
            var r = SSHReader(data); let type = try r.byte()
            switch type {
            case 11:
                guard r.remaining == 0 else { return Data([5]) }
                let keys = await identities(); var w = SSHWriter(); w.byte(12); w.uint32(UInt32(keys.count))
                for key in keys { w.string(key.blob); w.text(key.name) }; return w.data
            case 13:
                let blob = try r.string(), message = try r.string(), flags = try r.uint32(); guard r.remaining == 0 else { return Data([5]) }
                if !binding.bindings.isEmpty, SignContext.userAuth(message) != nil, binding.host(for: message) == nil { return Data([5]) }
                let context = SignContext(keyBlob: blob, data: message, flags: flags, host: binding.host(for: message), forwarded: binding.forwarded)
                guard let signature = await sign(context) else { return Data([5]) }
                var w = SSHWriter(); w.byte(14); w.string(signature); return w.data
            case 27:
                let extensionName = try r.text()
                guard extensionName == "session-bind@openssh.com" else { return Data([28]) }
                return Data([binding.bind(try r.bytes(r.remaining)) ? 6 : 5])
            default: return Data([5]) // add/remove/unlock requests from clients are never accepted.
            }
        } catch { return Data([5]) }
    }
}
