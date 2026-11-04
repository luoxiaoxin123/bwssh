import Foundation

public enum SSHConfiguration {
    static let begin = "# >>> bwssh macOS >>>"
    static let end = "# <<< bwssh macOS <<<"
    public static func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func configQuote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
    static func removingBlock(_ config: String) throws -> String {
        guard let start = config.range(of: begin) else {
            guard !config.contains(end) else { throw BwError("Malformed bwssh SSH config block") }; return config
        }
        guard let finish = config.range(of: end, range: start.upperBound..<config.endIndex),
              !config[start.upperBound..<finish.lowerBound].contains(begin), !config[finish.upperBound...].contains(begin) else { throw BwError("Malformed bwssh SSH config block") }
        var after = finish.upperBound; if after < config.endIndex && config[after] == "\n" { after = config.index(after: after) }
        return String(config[..<start.lowerBound]) + String(config[after...])
    }
    public static func configured(_ original: String, executable: String, socket: String, onDemand: Bool) throws -> String {
        guard !executable.contains("\n"), !socket.contains("\n") else { throw BwError("Invalid executable or socket path") }
        let rest = try removingBlock(original)
        // IdentityAgent belongs to Host *, and Match all restores scope before the existing configuration.
        var block = "\(begin)\nHost *\n    IdentityAgent \(configQuote(socket.replacingOccurrences(of: "%", with: "%%")))\n"
        if onDemand {
            let command = shellQuote(executable.replacingOccurrences(of: "%", with: "%%")) + " --ensure-agent"
            block += "Match exec \(configQuote(command))\n"
        }
        block += "Match all\n\(end)\n"
        return block + rest
    }
    public static func install(executable: String, onDemand: Bool) throws {
        let ssh = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh", isDirectory: true)
        try Paths.prepare(ssh)
        let url = ssh.appendingPathComponent("config"); var info = stat()
        if lstat(url.path, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid() else { throw BwError("Refusing to replace a symlink or non-owned SSH config") }
        }
        let original = FileManager.default.fileExists(atPath: url.path) ? try String(contentsOf: url, encoding: .utf8) : ""
        let backup = ssh.appendingPathComponent("config.bwssh.bak")
        if !FileManager.default.fileExists(atPath: backup.path) { try Paths.write(Data(original.utf8), to: backup) }
        let result = try configured(original, executable: executable, socket: Paths.socket, onDemand: onDemand)
        try Paths.write(Data(result.utf8), to: url)
    }
    public static func uninstall() throws {
        let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
        var info = stat(); guard lstat(url.path, &info) == 0 else { return }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid() else { throw BwError("Unsafe SSH config") }
        let original = try String(contentsOf: url, encoding: .utf8)
        try Paths.write(Data(try removingBlock(original).utf8), to: url)
    }
}
