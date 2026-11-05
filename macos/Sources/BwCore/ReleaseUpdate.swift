import Foundation

/// Version metadata only. No download, installation, or vault access.
public struct ReleaseUpdate: Equatable {
    public let version: String
    public let url: URL
    public static let latestURL = URL(string: "https://github.com/luoxiaoxin123/bwssh/releases/latest")!
    public init(version: String, url: URL) { self.version = version; self.url = url }

    private static func parsed(_ value: String) -> (parts: [Int], prerelease: Bool)? {
        let pattern = #"^[vV]?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)), match.range.length == value.utf16.count else { return nil }
        var parts: [Int] = []
        for index in 1...3 {
            guard let range = Range(match.range(at: index), in: value), let n = Int(value[range]), n <= Int(Int32.max) else { return nil }
            parts.append(n)
        }
        return (parts, match.range(at: 4).location != NSNotFound)
    }
    public static func fromJSON(_ data: Data, currentVersion: String) -> ReleaseUpdate? {
        struct Release: Decodable { let tag_name: String; let draft: Bool; let prerelease: Bool }
        guard let release = try? JSONDecoder().decode(Release.self, from: data), !release.draft, !release.prerelease,
              let latest = parsed(release.tag_name), !latest.prerelease, let current = parsed(currentVersion) else { return nil }
        let greater = current.parts.lexicographicallyPrecedes(latest.parts)
        guard greater || (latest.parts == current.parts && current.prerelease) else { return nil }
        let tag = release.tag_name
        let version = tag.first == "v" || tag.first == "V" ? String(tag.dropFirst()) : tag
        let url = URL(string: "https://github.com/luoxiaoxin123/bwssh/releases/tag/")!.appendingPathComponent(tag)
        return ReleaseUpdate(version: version, url: url)
    }
}

public struct ReleaseChecker {
    private let session: URLSession
    public init(session: URLSession = URLSession(configuration: .ephemeral)) { self.session = session }
    public func check(currentVersion: String) async -> ReleaseUpdate? {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/luoxiaoxin123/bwssh/releases/latest")!)
        request.timeoutInterval = 8
        request.setValue("bwssh", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await session.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
            return ReleaseUpdate.fromJSON(data, currentVersion: currentVersion)
        } catch { return nil }
    }
}
