import Foundation
import Combine
import BwCore

@MainActor final class UpdateStatus: ObservableObject {
    @Published private(set) var available: ReleaseUpdate?
    let currentVersion: String
    private var checked = false
    init(currentVersion: String? = nil) {
        self.currentVersion = currentVersion ?? (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0")
    }
    func check() async -> ReleaseUpdate? {
        guard !checked else { return nil }; checked = true
        available = await ReleaseChecker().check(currentVersion: currentVersion)
        return available
    }
    #if DEBUG
    func showPreview() {
        // Synthetic UI state, not a claim that this version has been published.
        available = ReleaseUpdate(version: "0.3.1", url: ReleaseUpdate.latestURL)
        checked = true
    }
    #endif
}
