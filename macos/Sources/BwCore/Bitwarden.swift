import Foundation

typealias Object = [String: Any]
extension Dictionary where Key == String, Value == Any {
    func field(_ key: String) -> Any? { self.first(where: { $0.key.caseInsensitiveCompare(key) == .orderedSame })?.value }
    func text(_ key: String) -> String? { field(key) as? String }
    func number(_ key: String) -> Int? { field(key) as? Int }
    func object(_ key: String) -> Object { field(key) as? Object ?? [:] }
    func objects(_ key: String) -> [Object] { field(key) as? [Object] ?? [] }
    func kdf(modern: Bool) throws -> KDF {
        guard let iterations = number(modern ? "iterations" : "kdfIterations") else { throw BwError("Missing KDF parameters") }
        return KDF(type: number(modern ? "kdfType" : "kdf") ?? 0, iterations: iterations, memory: number(modern ? "memory" : "kdfMemory") ?? 64, parallelism: number(modern ? "parallelism" : "kdfParallelism") ?? 4)
    }
}

public struct Server: Codable, Equatable {
    public var base: String
    public init(_ base: String = "https://bitwarden.com") throws {
        var value = base.trimmingCharacters(in: .whitespacesAndNewlines)
        if !value.contains("://") { value = "https://" + value }
        while value.hasSuffix("/") { value.removeLast() }
        guard let url = URL(string: value), url.scheme == "https", url.host != nil, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil else { throw BwError(tr("请输入有效的 HTTPS 服务器地址。", "Enter a valid HTTPS server URL.")) }
        self.base = value
    }
    public var identity: String {
        base == "https://bitwarden.com" ? "https://identity.bitwarden.com" : base == "https://bitwarden.eu" ? "https://identity.bitwarden.eu" : base + "/identity"
    }
    public var api: String {
        base == "https://bitwarden.com" ? "https://api.bitwarden.com" : base == "https://bitwarden.eu" ? "https://api.bitwarden.eu" : base + "/api"
    }
}

public struct Account: Codable {
    public var server: Server
    public var email: String
    public var salt: String
    public var kdf: KDF
    public var accessToken: String
    public var refreshToken: String?
    public var expires: Date
    public var encryptedUserKey: String
    public var userID: String
    public var snapshot: Data
    public var syncedAt: Date
    public var apiClientID: String? = nil
    public var apiClientSecret: String? = nil
}

public struct LoginChallenge: Error, LocalizedError {
    public let providers: [Int]
    public let newDevice: Bool
    public let session: String?
    public let errorDescription: String? = tr("需要两步验证或新设备验证码。", "Two-factor authentication or a new-device code is required.")
}

public final class BitwardenAPI {
    private let session: URLSession
    public init(session: URLSession = .shared) { self.session = session }
    private func request(_ url: String, method: String = "POST", json: Object? = nil, form: [String: String]? = nil, token: String? = nil, authEmail: String? = nil) async throws -> Object {
        guard let url = URL(string: url) else { throw BwError("Invalid URL") }
        var request = URLRequest(url: url, timeoutInterval: 60); request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("7", forHTTPHeaderField: "Device-Type") // MacOsDesktop
        request.setValue("desktop", forHTTPHeaderField: "Bitwarden-Client-Name")
        request.setValue("2026.9.1", forHTTPHeaderField: "Bitwarden-Client-Version")
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        if let authEmail { request.setValue(authEmail, forHTTPHeaderField: "Auth-Email") }
        if let json { request.httpBody = try JSONSerialization.data(withJSONObject: json); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let form {
            let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
            request.httpBody = Data(form.sorted(by: { $0.key < $1.key }).map { "\($0.key.addingPercentEncoding(withAllowedCharacters: allowed)!)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed)!)" }.joined(separator: "&").utf8)
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw BwError("Invalid server response") }
        let object = (try? JSONSerialization.jsonObject(with: data)) as? Object ?? [:]
        guard (200..<300).contains(http.statusCode) else {
            let message = object.object("ErrorModel").text("Message") ?? object.text("error_description") ?? object.text("message") ?? object.text("error") ?? "HTTP \(http.statusCode)"
            let providers = object.object("TwoFactorProviders2").keys.compactMap(Int.init)
            if !providers.isEmpty || message.lowercased() == "new device verification required" {
                throw LoginChallenge(providers: providers, newDevice: providers.isEmpty, session: object.text("SsoEmail2faSessionToken"))
            }
            throw HTTPError(status: http.statusCode, message: message)
        }; return object
    }
    struct HTTPError: LocalizedError { let status: Int; let message: String; var errorDescription: String? { message } }
    public func prelogin(server: Server, email: String) async throws -> (KDF, String) {
        do {
            let result = try await request(server.identity + "/accounts/prelogin/password", json: ["email": email])
            if !result.object("kdfSettings").isEmpty { return (try result.object("kdfSettings").kdf(modern: true), result.text("salt") ?? email.lowercased()) }
        } catch let error as HTTPError where error.status == 404 || error.status == 405 {
            // Older Bitwarden and Vaultwarden installations use the legacy endpoint below.
        }
        let result = try await request(server.identity + "/accounts/prelogin", json: ["email": email])
        return (try result.kdf(modern: false), email.lowercased())
    }
    public func login(server: Server, email: String, password: String, provider: Int?, code: String, newDeviceOTP: String, clientID: String, clientSecret: String) async throws -> (Account, Secret) {
        let (kdf, salt) = try await prelogin(server: server, email: email)
        var master = try await Task.detached { try kdf.derive(password: password, salt: salt) }.value
        defer { master.wipe() }
        var form = ["deviceType": "7", "deviceIdentifier": Self.deviceID, "deviceName": "macos", "client_id": "desktop"]
        if clientID.isEmpty {
            form["grant_type"] = "password"; form["username"] = email; form["scope"] = "api offline_access"
            form["password"] = try Crypto.pbkdf(master, salt: Data(password.utf8), rounds: 1).base64EncodedString()
            if let provider, !code.isEmpty { form["twoFactorProvider"] = String(provider); form["twoFactorToken"] = code; form["twoFactorRemember"] = "0" }
            if !newDeviceOTP.isEmpty { form["newDeviceOtp"] = newDeviceOTP }
        } else {
            form["grant_type"] = "client_credentials"; form["client_id"] = clientID; form["client_secret"] = clientSecret; form["scope"] = "api"
        }
        let authEmail = Data(email.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let token = try await request(server.identity + "/connect/token", form: form, authEmail: clientID.isEmpty ? authEmail : nil)
        guard let access = token.text("access_token") else { throw BwError("Missing access token") }
        let sync = try await request(server.api + "/sync?excludeDomains=true", method: "GET", token: access)
        let profile = sync.object("profile"), unlock = sync.object("userDecryption").object("masterPasswordUnlock")
        guard let encrypted = token.text("key") ?? profile.text("key") ?? unlock.text("masterKeyEncryptedUserKey") else { throw BwError("Missing encrypted user key") }
        var userKey = try Crypto.decryptUserKey(encrypted, master: master); defer { userKey.wipe() }
        guard userKey.count == 64 || userKey.count == 32 else { throw BwError("Invalid user key") }
        var account = Account(server: server, email: email, salt: salt, kdf: kdf, accessToken: access, refreshToken: token.text("refresh_token"),
            expires: Date().addingTimeInterval(Double(token.number("expires_in") ?? 3600)), encryptedUserKey: encrypted,
            userID: profile.text("id") ?? "", snapshot: try JSONSerialization.data(withJSONObject: sync), syncedAt: Date())
        if !clientID.isEmpty { account.apiClientID = clientID; account.apiClientSecret = clientSecret }
        return (account, Secret(userKey))
    }
    public func sendEmailCode(server: Server, email: String, password: String, challengeSession: String?) async throws {
        let (kdf, salt) = try await prelogin(server: server, email: email)
        var master = try await Task.detached { try kdf.derive(password: password, salt: salt) }.value; defer { master.wipe() }
        var body: Object = ["email": email, "masterPasswordHash": try Crypto.pbkdf(master, salt: Data(password.utf8), rounds: 1).base64EncodedString(), "deviceIdentifier": Self.deviceID]
        if let challengeSession { body["ssoEmail2FaSessionToken"] = challengeSession }
        _ = try await request(server.api + "/two-factor/send-email-login", json: body)
    }
    public func refreshed(_ account: Account) async throws -> Account {
        guard account.expires.timeIntervalSinceNow < 120 else { return account }
        let form: [String: String]
        if let refresh = account.refreshToken { form = ["grant_type": "refresh_token", "client_id": "desktop", "refresh_token": refresh] }
        else if let client = account.apiClientID, let secret = account.apiClientSecret {
            form = ["grant_type": "client_credentials", "client_id": client, "client_secret": secret, "scope": "api", "deviceType": "7", "deviceIdentifier": Self.deviceID, "deviceName": "macos"]
        } else { throw BwError(tr("登录已过期，请重新登录。", "Session expired. Sign in again.")) }
        let token = try await request(account.server.identity + "/connect/token", form: form)
        guard let access = token.text("access_token") else { throw BwError("Missing access token") }
        var updated = account; updated.accessToken = access; updated.refreshToken = token.text("refresh_token") ?? account.refreshToken
        updated.expires = Date().addingTimeInterval(Double(token.number("expires_in") ?? 3600)); return updated
    }
    public func sync(_ account: Account) async throws -> Account {
        var account = try await refreshed(account)
        let sync = try await request(account.server.api + "/sync?excludeDomains=true", method: "GET", token: account.accessToken)
        account.snapshot = try JSONSerialization.data(withJSONObject: sync); account.syncedAt = Date()
        let unlock = sync.object("userDecryption").object("masterPasswordUnlock")
        account.encryptedUserKey = sync.object("profile").text("key") ?? unlock.text("masterKeyEncryptedUserKey") ?? account.encryptedUserKey
        if !unlock.object("kdf").isEmpty { account.kdf = try unlock.object("kdf").kdf(modern: true) }
        account.salt = unlock.text("salt") ?? account.salt
        return account
    }
    func mutate(_ account: Account, method: String, path: String, body: Object?) async throws {
        _ = try await request(account.server.api + path, method: method, json: body, token: account.accessToken)
    }
    private static var deviceID: String {
        if let id = UserDefaults.standard.string(forKey: "deviceID") { return id }
        let id = UUID().uuidString.lowercased(); UserDefaults.standard.set(id, forKey: "deviceID"); return id
    }
}
