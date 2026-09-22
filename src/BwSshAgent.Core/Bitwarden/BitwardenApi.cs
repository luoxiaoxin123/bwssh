using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BwSshAgent.Core.Crypto;

namespace BwSshAgent.Core.Bitwarden;

public sealed class BitwardenApiException(string message, HttpStatusCode? status = null) : Exception(message)
{
    public HttpStatusCode? Status { get; } = status;
}

public sealed record PreloginResult(KdfConfig Kdf, string Salt);

public sealed record TokenResult(
    string AccessToken,
    DateTimeOffset ExpiresAt,
    string? RefreshToken,
    string? TwoFactorRememberToken,
    string? EncUserKey);

public enum TwoFactorProvider
{
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

public abstract record TokenOutcome
{
    public sealed record Success(TokenResult Token) : TokenOutcome;
    public sealed record TwoFactorRequired(IReadOnlyList<TwoFactorProvider> Providers, string? EmailHint, string? SsoEmail2FaSessionToken) : TokenOutcome;
    public sealed record NewDeviceVerificationRequired : TokenOutcome;
    public sealed record Failed(string Message) : TokenOutcome;
}

/// <summary>Minimal Bitwarden identity + API client (read-only).</summary>
public sealed class BitwardenApi : IDisposable
{
    public const string ClientName = "desktop";
    public const string ClientVersion = "2026.9.1";
    public const string DeviceType = "6"; // WindowsDesktop

    private readonly HttpClient _http;

    public BitwardenApi(HttpMessageHandler? handler = null)
    {
        _http = handler == null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromSeconds(60);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.Add("Device-Type", DeviceType);
        _http.DefaultRequestHeaders.Add("Bitwarden-Client-Name", ClientName);
        _http.DefaultRequestHeaders.Add("Bitwarden-Client-Version", ClientVersion);
    }

    public async Task<PreloginResult> PreloginAsync(ServerEnvironment env, string email, CancellationToken ct = default)
    {
        var body = JsonContent(new JsonObject { ["email"] = email });
        using var response = await _http.PostAsync(env.IdentityUrl + "/accounts/prelogin/password", body, ct);
        if (response.IsSuccessStatusCode)
        {
            var json = await ReadJsonAsync(response, ct);
            var settings = J.Get(json, "KdfSettings");
            var salt = J.Str(json, "Salt");
            if (settings != null)
            {
                return new PreloginResult(ParseKdf(settings, "KdfType", "Iterations", "Memory", "Parallelism"),
                    string.IsNullOrEmpty(salt) ? KeyDerivation.NormalizeEmailSalt(email) : salt);
            }
        }
        else if (response.StatusCode is not (HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed))
        {
            throw await ErrorAsync(response, ct);
        }

        // Older servers and Vaultwarden.
        body = JsonContent(new JsonObject { ["email"] = email });
        using var legacy = await _http.PostAsync(env.IdentityUrl + "/accounts/prelogin", body, ct);
        if (!legacy.IsSuccessStatusCode)
        {
            throw await ErrorAsync(legacy, ct);
        }
        var legacyJson = await ReadJsonAsync(legacy, ct);
        return new PreloginResult(ParseKdf(legacyJson, "Kdf", "KdfIterations", "KdfMemory", "KdfParallelism"), KeyDerivation.NormalizeEmailSalt(email));
    }

    public static KdfConfig ParseKdf(JsonNode? node, string typeName, string iterName, string memName, string parName)
    {
        var type = J.Int(node, typeName) ?? 0;
        var iterations = J.Int(node, iterName) ?? throw new BitwardenApiException(L.T("服务器未返回 KDF 参数。", "The server did not return KDF parameters."));
        return new KdfConfig((KdfType)type, iterations, J.Int(node, memName), J.Int(node, parName));
    }

    public Task<TokenOutcome> PasswordTokenAsync(ServerEnvironment env, string email, string passwordHash, string deviceId,
        TwoFactorProvider? provider, string? twoFactorToken, bool remember, string? newDeviceOtp, CancellationToken ct = default)
    {
        var form = BaseForm(deviceId);
        form["grant_type"] = "password";
        form["username"] = email;
        form["password"] = passwordHash;
        form["scope"] = "api offline_access";
        form["client_id"] = ClientName;
        AddTwoFactor(form, provider, twoFactorToken, remember);
        if (!string.IsNullOrEmpty(newDeviceOtp))
        {
            form["newDeviceOtp"] = newDeviceOtp;
        }
        var authEmail = Convert.ToBase64String(Encoding.UTF8.GetBytes(email)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return TokenAsync(env, form, authEmail, ct);
    }

    public Task<TokenOutcome> ApiKeyTokenAsync(ServerEnvironment env, string clientId, string clientSecret, string deviceId, CancellationToken ct = default)
    {
        var form = BaseForm(deviceId);
        form["grant_type"] = "client_credentials";
        form["scope"] = "api";
        form["client_id"] = clientId;
        form["client_secret"] = clientSecret;
        return TokenAsync(env, form, null, ct);
    }

    public async Task<TokenResult> RefreshAsync(ServerEnvironment env, string refreshToken, CancellationToken ct = default)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = ClientName,
            ["refresh_token"] = refreshToken,
        };
        var outcome = await TokenAsync(env, form, null, ct);
        return outcome switch
        {
            TokenOutcome.Success s => s.Token with { RefreshToken = s.Token.RefreshToken ?? refreshToken },
            TokenOutcome.Failed f => throw new BitwardenApiException(f.Message, HttpStatusCode.Unauthorized),
            _ => throw new BitwardenApiException(L.T("刷新登录令牌失败，请重新登录。", "Could not refresh the session, please sign in again."), HttpStatusCode.Unauthorized),
        };
    }

    public async Task SendEmailLoginCodeAsync(ServerEnvironment env, string email, string passwordHash, string deviceId, string? ssoSessionToken, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["email"] = email,
            ["masterPasswordHash"] = passwordHash,
            ["deviceIdentifier"] = deviceId,
        };
        if (ssoSessionToken != null)
        {
            body["ssoEmail2FaSessionToken"] = ssoSessionToken;
        }
        using var response = await _http.PostAsync(env.ApiUrl + "/two-factor/send-email-login", JsonContent(body), ct);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct);
        }
    }

    public async Task<string> GetSyncJsonAsync(ServerEnvironment env, string accessToken, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, env.ApiUrl + "/sync?excludeDomains=true");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct);
        }
        return await response.Content.ReadAsStringAsync(ct);
    }

    public Task CreateCipherAsync(ServerEnvironment env, string accessToken, JsonObject request, CancellationToken ct = default) =>
        SendAuthorizedAsync(HttpMethod.Post, env.ApiUrl + "/ciphers", accessToken, request, ct);

    public Task UpdateCipherAsync(ServerEnvironment env, string accessToken, string id, JsonObject request, CancellationToken ct = default) =>
        SendAuthorizedAsync(HttpMethod.Put, env.ApiUrl + "/ciphers/" + Uri.EscapeDataString(id), accessToken, request, ct);

    /// <summary>Moves the item to the trash (soft delete); it can be restored from the web vault.</summary>
    public Task SoftDeleteCipherAsync(ServerEnvironment env, string accessToken, string id, CancellationToken ct = default) =>
        SendAuthorizedAsync(HttpMethod.Put, env.ApiUrl + "/ciphers/" + Uri.EscapeDataString(id) + "/delete", accessToken, null, ct);

    private async Task SendAuthorizedAsync(HttpMethod method, string url, string accessToken, JsonObject? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (body != null)
        {
            request.Content = JsonContent(body);
        }
        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct);
        }
    }

    private static Dictionary<string, string> BaseForm(string deviceId) => new()
    {
        ["deviceType"] = DeviceType,
        ["deviceIdentifier"] = deviceId,
        ["deviceName"] = "windows",
    };

    private static void AddTwoFactor(Dictionary<string, string> form, TwoFactorProvider? provider, string? token, bool remember)
    {
        if (provider != null && !string.IsNullOrEmpty(token))
        {
            form["twoFactorToken"] = token;
            form["twoFactorProvider"] = ((int)provider.Value).ToString();
            form["twoFactorRemember"] = remember ? "1" : "0";
        }
    }

    private async Task<TokenOutcome> TokenAsync(ServerEnvironment env, Dictionary<string, string> form, string? authEmail, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, env.IdentityUrl + "/connect/token")
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (authEmail != null)
        {
            request.Headers.Add("Auth-Email", authEmail);
        }
        using var response = await _http.SendAsync(request, ct);
        JsonNode? json = null;
        try
        {
            json = await ReadJsonAsync(response, ct);
        }
        catch (JsonException)
        {
        }

        if (response.IsSuccessStatusCode && json != null)
        {
            var access = J.Str(json, "access_token") ?? throw new BitwardenApiException(L.T("服务器未返回 access_token。", "The server did not return an access token."));
            var expiresIn = J.Int(json, "expires_in") ?? 3600;
            return new TokenOutcome.Success(new TokenResult(
                access,
                DateTimeOffset.UtcNow.AddSeconds(expiresIn),
                J.Str(json, "refresh_token"),
                J.Str(json, "TwoFactorToken"),
                J.Str(json, "Key")));
        }

        if (response.StatusCode == HttpStatusCode.BadRequest && json != null)
        {
            if (J.Get(json, "TwoFactorProviders2") is JsonObject providers && providers.Count > 0)
            {
                var list = new List<TwoFactorProvider>();
                string? emailHint = null;
                foreach (var kv in providers)
                {
                    if (int.TryParse(kv.Key, out var p))
                    {
                        list.Add((TwoFactorProvider)p);
                        if (p == (int)TwoFactorProvider.Email)
                        {
                            emailHint = J.Str(kv.Value, "Email");
                        }
                    }
                }
                return new TokenOutcome.TwoFactorRequired(list, emailHint, J.Str(json, "SsoEmail2faSessionToken"));
            }

            var message = J.Str(J.Get(json, "ErrorModel"), "Message");
            if (string.Equals(message, "new device verification required", StringComparison.OrdinalIgnoreCase))
            {
                return new TokenOutcome.NewDeviceVerificationRequired();
            }
        }

        return new TokenOutcome.Failed(ExtractError(json) ?? L.T($"登录失败 (HTTP {(int)response.StatusCode})。", $"Sign-in failed (HTTP {(int)response.StatusCode})."));
    }

    private static string? ExtractError(JsonNode? json)
    {
        if (json == null)
        {
            return null;
        }
        var model = J.Get(json, "ErrorModel");
        var message = J.Str(model, "Message") ?? J.Str(json, "message") ?? J.Str(json, "error_description") ?? J.Str(json, "error");
        if (message == "invalid_username_or_password")
        {
            return L.T("邮箱或主密码不正确。", "Incorrect email or master password.");
        }
        return message;
    }

    private static async Task<BitwardenApiException> ErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        string? message = null;
        try
        {
            message = ExtractError(await ReadJsonAsync(response, ct));
        }
        catch (Exception)
        {
        }
        return new BitwardenApiException(message ?? L.T($"服务器返回错误 HTTP {(int)response.StatusCode}。", $"Server error HTTP {(int)response.StatusCode}."), response.StatusCode);
    }

    private static async Task<JsonNode?> ReadJsonAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var text = await response.Content.ReadAsStringAsync(ct);
        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }

    private static StringContent JsonContent(JsonNode node) =>
        new(node.ToJsonString(), Encoding.UTF8, "application/json");

    public void Dispose() => _http.Dispose();
}
