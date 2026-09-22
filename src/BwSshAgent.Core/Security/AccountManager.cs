using System.Net;
using System.Security.Cryptography;
using BwSshAgent.Core.Bitwarden;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Ssh;

namespace BwSshAgent.Core.Security;

public abstract record LoginStep
{
    public sealed record Done : LoginStep;
    public sealed record TwoFactor(IReadOnlyList<TwoFactorProvider> Providers, string? EmailHint) : LoginStep;
    public sealed record NewDeviceOtp : LoginStep;
    public sealed record Error(string Message) : LoginStep;
}

/// <summary>Login (master password / API key, 2FA, new device verification), token refresh and sync.</summary>
public sealed class AccountManager : IDisposable
{
    private readonly BitwardenApi _api;
    private readonly VaultSession _session;
    private readonly SemaphoreSlim _syncGate = new(1, 1);
    private PendingLogin? _pending;

    private sealed class PendingLogin : IDisposable
    {
        public required ServerEnvironment Env { get; init; }
        public required string Email { get; init; }
        public required byte[] MasterKey { get; init; }
        public required string PasswordHash { get; init; }
        public required KdfConfig Kdf { get; init; }
        public required string Salt { get; init; }
        public string? SsoEmailSessionToken { get; set; }
        public TwoFactorProvider? Provider { get; set; }
        public string? TwoFactorCode { get; set; }
        public bool Remember { get; set; }

        public void Dispose() => CryptographicOperations.ZeroMemory(MasterKey);
    }

    public AccountManager(VaultSession session, BitwardenApi? api = null)
    {
        _session = session;
        _api = api ?? new BitwardenApi();
    }

    public bool Syncing { get; private set; }
    public DateTimeOffset? LastSync => _session.Snapshot?.SyncedAt;
    public string? LastSyncError { get; private set; }

    public event Action? SyncStateChanged;

    public async Task<LoginStep> LoginWithPasswordAsync(ServerEnvironment env, string email, string password, CancellationToken ct = default)
    {
        ClearPending();
        email = email.Trim();
        try
        {
            var prelogin = await _api.PreloginAsync(env, email, ct);
            var masterKey = await Task.Run(() => KeyDerivation.DeriveMasterKey(password, prelogin.Salt, prelogin.Kdf), ct);
            _pending = new PendingLogin
            {
                Env = env,
                Email = email,
                MasterKey = masterKey,
                PasswordHash = KeyDerivation.HashMasterPassword(masterKey, password),
                Kdf = prelogin.Kdf,
                Salt = prelogin.Salt,
            };

            var remembered = AccountStore.GetTwoFactorRemember(env, email);
            if (remembered != null)
            {
                var outcome = await _api.PasswordTokenAsync(env, email, _pending.PasswordHash, AccountStore.DeviceId,
                    TwoFactorProvider.Remember, remembered, false, null, ct);
                if (outcome is TokenOutcome.TwoFactorRequired)
                {
                    AccountStore.SetTwoFactorRemember(env, email, null);
                }
                else
                {
                    return await HandleOutcomeAsync(outcome, ct);
                }
            }
            return await RequestTokenAsync(null, ct);
        }
        catch (Exception ex) when (ex is BitwardenApiException or HttpRequestException or TaskCanceledException or CryptographicException)
        {
            ClearPending();
            return new LoginStep.Error(FriendlyError(ex));
        }
    }

    public async Task<LoginStep> SubmitTwoFactorAsync(TwoFactorProvider provider, string code, bool remember, CancellationToken ct = default)
    {
        if (_pending == null)
        {
            return new LoginStep.Error(L.T("登录会话已失效，请重新登录。", "The sign-in session expired, please start again."));
        }
        _pending.Provider = provider;
        _pending.TwoFactorCode = code.Trim().Replace(" ", "");
        _pending.Remember = remember;
        return await RequestTokenAsync(null, ct);
    }

    public async Task<LoginStep> SubmitNewDeviceOtpAsync(string otp, CancellationToken ct = default)
    {
        if (_pending == null)
        {
            return new LoginStep.Error(L.T("登录会话已失效，请重新登录。", "The sign-in session expired, please start again."));
        }
        return await RequestTokenAsync(otp.Trim(), ct);
    }

    public async Task<string?> SendEmailCodeAsync(CancellationToken ct = default)
    {
        if (_pending == null)
        {
            return L.T("登录会话已失效，请重新登录。", "The sign-in session expired, please start again.");
        }
        try
        {
            await _api.SendEmailLoginCodeAsync(_pending.Env, _pending.Email, _pending.PasswordHash, AccountStore.DeviceId, _pending.SsoEmailSessionToken, ct);
            return null;
        }
        catch (Exception ex) when (ex is BitwardenApiException or HttpRequestException or TaskCanceledException)
        {
            return FriendlyError(ex);
        }
    }

    public async Task<LoginStep> LoginWithApiKeyAsync(ServerEnvironment env, string clientId, string clientSecret, string password, CancellationToken ct = default)
    {
        ClearPending();
        clientId = clientId.Trim();
        clientSecret = clientSecret.Trim();
        try
        {
            var outcome = await _api.ApiKeyTokenAsync(env, clientId, clientSecret, AccountStore.DeviceId, ct);
            if (outcome is not TokenOutcome.Success success)
            {
                return outcome is TokenOutcome.Failed f ? new LoginStep.Error(f.Message) : new LoginStep.Error(L.T("API Key 登录失败。", "API key sign-in failed."));
            }
            var syncJson = await _api.GetSyncJsonAsync(env, success.Token.AccessToken, ct);
            var snapshot = VaultSnapshot.FromSyncJson(syncJson);
            var prelogin = snapshot.Kdf != null && snapshot.Salt != null
                ? new PreloginResult(snapshot.Kdf, snapshot.Salt)
                : await _api.PreloginAsync(env, snapshot.Email, ct);
            var masterKey = await Task.Run(() => KeyDerivation.DeriveMasterKey(password, prelogin.Salt, prelogin.Kdf), ct);
            SymmetricKey userKey;
            try
            {
                userKey = KeyDerivation.DecryptUserKey(masterKey, snapshot.EncUserKey ?? throw new BitwardenApiException(L.T("同步数据中缺少用户密钥。", "The sync response has no user key.")));
            }
            catch (CryptographicException)
            {
                return new LoginStep.Error(L.T("主密码不正确。", "Incorrect master password."));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKey);
            }

            var account = new AccountState
            {
                Environment = env,
                Email = snapshot.Email,
                UserId = snapshot.UserId,
                Kdf = prelogin.Kdf,
                Salt = prelogin.Salt,
                AccessToken = success.Token.AccessToken,
                AccessTokenExpiry = success.Token.ExpiresAt,
                ApiClientId = clientId,
                ApiClientSecret = clientSecret,
            };
            await _session.SetLoggedInAsync(account, snapshot, userKey);
            return new LoginStep.Done();
        }
        catch (Exception ex) when (ex is BitwardenApiException or HttpRequestException or TaskCanceledException or UnsupportedEncryptionException or UnlockException)
        {
            return new LoginStep.Error(FriendlyError(ex));
        }
    }

    private async Task<LoginStep> RequestTokenAsync(string? newDeviceOtp, CancellationToken ct)
    {
        var p = _pending!;
        try
        {
            var outcome = await _api.PasswordTokenAsync(p.Env, p.Email, p.PasswordHash, AccountStore.DeviceId,
                p.Provider, p.TwoFactorCode, p.Remember, newDeviceOtp, ct);
            return await HandleOutcomeAsync(outcome, ct);
        }
        catch (Exception ex) when (ex is BitwardenApiException or HttpRequestException or TaskCanceledException)
        {
            return new LoginStep.Error(FriendlyError(ex));
        }
    }

    private async Task<LoginStep> HandleOutcomeAsync(TokenOutcome outcome, CancellationToken ct)
    {
        var p = _pending!;
        switch (outcome)
        {
            case TokenOutcome.TwoFactorRequired tf:
                p.SsoEmailSessionToken = tf.SsoEmail2FaSessionToken;
                var usable = tf.Providers.Where(x => x is TwoFactorProvider.Authenticator or TwoFactorProvider.Email or TwoFactorProvider.YubiKey).ToList();
                if (usable.Count == 0)
                {
                    return new LoginStep.Error(L.T("此账户只启用了本客户端不支持的两步验证方式（Duo / WebAuthn 等）。请在账户中额外启用验证器 App 或邮件验证。", "This account only has two-step methods this app does not support (Duo, WebAuthn...). Enable an authenticator app or email as well."));
                }
                if (p.Provider != null && p.TwoFactorCode != null)
                {
                    p.TwoFactorCode = null;
                    return new LoginStep.Error(L.T("验证码不正确，请重试。", "Incorrect code, please try again."));
                }
                return new LoginStep.TwoFactor(usable, tf.EmailHint);

            case TokenOutcome.NewDeviceVerificationRequired:
                return new LoginStep.NewDeviceOtp();

            case TokenOutcome.Failed f:
                return new LoginStep.Error(f.Message);

            case TokenOutcome.Success s:
                return await CompleteLoginAsync(s.Token, ct);
        }
        return new LoginStep.Error(L.T("未知的登录响应。", "Unexpected sign-in response."));
    }

    private async Task<LoginStep> CompleteLoginAsync(TokenResult token, CancellationToken ct)
    {
        var p = _pending!;
        if (p.Remember && token.TwoFactorRememberToken != null)
        {
            AccountStore.SetTwoFactorRemember(p.Env, p.Email, token.TwoFactorRememberToken);
        }

        var syncJson = await _api.GetSyncJsonAsync(p.Env, token.AccessToken, ct);
        var snapshot = VaultSnapshot.FromSyncJson(syncJson);
        SymmetricKey userKey;
        try
        {
            userKey = KeyDerivation.DecryptUserKey(p.MasterKey, snapshot.EncUserKey ?? token.EncUserKey
                ?? throw new BitwardenApiException(L.T("服务器未返回用户密钥。", "The server did not return a user key.")));
        }
        catch (UnsupportedEncryptionException ex)
        {
            return new LoginStep.Error(ex.Message);
        }

        var account = new AccountState
        {
            Environment = p.Env,
            Email = string.IsNullOrEmpty(snapshot.Email) ? p.Email : snapshot.Email,
            UserId = snapshot.UserId,
            Kdf = p.Kdf,
            Salt = p.Salt,
            AccessToken = token.AccessToken,
            AccessTokenExpiry = token.ExpiresAt,
            RefreshToken = token.RefreshToken,
        };
        ClearPending();
        await _session.SetLoggedInAsync(account, snapshot, userKey);
        return new LoginStep.Done();
    }

    public void CancelLogin() => ClearPending();

    private void ClearPending()
    {
        _pending?.Dispose();
        _pending = null;
    }

    /// <summary>Downloads /sync. Works while locked: data stays encrypted until the next unlock.</summary>
    public async Task<bool> SyncAsync(CancellationToken ct = default)
    {
        var account = _session.Account;
        if (account == null || account.NeedsReauth)
        {
            return false;
        }
        if (!await _syncGate.WaitAsync(0, ct))
        {
            return false;
        }
        Syncing = true;
        SyncStateChanged?.Invoke();
        try
        {
            var token = await EnsureAccessTokenAsync(account, forceRefresh: false, ct);
            string json;
            try
            {
                json = await _api.GetSyncJsonAsync(account.Environment, token, ct);
            }
            catch (BitwardenApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
            {
                token = await EnsureAccessTokenAsync(account, forceRefresh: true, ct);
                json = await _api.GetSyncJsonAsync(account.Environment, token, ct);
            }
            var snapshot = VaultSnapshot.FromSyncJson(json);
            if (!string.Equals(snapshot.UserId, account.UserId, StringComparison.OrdinalIgnoreCase))
            {
                throw new BitwardenApiException(L.T("同步返回了不同的用户。", "Sync returned a different user."));
            }
            _session.ApplySnapshot(snapshot);
            LastSyncError = null;
            Log.Info($"Sync complete: {snapshot.SshCiphers.Count} SSH item(s)");
            return true;
        }
        catch (Exception ex) when (ex is BitwardenApiException or HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            LastSyncError = FriendlyError(ex);
            Log.Warn("Sync failed: " + LastSyncError);
            return false;
        }
        finally
        {
            Syncing = false;
            _syncGate.Release();
            SyncStateChanged?.Invoke();
        }
    }

    /// <summary>Saves a new SSH key to the personal vault. Returns an error message, or null on success.</summary>
    public Task<string?> AddSshKeyAsync(string name, SshPrivateKey key, CancellationToken ct = default) =>
        WriteAsync(async (account, token, userKey) =>
        {
            var pem = SshKeyFactory.ToOpenSshPem(key);
            var request = CipherRequests.NewSshKey(account.UserId, userKey, name.Trim(), pem, key.PublicKeyLine(""), key.Fingerprint);
            await _api.CreateCipherAsync(account.Environment, token, request, ct);
            Log.Info("SSH key item created");
        }, ct);

    public Task<string?> RenameSshKeyAsync(string cipherId, string newName, CancellationToken ct = default) =>
        WriteAsync(async (account, token, userKey) =>
        {
            var snapshot = _session.Snapshot ?? throw new BitwardenApiException(L.T("本地没有密码库数据。", "No local vault data."));
            var cipher = snapshot.SshCiphers.FirstOrDefault(c => c.Id == cipherId) ?? throw new BitwardenApiException(L.T("找不到该条目，请先同步。", "Item not found, please sync first."));
            using var cipherKey = VaultDecryptor.ResolveCipherKey(snapshot, cipher, userKey);
            var request = CipherRequests.Rename(cipher, account.UserId, cipherKey, newName.Trim());
            await _api.UpdateCipherAsync(account.Environment, token, cipherId, request, ct);
            Log.Info("SSH key item renamed");
        }, ct);

    public Task<string?> DeleteSshKeyAsync(string cipherId, CancellationToken ct = default) =>
        WriteAsync(async (account, token, _) =>
        {
            await _api.SoftDeleteCipherAsync(account.Environment, token, cipherId, ct);
            Log.Info("SSH key item moved to trash");
        }, ct);

    private async Task<string?> WriteAsync(Func<AccountState, string, SymmetricKey, Task> action, CancellationToken ct)
    {
        var account = _session.Account;
        if (account == null)
        {
            return L.T("未登录。", "Not signed in.");
        }
        if (account.NeedsReauth)
        {
            return L.T("登录已过期，请先重新登录。", "Session expired, please sign in again.");
        }
        using var userKey = _session.CopyUserKey();
        if (userKey == null)
        {
            return L.T("请先解锁密码库。", "Unlock the vault first.");
        }
        try
        {
            var token = await EnsureAccessTokenAsync(account, forceRefresh: false, ct);
            try
            {
                await action(account, token, userKey);
            }
            catch (BitwardenApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
            {
                token = await EnsureAccessTokenAsync(account, forceRefresh: true, ct);
                await action(account, token, userKey);
            }
        }
        catch (Exception ex) when (ex is BitwardenApiException or HttpRequestException or TaskCanceledException or CryptographicException or InvalidOperationException)
        {
            return FriendlyError(ex);
        }
        await SyncAsync(ct);
        return null;
    }

    private async Task<string> EnsureAccessTokenAsync(AccountState account, bool forceRefresh, CancellationToken ct)
    {
        if (!forceRefresh && account.AccessToken != null && account.AccessTokenExpiry > DateTimeOffset.UtcNow.AddMinutes(2))
        {
            return account.AccessToken;
        }
        try
        {
            TokenResult token;
            if (account.ApiClientId != null && account.ApiClientSecret != null)
            {
                var outcome = await _api.ApiKeyTokenAsync(account.Environment, account.ApiClientId, account.ApiClientSecret, AccountStore.DeviceId, ct);
                token = outcome is TokenOutcome.Success s
                    ? s.Token
                    : throw new BitwardenApiException(outcome is TokenOutcome.Failed f ? f.Message : L.T("API Key 已失效。", "The API key is no longer valid."), HttpStatusCode.Unauthorized);
            }
            else if (account.RefreshToken != null)
            {
                token = await _api.RefreshAsync(account.Environment, account.RefreshToken, ct);
            }
            else
            {
                throw new BitwardenApiException(L.T("没有可用的刷新令牌。", "No refresh token available."), HttpStatusCode.Unauthorized);
            }
            account.AccessToken = token.AccessToken;
            account.AccessTokenExpiry = token.ExpiresAt;
            account.RefreshToken = token.RefreshToken ?? account.RefreshToken;
            _session.UpdateAccount(account);
            return token.AccessToken;
        }
        catch (BitwardenApiException ex) when (ex.Status is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest)
        {
            account.NeedsReauth = true;
            account.AccessToken = null;
            _session.UpdateAccount(account);
            throw new BitwardenApiException(L.T("登录已过期，需要重新登录才能同步（已缓存的密钥仍可使用）。", "Session expired. Sign in again to sync (cached keys still work)."));
        }
    }

    private static string FriendlyError(Exception ex) => ex switch
    {
        TaskCanceledException => L.T("连接服务器超时。", "Connection to the server timed out."),
        HttpRequestException h => L.T("无法连接服务器：", "Cannot reach the server: ") + h.Message,
        _ => ex.Message,
    };

    public void Dispose()
    {
        ClearPending();
        _api.Dispose();
    }
}
