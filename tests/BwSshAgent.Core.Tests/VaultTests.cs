using System.Net;
using System.Security.Cryptography;
using System.Text;
using BwSshAgent.Core.Approval;
using BwSshAgent.Core.Audit;
using BwSshAgent.Core.Bitwarden;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Settings;
using BwSshAgent.Core.Ssh;

namespace BwSshAgent.Core.Tests;

public class VaultTests
{
    [Fact]
    public void SyncParsingFiltersAndDecryptsPersonalAndOrgKeys()
    {
        TestEnv.ResetAppData();
        var fx = new VaultFixture();
        var ed = TestEnv.GenerateKey("ed25519");
        var rsa = TestEnv.GenerateKey("rsa", 2048);
        var personalId = fx.AddPersonalKey("personal key", ed.PrivatePem);
        var orgId = fx.AddOrgKeyWithItemKey("org key", rsa.PrivatePem);
        fx.AddNoise(ed.PrivatePem);

        var snapshot = VaultSnapshot.FromSyncJson(fx.SyncJson());
        Assert.Equal(fx.UserId, snapshot.UserId);
        Assert.Equal(2, snapshot.SshCiphers.Count);
        Assert.Equal(VaultFixture.Kdf.Iterations, snapshot.Kdf!.Iterations);
        Assert.Equal(VaultFixture.Email, snapshot.Salt);

        var result = VaultDecryptor.DecryptSshKeys(snapshot, fx.UserKey);
        Assert.Empty(result.Errors);
        Assert.Equal("personal key", result.Items.Single(i => i.CipherId == personalId).Name);
        var org = result.Items.Single(i => i.CipherId == orgId);
        Assert.Equal("org key", org.Name);
        Assert.Equal(rsa.PrivatePem, Encoding.UTF8.GetString(org.PrivateKeyUtf8));
    }

    [Fact]
    public async Task MasterPasswordUnlockLockAndSign()
    {
        TestEnv.ResetAppData();
        var (session, fx, key) = await LoggedInSessionAsync();
        Assert.Equal(VaultState.Unlocked, session.State);
        var entry = Assert.Single(session.PublicKeys);
        Assert.Equal(key.PublicLine.Split(' ')[1], entry.BlobBase64);
        Assert.NotNull(session.Sign(entry.CipherId, "data"u8, 0));

        session.Lock("test");
        Assert.Equal(VaultState.Locked, session.State);
        Assert.Null(session.Sign(entry.CipherId, "data"u8, 0));
        Assert.Single(session.PublicKeys); // still listable while locked

        await Assert.ThrowsAsync<UnlockException>(() => session.UnlockWithMasterPasswordAsync("wrong password"));
        await session.UnlockWithMasterPasswordAsync(VaultFixture.Password);
        Assert.Equal(VaultState.Unlocked, session.State);

        // Restart: a fresh session loads the cached (encrypted) vault and public key list.
        var restarted = new VaultSession();
        restarted.Initialize();
        Assert.Equal(VaultState.Locked, restarted.State);
        Assert.Single(restarted.PublicKeys);
        await restarted.UnlockWithMasterPasswordAsync(VaultFixture.Password);
        Assert.NotNull(restarted.Sign(entry.CipherId, "data"u8, 0));
    }

    [Fact]
    public async Task EphemeralPinSurvivesLockButNotRestart()
    {
        TestEnv.ResetAppData();
        var (session, _, _) = await LoggedInSessionAsync();
        using (var uk = session.CopyUserKey()!)
        {
            await session.Pin.EnableAsync("2468", persistent: false, uk);
        }
        session.Lock("test");
        await session.UnlockWithPinAsync("2468");
        Assert.Equal(VaultState.Unlocked, session.State);

        var restarted = new VaultSession();
        restarted.Initialize();
        Assert.True(restarted.Pin.IsEnabled);
        Assert.False(restarted.Pin.IsAvailable);
        await Assert.ThrowsAsync<UnlockException>(() => restarted.UnlockWithPinAsync("2468"));
        await restarted.UnlockWithMasterPasswordAsync(VaultFixture.Password);
        Assert.True(restarted.Pin.IsAvailable);
        restarted.Lock("test");
        await restarted.UnlockWithPinAsync("2468");
        Assert.Equal(VaultState.Unlocked, restarted.State);
    }

    [Fact]
    public async Task PersistentPinWorksAfterRestartAndIsClearedAfterFiveFailures()
    {
        TestEnv.ResetAppData();
        var (session, _, _) = await LoggedInSessionAsync();
        using (var uk = session.CopyUserKey()!)
        {
            await session.Pin.EnableAsync("1357", persistent: true, uk);
        }
        var restarted = new VaultSession();
        restarted.Initialize();
        Assert.True(restarted.Pin.IsAvailable);
        await restarted.UnlockWithPinAsync("1357");
        restarted.Lock("test");

        for (var i = 1; i < PinProtector.MaxAttempts; i++)
        {
            var ex = await Assert.ThrowsAsync<UnlockException>(() => restarted.UnlockWithPinAsync("0000"));
            Assert.Contains((PinProtector.MaxAttempts - i).ToString(), ex.Message);
        }
        await Assert.ThrowsAsync<UnlockException>(() => restarted.UnlockWithPinAsync("0000"));
        Assert.False(restarted.Pin.IsEnabled);
        await Assert.ThrowsAsync<UnlockException>(() => restarted.UnlockWithPinAsync("1357"));
    }

    internal static async Task<(VaultSession Session, VaultFixture Fixture, (string PrivatePem, string PublicLine, string Path) Key)> LoggedInSessionAsync()
    {
        var fx = new VaultFixture();
        var key = TestEnv.GenerateKey("ed25519");
        fx.AddPersonalKey("github", key.PrivatePem);
        var session = new VaultSession();
        session.Initialize();
        var userKey = new SymmetricKey(fx.UserKey.ToBytes());
        await session.SetLoggedInAsync(fx.Account(), VaultSnapshot.FromSyncJson(fx.SyncJson()), userKey);
        return (session, fx, key);
    }
}

public class ApprovalPolicyTests
{
    private sealed class FakePresenter : IApprovalPresenter
    {
        public List<PendingApproval> Approvals { get; } = [];
        public List<PendingApproval> UnlockPrompts { get; } = [];
        public Action<PendingApproval>? OnApproval { get; set; }
        public Action<PendingApproval>? OnUnlock { get; set; }

        public void ShowApproval(PendingApproval request, int grantMinutes)
        {
            lock (Approvals)
            {
                Approvals.Add(request);
            }
            OnApproval?.Invoke(request);
        }

        public void ShowUnlockRequired(PendingApproval request)
        {
            UnlockPrompts.Add(request);
            OnUnlock?.Invoke(request);
        }

        public void ShowListUnlockRequired(string processChain)
        {
        }

        public void Dismiss(PendingApproval request)
        {
        }
    }

    private static async Task<(AgentService Agent, FakePresenter Presenter, VaultSession Session, AppSettings Settings, PublicKeyEntry Key)> SetupAsync(PromptMode mode)
    {
        TestEnv.ResetAppData();
        var (session, _, _) = await VaultTests.LoggedInSessionAsync();
        var settings = new AppSettings { PromptMode = mode };
        var agent = new AgentService(session, () => settings, new AuditLog());
        var presenter = new FakePresenter();
        agent.Presenter = presenter;
        return (agent, presenter, session, settings, session.PublicKeys.Single());
    }

    private static SignRequest Auth(PublicKeyEntry key, string host) => new()
    {
        KeyBlob = key.Blob,
        Data = RandomNumberGenerator.GetBytes(64),
        Kind = SignKind.SshAuth,
        HostFingerprint = host,
    };

    private static AgentClient Client(int rootPid = 100, string root = "claude.exe") =>
        new() { Pid = rootPid + 2, Chain = TestEnv.FakeChain(rootPid, root) };

    [Fact]
    public async Task AlwaysModePromptsEveryTime()
    {
        var (agent, presenter, _, _, key) = await SetupAsync(PromptMode.Always);
        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.Approve);
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:host"), default));
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:host"), default));
        Assert.Equal(2, presenter.Approvals.Count);
        Assert.Equal("claude.exe → git.exe → ssh.exe", presenter.Approvals[0].ProcessChain);
        Assert.Equal("git@github.com", presenter.Approvals[0].Destination);

        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.Deny);
        Assert.Null(await agent.SignAsync(Client(), Auth(key, "SHA256:host"), default));
    }

    [Fact]
    public async Task RememberUntilLockCachesPerHostAndClearsOnLock()
    {
        var (agent, presenter, session, _, key) = await SetupAsync(PromptMode.RememberUntilLock);
        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.Approve);
        await agent.SignAsync(Client(), Auth(key, "SHA256:a"), default);
        await agent.SignAsync(Client(200, "other.exe"), Auth(key, "SHA256:a"), default);
        Assert.Single(presenter.Approvals);

        await agent.SignAsync(Client(), Auth(key, "SHA256:b"), default);
        Assert.Equal(2, presenter.Approvals.Count);

        session.Lock("test");
        await session.UnlockWithMasterPasswordAsync(VaultFixture.Password);
        await agent.SignAsync(Client(), Auth(key, "SHA256:a"), default);
        Assert.Equal(3, presenter.Approvals.Count);
    }

    [Fact]
    public async Task NeverModeDoesNotPrompt()
    {
        var (agent, presenter, _, _, key) = await SetupAsync(PromptMode.Never);
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:x"), default));
        Assert.Empty(presenter.Approvals);
    }

    [Fact]
    public async Task ProcessGrantCoversSameProcessOnly()
    {
        var (agent, presenter, _, settings, key) = await SetupAsync(PromptMode.Always);
        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.ApproveForProcess);
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:a"), default));
        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.Deny);

        // Same claude.exe instance, different host and different ssh child: covered.
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:other"), default));
        Assert.Single(presenter.Approvals);
        Assert.Single(agent.ActiveGrants);

        // A different root process is not covered.
        Assert.Null(await agent.SignAsync(Client(300, "claude.exe"), Auth(key, "SHA256:a"), default));
        Assert.Equal(2, presenter.Approvals.Count);

        // Forwarded requests never match a grant.
        var forwarded = new SignRequest { KeyBlob = key.Blob, Data = [1], Kind = SignKind.SshAuth, IsForwarding = true, HostFingerprint = "SHA256:a" };
        Assert.Null(await agent.SignAsync(Client(), forwarded, default));
        Assert.Equal(3, presenter.Approvals.Count);
        Assert.Equal(15, settings.GrantMinutes);
    }

    [Fact]
    public async Task LockedRequestIsApprovedByUnlock()
    {
        var (agent, presenter, session, _, key) = await SetupAsync(PromptMode.Always);
        session.Lock("test");
        presenter.OnUnlock = p =>
        {
            agent.MarkUnlockRequested(p.Id);
            _ = session.UnlockWithMasterPasswordAsync(VaultFixture.Password);
        };
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:a"), default));
        Assert.Single(presenter.UnlockPrompts);
        Assert.Empty(presenter.Approvals);
    }

    [Fact]
    public async Task LockedRequestFallsBackToApprovalWhenUnlockedElsewhere()
    {
        var (agent, presenter, session, _, key) = await SetupAsync(PromptMode.Always);
        session.Lock("test");
        presenter.OnUnlock = p => _ = session.UnlockWithMasterPasswordAsync(VaultFixture.Password);
        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.Approve);
        Assert.NotNull(await agent.SignAsync(Client(), Auth(key, "SHA256:a"), default));
        Assert.Single(presenter.Approvals);
    }

    [Fact]
    public async Task UnknownKeysAreRefusedWithoutPrompt()
    {
        var (agent, presenter, _, _, _) = await SetupAsync(PromptMode.Always);
        var request = new SignRequest { KeyBlob = [1, 2, 3], Data = [1] };
        Assert.Null(await agent.SignAsync(Client(), request, default));
        Assert.Empty(presenter.Approvals);
    }

    [Fact]
    public async Task AuditRecordsDecisions()
    {
        var (agent, presenter, _, _, key) = await SetupAsync(PromptMode.Always);
        var audit = new AuditLog();
        presenter.OnApproval = p => agent.Respond(p.Id, UserChoice.Approve);
        await agent.SignAsync(Client(), Auth(key, "SHA256:a"), default);
        var entry = audit.ReadRecent().First();
        Assert.Equal("已批准", entry.Decision);
        Assert.Equal("SSH 登录", entry.Operation);
        Assert.Equal("github", entry.KeyName);
        Assert.Equal("git@github.com", entry.Destination);
        Assert.Equal("claude.exe", entry.GrantTarget);
    }
}

public class LoginFlowTests
{
    private sealed class FakeServer : HttpMessageHandler
    {
        public List<(string Path, string Body)> Requests { get; } = [];
        public required Func<string, string, (HttpStatusCode, string)> Respond { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content == null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((path, body));
            var (status, json) = Respond(path, body);
            return new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }

    [Fact]
    public async Task PasswordLoginWithAuthenticatorTwoFactorThenSync()
    {
        TestEnv.ResetAppData();
        var fx = new VaultFixture();
        var key = TestEnv.GenerateKey("ecdsa", 256);
        fx.AddPersonalKey("server", key.PrivatePem);
        var masterKey = KeyDerivation.DeriveMasterKey(VaultFixture.Password, VaultFixture.Email, VaultFixture.Kdf);
        var expectedHash = KeyDerivation.HashMasterPassword(masterKey, VaultFixture.Password);

        var server = new FakeServer
        {
            Respond = (path, body) => path switch
            {
                "/identity/accounts/prelogin/password" => (HttpStatusCode.NotFound, "{}"),
                "/identity/accounts/prelogin" => (HttpStatusCode.OK, $$"""{"kdf":0,"kdfIterations":{{VaultFixture.Kdf.Iterations}}}"""),
                "/identity/connect/token" when !body.Contains("twoFactorToken") =>
                    (HttpStatusCode.BadRequest, """{"error":"invalid_grant","TwoFactorProviders2":{"0":null,"7":{}}}"""),
                "/identity/connect/token" when body.Contains("twoFactorToken=123456") =>
                    (HttpStatusCode.OK, """{"access_token":"at","expires_in":3600,"refresh_token":"rt","TwoFactorToken":"remember-me"}"""),
                "/identity/connect/token" => (HttpStatusCode.BadRequest, """{"ErrorModel":{"Message":"Two-step token is invalid. Try again."}}"""),
                "/api/sync" => (HttpStatusCode.OK, fx.SyncJson()),
                _ => (HttpStatusCode.NotFound, "{}"),
            },
        };
        var session = new VaultSession();
        session.Initialize();
        using var manager = new AccountManager(session, new BitwardenApi(server));
        var env = ServerEnvironment.SelfHosted("vault.example.test");

        var step = await manager.LoginWithPasswordAsync(env, "  User@Example.com ", VaultFixture.Password);
        var tf = Assert.IsType<LoginStep.TwoFactor>(step);
        Assert.Equal(new[] { TwoFactorProvider.Authenticator }, tf.Providers);

        var tokenBody = server.Requests.Last(r => r.Path.EndsWith("/connect/token")).Body;
        Assert.Contains("grant_type=password", tokenBody);
        Assert.Contains("client_id=desktop", tokenBody);
        Assert.Contains("deviceType=6", tokenBody);
        Assert.Contains("password=" + Uri.EscapeDataString(expectedHash), tokenBody);

        step = await manager.SubmitTwoFactorAsync(TwoFactorProvider.Authenticator, "000000", remember: true);
        Assert.Contains("invalid", Assert.IsType<LoginStep.Error>(step).Message);

        step = await manager.SubmitTwoFactorAsync(TwoFactorProvider.Authenticator, "123 456", remember: true);
        Assert.IsType<LoginStep.Done>(step);
        Assert.Equal(VaultState.Unlocked, session.State);
        Assert.Equal("server", session.PublicKeys.Single().Name);
        Assert.Equal("remember-me", AccountStore.GetTwoFactorRemember(env, VaultFixture.Email));
        Assert.Equal("rt", session.Account!.RefreshToken);

        // Background sync keeps working with the stored token.
        Assert.True(await manager.SyncAsync());
        Assert.Null(manager.LastSyncError);
    }

    [Fact]
    public async Task NewDeviceVerificationAndRefreshFailureMarksReauth()
    {
        TestEnv.ResetAppData();
        var fx = new VaultFixture();
        fx.AddPersonalKey("k", TestEnv.GenerateKey("ed25519").PrivatePem);
        var refreshFails = false;
        var server = new FakeServer
        {
            Respond = (path, body) => path switch
            {
                "/identity/accounts/prelogin/password" =>
                    (HttpStatusCode.OK, $$"""{"KdfSettings":{"KdfType":0,"Iterations":{{VaultFixture.Kdf.Iterations}}},"Salt":"{{VaultFixture.Email}}"}"""),
                "/identity/connect/token" when body.Contains("grant_type=refresh_token") && refreshFails =>
                    (HttpStatusCode.BadRequest, """{"error":"invalid_grant"}"""),
                "/identity/connect/token" when body.Contains("grant_type=refresh_token") =>
                    (HttpStatusCode.OK, """{"access_token":"at2","expires_in":3600}"""),
                "/identity/connect/token" when !body.Contains("newDeviceOtp") =>
                    (HttpStatusCode.BadRequest, """{"error":"invalid_grant","ErrorModel":{"Message":"new device verification required"}}"""),
                "/identity/connect/token" => (HttpStatusCode.OK, """{"access_token":"at","expires_in":1,"refresh_token":"rt"}"""),
                "/api/sync" => (HttpStatusCode.OK, fx.SyncJson()),
                _ => (HttpStatusCode.NotFound, "{}"),
            },
        };
        var session = new VaultSession();
        session.Initialize();
        using var manager = new AccountManager(session, new BitwardenApi(server));
        var env = ServerEnvironment.SelfHosted("https://vault.example.test/");
        Assert.IsType<LoginStep.NewDeviceOtp>(await manager.LoginWithPasswordAsync(env, VaultFixture.Email, VaultFixture.Password));
        Assert.IsType<LoginStep.Done>(await manager.SubmitNewDeviceOtpAsync("99887766"));

        // Token expires almost immediately, so sync refreshes it.
        Assert.True(await manager.SyncAsync());
        Assert.Equal("at2", session.Account!.AccessToken);

        refreshFails = true;
        session.Account.AccessTokenExpiry = DateTimeOffset.UtcNow;
        Assert.False(await manager.SyncAsync());
        Assert.True(session.Account.NeedsReauth);
        Assert.NotNull(manager.LastSyncError);
        Assert.Single(session.PublicKeys);
    }

    [Fact]
    public async Task WrongPasswordAndUnsupportedTwoFactorAreReported()
    {
        TestEnv.ResetAppData();
        var server = new FakeServer
        {
            Respond = (path, body) => path switch
            {
                "/identity/accounts/prelogin/password" => (HttpStatusCode.OK, """{"KdfSettings":{"KdfType":1,"Iterations":3,"Memory":16,"Parallelism":2},"Salt":"s@x"}"""),
                "/identity/connect/token" when body.Contains("username=duo") =>
                    (HttpStatusCode.BadRequest, """{"TwoFactorProviders2":{"2":{},"7":{}}}"""),
                _ => (HttpStatusCode.BadRequest, """{"error":"invalid_grant","error_description":"invalid_username_or_password"}"""),
            },
        };
        var session = new VaultSession();
        session.Initialize();
        using var manager = new AccountManager(session, new BitwardenApi(server));
        var env = ServerEnvironment.SelfHosted("https://vault.example.test");
        Assert.Equal("邮箱或主密码不正确。", Assert.IsType<LoginStep.Error>(await manager.LoginWithPasswordAsync(env, "a@b.c", "pw")).Message);
        Assert.Contains("Duo", Assert.IsType<LoginStep.Error>(await manager.LoginWithPasswordAsync(env, "duo", "pw")).Message);
    }

    [Fact]
    public void ServerEnvironmentUrls()
    {
        Assert.Equal("https://identity.bitwarden.eu", ServerEnvironment.Eu.IdentityUrl);
        Assert.Equal("https://api.bitwarden.com", ServerEnvironment.Us.ApiUrl);
        var self = ServerEnvironment.SelfHosted("bw.example.org/");
        Assert.Equal("https://bw.example.org/identity", self.IdentityUrl);
        Assert.Equal("https://bw.example.org/api", self.ApiUrl);
        var custom = ServerEnvironment.SelfHosted("https://bw.example.org", "https://id.example.org", null);
        Assert.Equal("https://id.example.org", custom.IdentityUrl);
        Assert.Throws<ArgumentException>(() => ServerEnvironment.SelfHosted("ftp://x"));
    }
}
