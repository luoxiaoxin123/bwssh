using System.Collections.Concurrent;
using BwSshAgent.Core.Audit;
using BwSshAgent.Core.Native;
using BwSshAgent.Core.Security;
using BwSshAgent.Core.Settings;
using BwSshAgent.Core.Ssh;

namespace BwSshAgent.Core.Approval;

public enum UserChoice
{
    Approve,
    ApproveForProcess,
    Deny,
}

internal enum Resolution
{
    Approved,
    ApprovedForProcess,
    ApprovedAfterUnlock,
    AutoRemembered,
    AutoGrant,
    Denied,
    TimedOut,
    Cancelled,
}

/// <summary>A sign request waiting for the user.</summary>
public sealed class PendingApproval
{
    internal TaskCompletionSource<Resolution> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public required string Id { get; init; }
    public required PublicKeyEntry Key { get; init; }
    public required SignRequest Request { get; init; }
    public required AgentClient Client { get; init; }
    public required ProcessNode GrantTarget { get; init; }
    public string? Destination { get; init; }
    public DateTimeOffset CreatedAt { get; } = DateTimeOffset.Now;

    /// <summary>True while the prompt is the "unlock required" variant.</summary>
    public bool Locked { get; internal set; }

    /// <summary>The user chose "unlock" on this request, so a successful unlock also approves it.</summary>
    public bool UnlockRequested { get; internal set; }

    public string Operation => AgentService.DescribeOperation(Request);

    public string ProcessChain => AgentService.DescribeChain(Client.Chain);
}

/// <summary>Shows prompts. Implementations must be thread-safe; calls arrive on thread-pool threads.</summary>
public interface IApprovalPresenter
{
    void ShowApproval(PendingApproval request, int grantMinutes);
    void ShowUnlockRequired(PendingApproval request);
    void ShowListUnlockRequired(string processChain);
    void Dismiss(PendingApproval request);
}

/// <summary>
/// Agent policy: same three modes as Bitwarden desktop, plus time-limited per-process grants.
/// </summary>
public sealed class AgentService : IAgentHandler
{
    private readonly VaultSession _session;
    private readonly Func<AppSettings> _settings;
    private readonly AuditLog _audit;
    private readonly ConcurrentDictionary<string, PendingApproval> _pending = new();
    private readonly Lock _cacheGate = new();
    private readonly Dictionary<string, HashSet<string>> _remembered = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _grants = new();
    private int _nextId;

    public AgentService(VaultSession session, Func<AppSettings> settings, AuditLog audit)
    {
        _session = session;
        _settings = settings;
        _audit = audit;
        _session.Unlocked += OnUnlocked;
        _session.LockedOrLoggedOut += OnLocked;
    }

    public IApprovalPresenter? Presenter { get; set; }

    public IReadOnlyCollection<PendingApproval> Pending => _pending.Values.ToList();

    public event Action? GrantsChanged;

    public IReadOnlyList<(string Identity, DateTimeOffset Expires)> ActiveGrants
    {
        get
        {
            lock (_cacheGate)
            {
                PruneGrants();
                return _grants.Select(kv => (kv.Key, kv.Value)).ToList();
            }
        }
    }

    public void RevokeAllGrants()
    {
        lock (_cacheGate)
        {
            _grants.Clear();
            _remembered.Clear();
        }
        GrantsChanged?.Invoke();
    }

    public async Task<IReadOnlyList<AgentIdentity>> ListAsync(AgentClient client, CancellationToken ct)
    {
        if (_session.State == VaultState.LoggedOut)
        {
            return [];
        }
        var keys = _session.PublicKeys;
        if (keys.Count == 0 && !_session.HasEverUnlocked && _session.State == VaultState.Locked)
        {
            // Nothing cached yet (first run): ask the user to unlock, like Bitwarden's list approval.
            var unlocked = WaitForUnlockAsync(TimeSpan.FromSeconds(_settings().ApprovalTimeoutSeconds), ct);
            Presenter?.ShowListUnlockRequired(DescribeChain(client.Chain));
            await unlocked;
            keys = _session.PublicKeys;
        }
        return keys.Select(k => new AgentIdentity(k.Blob, k.Name)).ToList();
    }

    public async Task<byte[]?> SignAsync(AgentClient client, SignRequest request, CancellationToken ct)
    {
        if (_session.State == VaultState.LoggedOut)
        {
            return null;
        }
        var key = _session.FindPublicKey(request.KeyBlob);
        if (key == null)
        {
            return null;
        }

        var sshNode = client.Chain.FirstOrDefault(ProcessInfo.IsSshClient);
        var pending = new PendingApproval
        {
            Id = Interlocked.Increment(ref _nextId).ToString(),
            Key = key,
            Request = request,
            Client = client,
            GrantTarget = ProcessInfo.GrantTarget(client.Chain),
            Destination = ProcessInfo.ParseSshDestination(sshNode?.CommandLine),
        };

        var settings = _settings();
        Resolution resolution;
        if (_session.State == VaultState.Unlocked && TryAutoApprove(pending, settings) is { } auto)
        {
            resolution = auto;
        }
        else
        {
            resolution = await PromptAsync(pending, settings, ct);
        }

        if (resolution is Resolution.Denied or Resolution.TimedOut or Resolution.Cancelled)
        {
            Audit(pending, resolution, settings);
            return null;
        }

        Remember(pending, resolution, settings);
        byte[]? signature = null;
        string? failure = null;
        try
        {
            signature = _session.Sign(key.CipherId, request.Data, request.Flags);
            if (signature == null)
            {
                failure = L.T("签名失败（密码库已锁定或密钥不可用）", "Signing failed (vault locked or key unavailable)");
            }
        }
        catch (Exception ex) when (ex is SshSignException or System.Security.Cryptography.CryptographicException)
        {
            failure = L.T("签名失败：", "Signing failed: ") + ex.Message;
        }
        Audit(pending, resolution, settings, failure);
        return signature;
    }

    private Resolution? TryAutoApprove(PendingApproval p, AppSettings settings)
    {
        if (settings.PromptMode == PromptMode.Never)
        {
            return Resolution.AutoRemembered;
        }
        lock (_cacheGate)
        {
            PruneGrants();
            if (_grants.ContainsKey(GrantKey(p)))
            {
                return Resolution.AutoGrant;
            }
            if (settings.PromptMode == PromptMode.RememberUntilLock &&
                RememberKey(p.Request) is { } rk &&
                _remembered.TryGetValue(p.Key.CipherId, out var set) && set.Contains(rk))
            {
                return Resolution.AutoRemembered;
            }
        }
        return null;
    }

    private async Task<Resolution> PromptAsync(PendingApproval p, AppSettings settings, CancellationToken ct)
    {
        _pending[p.Id] = p;
        try
        {
            if (_session.State == VaultState.Unlocked)
            {
                Presenter?.ShowApproval(p, settings.GrantMinutes);
            }
            else
            {
                p.Locked = true;
                Presenter?.ShowUnlockRequired(p);
            }

            var timeout = TimeSpan.FromSeconds(p.Locked ? Math.Max(settings.ApprovalTimeoutSeconds, 120) : settings.ApprovalTimeoutSeconds);
            var winner = await Task.WhenAny(p.Completion.Task, Task.Delay(timeout, ct));
            if (winner == p.Completion.Task)
            {
                return p.Completion.Task.Result;
            }
            return ct.IsCancellationRequested ? Resolution.Cancelled : Resolution.TimedOut;
        }
        catch (OperationCanceledException)
        {
            return Resolution.Cancelled;
        }
        finally
        {
            _pending.TryRemove(p.Id, out _);
            Presenter?.Dismiss(p);
        }
    }

    /// <summary>Called by the UI when the user answers a prompt.</summary>
    public void Respond(string id, UserChoice choice)
    {
        if (!_pending.TryGetValue(id, out var p))
        {
            return;
        }
        switch (choice)
        {
            case UserChoice.Deny:
                p.Completion.TrySetResult(Resolution.Denied);
                break;
            case UserChoice.Approve:
                p.Completion.TrySetResult(p.Locked ? Resolution.ApprovedAfterUnlock : Resolution.Approved);
                break;
            case UserChoice.ApproveForProcess:
                AddGrant(p, _settings().GrantMinutes);
                p.Completion.TrySetResult(Resolution.ApprovedForProcess);
                // Other prompts from the same process are covered by the new grant.
                foreach (var other in _pending.Values)
                {
                    if (other != p && !other.Locked && GrantKey(other) == GrantKey(p))
                    {
                        other.Completion.TrySetResult(Resolution.AutoGrant);
                    }
                }
                break;
        }
    }

    /// <summary>The user picked "unlock" on a locked prompt; a successful unlock will approve it.</summary>
    public void MarkUnlockRequested(string id)
    {
        if (_pending.TryGetValue(id, out var p))
        {
            p.UnlockRequested = true;
        }
    }

    private void OnUnlocked()
    {
        var settings = _settings();
        foreach (var p in _pending.Values.Where(x => x.Locked))
        {
            if (p.UnlockRequested)
            {
                p.Completion.TrySetResult(Resolution.ApprovedAfterUnlock);
                continue;
            }
            if (TryAutoApprove(p, settings) is { } auto)
            {
                p.Completion.TrySetResult(auto);
                continue;
            }
            Presenter?.Dismiss(p);
            p.Locked = false;
            Presenter?.ShowApproval(p, settings.GrantMinutes);
        }
    }

    private void OnLocked()
    {
        lock (_cacheGate)
        {
            _remembered.Clear();
            _grants.Clear();
        }
        foreach (var p in _pending.Values.Where(x => !x.Locked))
        {
            p.Completion.TrySetResult(Resolution.Denied);
        }
        GrantsChanged?.Invoke();
    }

    private Task WaitForUnlockAsync(TimeSpan timeout, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler() => tcs.TrySetResult();
        _session.Unlocked += Handler;
        return Task.WhenAny(tcs.Task, Task.Delay(timeout, ct)).ContinueWith(_ => _session.Unlocked -= Handler, TaskScheduler.Default);
    }

    private void Remember(PendingApproval p, Resolution resolution, AppSettings settings)
    {
        if (settings.PromptMode != PromptMode.RememberUntilLock ||
            resolution is not (Resolution.Approved or Resolution.ApprovedAfterUnlock or Resolution.ApprovedForProcess))
        {
            return;
        }
        if (RememberKey(p.Request) is not { } rk)
        {
            return;
        }
        lock (_cacheGate)
        {
            if (!_remembered.TryGetValue(p.Key.CipherId, out var set))
            {
                _remembered[p.Key.CipherId] = set = [];
            }
            set.Add(rk);
        }
    }

    private void AddGrant(PendingApproval p, int minutes)
    {
        lock (_cacheGate)
        {
            _grants[GrantKey(p)] = DateTimeOffset.Now.AddMinutes(minutes);
        }
        GrantsChanged?.Invoke();
    }

    private void PruneGrants()
    {
        var now = DateTimeOffset.Now;
        foreach (var expired in _grants.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList())
        {
            _grants.Remove(expired);
        }
    }

    /// <summary>Grant scope: (key, process instance). Forwarded requests never match a grant.</summary>
    private static string GrantKey(PendingApproval p) =>
        p.Request.IsForwarding ? "forwarded:" + p.Id : $"{p.Key.CipherId}|{p.GrantTarget.Identity}";

    /// <summary>Same cache key as Bitwarden desktop's authorizedHostsCacheKey.</summary>
    internal static string? RememberKey(SignRequest r)
    {
        if (r.IsForwarding)
        {
            return r.HostFingerprint == null ? null : "forwarded:" + r.HostFingerprint;
        }
        return r.HostFingerprint == null ? "local" : "local:" + r.HostFingerprint;
    }

    private void Audit(PendingApproval p, Resolution resolution, AppSettings settings, string? failure = null)
    {
        var decision = failure ?? resolution switch
        {
            Resolution.Approved => L.T("已批准", "Approved"),
            Resolution.ApprovedForProcess => L.T($"已批准（授权该程序 {settings.GrantMinutes} 分钟）", $"Approved (process allowed for {settings.GrantMinutes} min)"),
            Resolution.ApprovedAfterUnlock => L.T("解锁并批准", "Unlocked and approved"),
            Resolution.AutoRemembered => settings.PromptMode == PromptMode.Never ? L.T("自动批准（从不询问）", "Auto-approved (never ask)") : L.T("自动批准（锁定前记住）", "Auto-approved (remembered until lock)"),
            Resolution.AutoGrant => L.T("自动批准（程序授权期内）", "Auto-approved (process allowed)"),
            Resolution.Denied => L.T("已拒绝", "Denied"),
            Resolution.TimedOut => L.T("超时未响应，已拒绝", "Timed out, denied"),
            _ => L.T("已取消", "Cancelled"),
        };
        _audit.Append(new AuditEntry
        {
            Time = DateTimeOffset.Now,
            Decision = decision,
            Operation = p.Operation,
            KeyName = p.Key.Name,
            KeyFingerprint = p.Key.Fingerprint,
            Process = p.ProcessChain,
            Pid = p.Client.Pid,
            GrantTarget = p.GrantTarget.Name,
            Destination = p.Destination,
            RemoteUser = p.Request.RemoteUser,
            Forwarded = p.Request.IsForwarding,
            HostFingerprint = p.Request.HostFingerprint,
        });
    }

    public static string DescribeOperation(SignRequest r) => r.Kind switch
    {
        SignKind.SshAuth => L.T("SSH 登录", "SSH login"),
        SignKind.GitSign => L.T("Git 提交签名", "Git commit signing"),
        SignKind.FileSign => L.T("文件签名", "File signing"),
        SignKind.OtherSign => L.T($"签名（{r.Namespace}）", $"Signing ({r.Namespace})"),
        _ => L.T("签名", "Signing"),
    };

    public static string DescribeChain(IReadOnlyList<ProcessNode> chain) =>
        string.Join(" → ", chain.Reverse().Select(n => n.Name));
}
