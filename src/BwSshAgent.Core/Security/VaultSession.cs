using System.Security.Cryptography;
using BwSshAgent.Core.Bitwarden;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Ssh;

namespace BwSshAgent.Core.Security;

public enum VaultState
{
    LoggedOut,
    Locked,
    Unlocked,
}

public sealed class UnlockException(string message) : Exception(message);

/// <summary>
/// Holds lock state, the user key and decrypted SSH keys while unlocked. Locking zeroes and disposes all of it.
/// </summary>
public sealed class VaultSession
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, SshPrivateKey> _privateKeys = new(StringComparer.OrdinalIgnoreCase);
    private SymmetricKey? _userKey;
    private List<PublicKeyEntry> _publicKeys = [];

    public VaultSession()
    {
        Pin = new PinProtector();
        Hello = new HelloProtector();
    }

    public PinProtector Pin { get; }
    public HelloProtector Hello { get; }
    public VaultState State { get; private set; } = VaultState.LoggedOut;
    public AccountState? Account { get; private set; }
    public VaultSnapshot? Snapshot { get; private set; }
    public IReadOnlyList<string> DecryptErrors { get; private set; } = [];
    public bool HasEverUnlocked { get; private set; }

    public IReadOnlyList<PublicKeyEntry> PublicKeys
    {
        get
        {
            lock (_gate)
            {
                return _publicKeys.ToList();
            }
        }
    }

    /// <summary>Raised after any state change (login, unlock, lock, logout, key refresh).</summary>
    public event Action? Changed;

    /// <summary>Raised when the vault transitions to unlocked.</summary>
    public event Action? Unlocked;

    /// <summary>Raised when the vault is locked or logged out.</summary>
    public event Action? LockedOrLoggedOut;

    public void Initialize()
    {
        Account = AccountStore.LoadAccount();
        Snapshot = AccountStore.LoadSnapshot();
        if (Account == null)
        {
            State = VaultState.LoggedOut;
            return;
        }
        _publicKeys = AccountStore.LoadPublicKeys();
        State = VaultState.Locked;
    }

    public void UpdateAccount(AccountState account)
    {
        Account = account;
        AccountStore.SaveAccount(account);
        Changed?.Invoke();
    }

    public async Task UnlockWithMasterPasswordAsync(string password)
    {
        var account = Account ?? throw new UnlockException(L.T("未登录。", "Not signed in."));
        var snapshot = Snapshot ?? throw new UnlockException(L.T("本地没有密码库数据，请先联网同步。", "No local vault data, please sync while online."));
        var encUserKey = snapshot.EncUserKey ?? throw new UnlockException(L.T("同步数据中缺少用户密钥。", "The sync data has no user key."));
        var kdf = snapshot.Kdf ?? account.Kdf ?? throw new UnlockException(L.T("缺少 KDF 参数，请重新登录。", "KDF parameters are missing, please sign in again."));
        var salt = snapshot.Salt ?? account.Salt ?? KeyDerivation.NormalizeEmailSalt(account.Email);

        SymmetricKey userKey;
        try
        {
            userKey = await Task.Run(() =>
            {
                var masterKey = KeyDerivation.DeriveMasterKey(password, salt, kdf);
                try
                {
                    return KeyDerivation.DecryptUserKey(masterKey, encUserKey);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(masterKey);
                }
            });
        }
        catch (UnsupportedEncryptionException ex)
        {
            throw new UnlockException(ex.Message);
        }
        catch (CryptographicException)
        {
            throw new UnlockException(L.T("主密码不正确。", "Incorrect master password."));
        }
        await UnlockWithUserKeyAsync(userKey, restorePin: true);
    }

    public async Task UnlockWithPinAsync(string pin)
    {
        SymmetricKey userKey;
        try
        {
            userKey = await Pin.UnlockAsync(pin);
        }
        catch (PinException ex)
        {
            throw new UnlockException(ex.Message);
        }
        await UnlockWithUserKeyAsync(userKey, restorePin: false);
    }

    public async Task UnlockWithHelloAsync()
    {
        SymmetricKey userKey;
        try
        {
            userKey = await Hello.UnlockAsync();
        }
        catch (HelloException ex)
        {
            throw new UnlockException(ex.Message);
        }
        await UnlockWithUserKeyAsync(userKey, restorePin: true);
    }

    /// <summary>Takes ownership of <paramref name="userKey"/>.</summary>
    public async Task UnlockWithUserKeyAsync(SymmetricKey userKey, bool restorePin)
    {
        var snapshot = Snapshot ?? throw new UnlockException(L.T("本地没有密码库数据。", "No local vault data."));
        try
        {
            LoadKeys(snapshot, userKey);
        }
        catch
        {
            userKey.Dispose();
            throw;
        }

        lock (_gate)
        {
            _userKey?.Dispose();
            _userKey = userKey;
            State = VaultState.Unlocked;
            HasEverUnlocked = true;
        }
        Log.Info($"Vault unlocked, {_privateKeys.Count} SSH key(s) loaded");
        Changed?.Invoke();
        Unlocked?.Invoke();

        if (restorePin)
        {
            await Pin.RestoreAfterUnlockAsync(userKey);
        }
    }

    public async Task SetLoggedInAsync(AccountState account, VaultSnapshot snapshot, SymmetricKey userKey)
    {
        var previousUser = Account?.UserId;
        if (previousUser != null && !string.Equals(previousUser, account.UserId, StringComparison.OrdinalIgnoreCase))
        {
            Pin.Disable();
            await Hello.DisableAsync();
        }
        Account = account;
        Snapshot = snapshot;
        AccountStore.SaveAccount(account);
        AccountStore.SaveSnapshot(snapshot);
        await UnlockWithUserKeyAsync(userKey, restorePin: true);
    }

    /// <summary>Applies a fresh sync. If unlocked, re-decrypts keys with the current user key.</summary>
    public void ApplySnapshot(VaultSnapshot snapshot)
    {
        Snapshot = snapshot;
        AccountStore.SaveSnapshot(snapshot);
        lock (_gate)
        {
            if (State == VaultState.Unlocked && _userKey != null)
            {
                LoadKeys(snapshot, _userKey);
            }
        }
        Changed?.Invoke();
    }

    private void LoadKeys(VaultSnapshot snapshot, SymmetricKey userKey)
    {
        var result = VaultDecryptor.DecryptSshKeys(snapshot, userKey);
        var loaded = new Dictionary<string, SshPrivateKey>(StringComparer.OrdinalIgnoreCase);
        var publicKeys = new List<PublicKeyEntry>();
        var errors = new List<string>(result.Errors);
        foreach (var item in result.Items)
        {
            try
            {
                var key = SshKeyParser.Parse(item.PrivateKeyUtf8);
                loaded[item.CipherId] = key;
                publicKeys.Add(new PublicKeyEntry
                {
                    CipherId = item.CipherId,
                    Name = item.Name,
                    KeyType = key.KeyType,
                    BlobBase64 = Convert.ToBase64String(key.PublicBlob),
                    Fingerprint = key.Fingerprint,
                });
            }
            catch (Exception ex)
            {
                errors.Add(L.T($"“{item.Name}”: 无法解析私钥 ({ex.Message})", $"\"{item.Name}\": cannot parse private key ({ex.Message})"));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(item.PrivateKeyUtf8);
            }
        }

        lock (_gate)
        {
            foreach (var old in _privateKeys.Values)
            {
                old.Dispose();
            }
            _privateKeys.Clear();
            foreach (var kv in loaded)
            {
                _privateKeys[kv.Key] = kv.Value;
            }
            _publicKeys = publicKeys;
            DecryptErrors = errors;
        }
        foreach (var e in errors)
        {
            Log.Warn("Key load: " + e);
        }
        AccountStore.SavePublicKeys(publicKeys);
    }

    public PublicKeyEntry? FindPublicKey(ReadOnlySpan<byte> blob)
    {
        lock (_gate)
        {
            foreach (var k in _publicKeys)
            {
                if (blob.SequenceEqual(k.Blob))
                {
                    return k;
                }
            }
        }
        return null;
    }

    public byte[]? Sign(string cipherId, ReadOnlySpan<byte> data, uint flags)
    {
        lock (_gate)
        {
            if (State != VaultState.Unlocked || !_privateKeys.TryGetValue(cipherId, out var key))
            {
                return null;
            }
            return key.Sign(data, flags);
        }
    }

    /// <summary>A copy of the user key for PIN/Hello enrollment; caller disposes.</summary>
    public SymmetricKey? CopyUserKey()
    {
        lock (_gate)
        {
            if (_userKey == null)
            {
                return null;
            }
            var bytes = _userKey.ToBytes();
            try
            {
                return new SymmetricKey(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    public void Lock(string reason)
    {
        lock (_gate)
        {
            if (State != VaultState.Unlocked)
            {
                return;
            }
            ClearSecrets();
            State = VaultState.Locked;
        }
        Log.Info("Vault locked: " + reason);
        GC.Collect();
        Changed?.Invoke();
        LockedOrLoggedOut?.Invoke();
    }

    public void Logout()
    {
        lock (_gate)
        {
            ClearSecrets();
            _publicKeys = [];
            State = VaultState.LoggedOut;
        }
        Account = null;
        Snapshot = null;
        AccountStore.DeleteAccountData();
        Pin.Disable();
        _ = Hello.DisableAsync();
        Log.Info("Logged out");
        Changed?.Invoke();
        LockedOrLoggedOut?.Invoke();
    }

    private void ClearSecrets()
    {
        foreach (var key in _privateKeys.Values)
        {
            key.Dispose();
        }
        _privateKeys.Clear();
        _userKey?.Dispose();
        _userKey = null;
    }
}
