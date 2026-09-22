using System.Security.Cryptography;
using System.Text;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Storage;

namespace BwSshAgent.Core.Security;

public sealed class PinException(string message) : Exception(message);

/// <summary>
/// PIN unlock. The user key is sealed with AES-256-GCM under Argon2id(PIN). With "require master password
/// after restart" (default) the sealed envelope lives only in memory; it is rebuilt after each full unlock
/// from a copy of the PIN that is itself encrypted with the user key.
/// </summary>
public sealed class PinProtector
{
    public const int MaxAttempts = 5;
    private const string FileName = "pin.dat";
    private const int ArgonIterations = 3;
    private const int ArgonMemoryKiB = 64 * 1024;
    private const int ArgonParallelism = 4;

    private sealed class PinState
    {
        public bool Persistent { get; set; }
        public byte[]? Envelope { get; set; }
        public byte[] SealedPin { get; set; } = [];
        public int FailedAttempts { get; set; }
    }

    private PinState? _state;
    private byte[]? _memoryEnvelope;
    private int _memoryFailures;

    public PinProtector()
    {
        _state = SecureFile.ReadJson<PinState>(FileName);
    }

    public bool IsEnabled => _state != null;
    public bool IsPersistent => _state?.Persistent == true;
    public bool IsAvailable => _state != null && (_state.Persistent ? _state.Envelope != null : _memoryEnvelope != null);

    public event Action? Changed;

    public async Task EnableAsync(string pin, bool persistent, SymmetricKey userKey)
    {
        if (pin.Length < 4)
        {
            throw new PinException(L.T("PIN 至少需要 4 位。", "The PIN needs at least 4 characters."));
        }
        var userKeyBytes = userKey.ToBytes();
        try
        {
            var envelope = await Task.Run(() => Seal(pin, userKeyBytes));
            var state = new PinState
            {
                Persistent = persistent,
                Envelope = persistent ? envelope : null,
                SealedPin = SealPin(pin, userKeyBytes),
            };
            SecureFile.WriteJson(FileName, state);
            _state = state;
            _memoryEnvelope = persistent ? null : envelope;
            _memoryFailures = 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(userKeyBytes);
        }
        Changed?.Invoke();
    }

    public void Disable()
    {
        SecureFile.Delete(FileName);
        _state = null;
        ClearMemory();
        Changed?.Invoke();
    }

    public void ClearMemory()
    {
        if (_memoryEnvelope != null)
        {
            CryptographicOperations.ZeroMemory(_memoryEnvelope);
        }
        _memoryEnvelope = null;
        _memoryFailures = 0;
    }

    /// <summary>After unlocking by other means, rebuild the in-memory envelope for ephemeral PINs.</summary>
    public async Task RestoreAfterUnlockAsync(SymmetricKey userKey)
    {
        if (_state == null || _state.Persistent || _memoryEnvelope != null)
        {
            return;
        }
        var userKeyBytes = userKey.ToBytes();
        try
        {
            var pin = UnsealPin(_state.SealedPin, userKeyBytes);
            _memoryEnvelope = await Task.Run(() => Seal(pin, userKeyBytes));
            _memoryFailures = 0;
            Changed?.Invoke();
        }
        catch (CryptographicException ex)
        {
            Log.Warn("PIN restore failed, disabling PIN: " + ex.Message);
            Disable();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(userKeyBytes);
        }
    }

    public async Task<SymmetricKey> UnlockAsync(string pin)
    {
        if (_state == null)
        {
            throw new PinException(L.T("未设置 PIN。", "No PIN is set."));
        }
        var envelope = _state.Persistent ? _state.Envelope : _memoryEnvelope;
        if (envelope == null)
        {
            throw new PinException(L.T("重启后需要先用主密码或 Windows Hello 解锁一次，之后才能使用 PIN。", "After a restart, unlock once with your master password or Windows Hello before using the PIN."));
        }
        try
        {
            var raw = await Task.Run(() => Open(pin, envelope));
            try
            {
                ResetFailures();
                return new SymmetricKey(raw);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(raw);
            }
        }
        catch (CryptographicException)
        {
            var failures = RecordFailure();
            if (failures >= MaxAttempts)
            {
                Disable();
                throw new PinException(L.T($"PIN 已连续输错 {MaxAttempts} 次，PIN 已被清除，请使用主密码解锁。", $"Wrong PIN {MaxAttempts} times in a row. The PIN was removed, unlock with your master password."));
            }
            throw new PinException(L.T($"PIN 不正确，还可以再试 {MaxAttempts - failures} 次。", $"Incorrect PIN, {MaxAttempts - failures} attempts left."));
        }
    }

    private int RecordFailure()
    {
        if (_state!.Persistent)
        {
            _state.FailedAttempts++;
            SecureFile.WriteJson(FileName, _state);
            return _state.FailedAttempts;
        }
        return ++_memoryFailures;
    }

    private void ResetFailures()
    {
        if (_state!.Persistent && _state.FailedAttempts != 0)
        {
            _state.FailedAttempts = 0;
            SecureFile.WriteJson(FileName, _state);
        }
        _memoryFailures = 0;
    }

    // Envelope: salt(16) | nonce(12) | tag(16) | ciphertext
    private static byte[] Seal(string pin, byte[] secret)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = DerivePinKey(pin, salt);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var ct = new byte[secret.Length];
            using (var gcm = new AesGcm(key, 16))
            {
                gcm.Encrypt(nonce, secret, ct, tag);
            }
            return [.. salt, .. nonce, .. tag, .. ct];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] Open(string pin, byte[] envelope)
    {
        if (envelope.Length < 44)
        {
            throw new CryptographicException("Invalid envelope.");
        }
        var key = DerivePinKey(pin, envelope[..16]);
        try
        {
            var plain = new byte[envelope.Length - 44];
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(envelope.AsSpan(16, 12), envelope.AsSpan(44), envelope.AsSpan(28, 16), plain);
            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DerivePinKey(string pin, byte[] salt)
    {
        var pinBytes = Encoding.UTF8.GetBytes(pin);
        try
        {
            return KeyDerivation.Argon2id(pinBytes, salt, ArgonIterations, ArgonMemoryKiB, ArgonParallelism);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBytes);
        }
    }

    private static byte[] SealKey(byte[] userKeyBytes) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, userKeyBytes, 32, info: "BwSshAgent PIN seal"u8.ToArray());

    private static byte[] SealPin(string pin, byte[] userKeyBytes)
    {
        var key = SealKey(userKeyBytes);
        try
        {
            var plain = Encoding.UTF8.GetBytes(pin);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var ct = new byte[plain.Length];
            using (var gcm = new AesGcm(key, 16))
            {
                gcm.Encrypt(nonce, plain, ct, tag);
            }
            CryptographicOperations.ZeroMemory(plain);
            return [.. nonce, .. tag, .. ct];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string UnsealPin(byte[] sealedPin, byte[] userKeyBytes)
    {
        var key = SealKey(userKeyBytes);
        try
        {
            var plain = new byte[sealedPin.Length - 28];
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(sealedPin.AsSpan(0, 12), sealedPin.AsSpan(28), sealedPin.AsSpan(12, 16), plain);
            var pin = Encoding.UTF8.GetString(plain);
            CryptographicOperations.ZeroMemory(plain);
            return pin;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
