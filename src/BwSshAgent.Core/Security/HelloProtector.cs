using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using BwSshAgent.Core.Crypto;
using BwSshAgent.Core.Native;
using BwSshAgent.Core.Storage;
using Windows.Security.Credentials;

namespace BwSshAgent.Core.Security;

public sealed class HelloException(string message) : Exception(message);

/// <summary>
/// Windows Hello unlock, same idea as Bitwarden desktop's "sign" path: a Hello-protected key signs a fixed
/// random challenge; SHA-256 of the (deterministic RSA PKCS#1) signature is the AES-GCM key sealing the user key.
/// </summary>
public sealed class HelloProtector
{
    private const string CredentialName = "BwSshAgent";
    private const string FileName = "hello.dat";

    private sealed class HelloState
    {
        public byte[] Challenge { get; set; } = [];
        public byte[] Nonce { get; set; } = [];
        public byte[] Tag { get; set; } = [];
        public byte[] Ciphertext { get; set; } = [];
    }

    private static readonly SemaphoreSlim Gate = new(1, 1);

    public bool IsEnrolled => SecureFile.Exists(FileName);

    public event Action? Changed;

    public static async Task<bool> IsSupportedAsync()
    {
        try
        {
            return await KeyCredentialManager.IsSupportedAsync();
        }
        catch (Exception)
        {
            return false;
        }
    }

    public async Task EnrollAsync(SymmetricKey userKey)
    {
        await Gate.WaitAsync();
        try
        {
            if (!await IsSupportedAsync())
            {
                throw new HelloException(L.T("此设备未设置 Windows Hello。", "Windows Hello is not set up on this device."));
            }
            using var focus = new CancellationTokenSource();
            WindowFocus.FocusSecurityPromptWhile(focus.Token);
            try
            {
                var created = await KeyCredentialManager.RequestCreateAsync(CredentialName, KeyCredentialCreationOption.ReplaceExisting);
                if (created.Status != KeyCredentialStatus.Success)
                {
                    throw new HelloException(StatusMessage(created.Status));
                }
                var challenge = RandomNumberGenerator.GetBytes(32);
                var key = await SignAsync(created.Credential, challenge);
                var plain = userKey.ToBytes();
                try
                {
                    var nonce = RandomNumberGenerator.GetBytes(12);
                    var tag = new byte[16];
                    var ct = new byte[plain.Length];
                    using (var gcm = new AesGcm(key, 16))
                    {
                        gcm.Encrypt(nonce, plain, ct, tag);
                    }
                    SecureFile.WriteJson(FileName, new HelloState { Challenge = challenge, Nonce = nonce, Tag = tag, Ciphertext = ct });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                    CryptographicOperations.ZeroMemory(key);
                }
            }
            finally
            {
                await focus.CancelAsync();
            }
        }
        finally
        {
            Gate.Release();
        }
        Changed?.Invoke();
    }

    public async Task<SymmetricKey> UnlockAsync()
    {
        var state = SecureFile.ReadJson<HelloState>(FileName) ?? throw new HelloException(L.T("尚未启用 Windows Hello 解锁。", "Windows Hello unlock is not enabled."));
        await Gate.WaitAsync();
        var previous = WindowFocus.Foreground();
        using var focus = new CancellationTokenSource();
        try
        {
            var opened = await KeyCredentialManager.OpenAsync(CredentialName);
            if (opened.Status != KeyCredentialStatus.Success)
            {
                if (opened.Status == KeyCredentialStatus.NotFound)
                {
                    SecureFile.Delete(FileName);
                    Changed?.Invoke();
                }
                throw new HelloException(StatusMessage(opened.Status));
            }
            WindowFocus.FocusSecurityPromptWhile(focus.Token);
            var key = await SignAsync(opened.Credential, state.Challenge);
            try
            {
                var plain = new byte[state.Ciphertext.Length];
                using (var gcm = new AesGcm(key, 16))
                {
                    gcm.Decrypt(state.Nonce, state.Ciphertext, state.Tag, plain);
                }
                try
                {
                    return new SymmetricKey(plain);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }
            catch (CryptographicException)
            {
                throw new HelloException(L.T("Windows Hello 凭据已变化，请用主密码解锁后重新启用 Windows Hello。", "The Windows Hello credential changed. Unlock with your master password and enable Windows Hello again."));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
        finally
        {
            await focus.CancelAsync();
            Gate.Release();
            WindowFocus.Restore(previous);
        }
    }

    public async Task DisableAsync()
    {
        SecureFile.Delete(FileName);
        try
        {
            await KeyCredentialManager.DeleteAsync(CredentialName);
        }
        catch (Exception)
        {
        }
        Changed?.Invoke();
    }

    private static async Task<byte[]> SignAsync(KeyCredential credential, byte[] challenge)
    {
        var result = await credential.RequestSignAsync(challenge.AsBuffer());
        if (result.Status != KeyCredentialStatus.Success)
        {
            throw new HelloException(StatusMessage(result.Status));
        }
        return SHA256.HashData(result.Result.ToArray());
    }

    private static string StatusMessage(KeyCredentialStatus status) => status switch
    {
        KeyCredentialStatus.UserCanceled => L.T("已取消 Windows Hello 验证。", "Windows Hello was cancelled."),
        KeyCredentialStatus.UserPrefersPassword => L.T("已选择改用密码。", "Password chosen instead."),
        KeyCredentialStatus.NotFound => L.T("未找到 Windows Hello 凭据，请重新启用。", "Windows Hello credential not found, please enable it again."),
        KeyCredentialStatus.SecurityDeviceLocked => L.T("安全设备已锁定，请稍后再试。", "The security device is locked, try again later."),
        _ => L.T($"Windows Hello 验证失败 ({status})。", $"Windows Hello failed ({status})."),
    };
}
