using System.Security.Cryptography;
using System.Text.Json;

namespace BwSshAgent.Core.Storage;

public static class AppPaths
{
    private static string? _root;

    /// <summary>Overridable for tests.</summary>
    public static string Root
    {
        get => _root ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BwSshAgent");
        set => _root = value;
    }

    public static string File(string name)
    {
        Directory.CreateDirectory(Root);
        return Path.Combine(Root, name);
    }

    public static string AuditDir
    {
        get
        {
            var dir = Path.Combine(Root, "audit");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }
}

/// <summary>Files protected with DPAPI (CurrentUser scope).</summary>
public static class SecureFile
{
    private static readonly byte[] Entropy = "BwSshAgent.SecureFile.v1"u8.ToArray();

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
    };

    public static byte[] Protect(byte[] data) => ProtectedData.Protect(data, Entropy, DataProtectionScope.CurrentUser);

    public static byte[] Unprotect(byte[] data) => ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser);

    public static void WriteJson<T>(string name, T value)
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        try
        {
            WriteAtomic(AppPaths.File(name), Protect(plain));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static T? ReadJson<T>(string name) where T : class
    {
        var path = AppPaths.File(name);
        if (!System.IO.File.Exists(path))
        {
            return null;
        }
        try
        {
            var plain = Unprotect(System.IO.File.ReadAllBytes(path));
            try
            {
                return JsonSerializer.Deserialize<T>(plain, JsonOptions);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static void Delete(string name)
    {
        var path = AppPaths.File(name);
        if (System.IO.File.Exists(path))
        {
            System.IO.File.Delete(path);
        }
    }

    public static bool Exists(string name) => System.IO.File.Exists(AppPaths.File(name));

    public static void WriteAtomic(string path, byte[] data)
    {
        var tmp = path + ".tmp";
        System.IO.File.WriteAllBytes(tmp, data);
        System.IO.File.Move(tmp, path, overwrite: true);
    }
}
