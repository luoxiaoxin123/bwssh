using System.Text.Json;
using System.Text.Json.Serialization;
using BwSshAgent.Core.Storage;
using Microsoft.Win32;

namespace BwSshAgent.Core.Settings;

/// <summary>Same three modes as the Bitwarden desktop app (SshAgentPromptType).</summary>
public enum PromptMode
{
    Always,
    RememberUntilLock,
    Never,
}

public enum ApprovalUi
{
    Toast,
    Window,
}

public sealed class AppSettings
{
    private const string FileName = "settings.json";

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public PromptMode PromptMode { get; set; } = PromptMode.Always;
    public ApprovalUi ApprovalUi { get; set; } = ApprovalUi.Toast;
    public int GrantMinutes { get; set; } = 15;
    public int ApprovalTimeoutSeconds { get; set; } = 60;
    public int LockAfterIdleMinutes { get; set; }
    public bool LockOnSystemLock { get; set; }
    public bool LockOnSleep { get; set; }
    public int SyncIntervalMinutes { get; set; } = 30;
    public string PipeName { get; set; } = "openssh-ssh-agent";

    public static AppSettings Load()
    {
        try
        {
            var path = AppPaths.File(FileName);
            if (File.Exists(path))
            {
                var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Options);
                if (settings != null)
                {
                    settings.Clamp();
                    return settings;
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error("Failed to load settings", ex);
        }
        return new AppSettings();
    }

    public void Save()
    {
        Clamp();
        SecureFile.WriteAtomic(AppPaths.File(FileName), JsonSerializer.SerializeToUtf8Bytes(this, Options));
    }

    private void Clamp()
    {
        GrantMinutes = Math.Clamp(GrantMinutes, 1, 24 * 60);
        ApprovalTimeoutSeconds = Math.Clamp(ApprovalTimeoutSeconds, 15, 300);
        LockAfterIdleMinutes = Math.Clamp(LockAfterIdleMinutes, 0, 24 * 60);
        SyncIntervalMinutes = Math.Clamp(SyncIntervalMinutes, 0, 24 * 60);
        if (string.IsNullOrWhiteSpace(PipeName) || PipeName.Contains('\\'))
        {
            PipeName = "openssh-ssh-agent";
        }
    }
}

/// <summary>Start with Windows via HKCU\...\Run.</summary>
public static class AutoStart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "BwSshAgent";

    public static bool IsEnabled
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(ValueName) is string;
        }
    }

    public static void Set(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled)
        {
            key.SetValue(ValueName, $"\"{Environment.ProcessPath}\" --background");
        }
        else if (key.GetValue(ValueName) != null)
        {
            key.DeleteValue(ValueName);
        }
    }

    /// <summary>Keeps the registered path current when the app is moved or updated.</summary>
    public static void RefreshPath()
    {
        if (IsEnabled)
        {
            Set(true);
        }
    }
}
