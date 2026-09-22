using System.Text.Json;
using BwSshAgent.Core.Storage;

namespace BwSshAgent.Core.Audit;

public sealed class AuditEntry
{
    public DateTimeOffset Time { get; set; }
    public string Decision { get; set; } = "";
    public string Operation { get; set; } = "";
    public string KeyName { get; set; } = "";
    public string? KeyFingerprint { get; set; }
    public string Process { get; set; } = "";
    public int Pid { get; set; }
    public string? GrantTarget { get; set; }
    public string? Destination { get; set; }
    public string? RemoteUser { get; set; }
    public bool Forwarded { get; set; }
    public string? HostFingerprint { get; set; }
}

/// <summary>Append-only JSONL audit log, one file per day. Contains no secrets.</summary>
public sealed class AuditLog
{
    // Keep non-ASCII text (key names, decisions) readable when the file is opened directly.
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
    private readonly Lock _gate = new();

    public int RetentionDays { get; init; } = 30;

    public event Action<AuditEntry>? EntryAdded;

    public void Append(AuditEntry entry)
    {
        try
        {
            lock (_gate)
            {
                var path = Path.Combine(AppPaths.AuditDir, $"audit-{entry.Time.LocalDateTime:yyyyMMdd}.jsonl");
                File.AppendAllText(path, JsonSerializer.Serialize(entry, Options) + "\n");
            }
        }
        catch (Exception ex)
        {
            Log.Error("Failed to write audit entry", ex);
        }
        EntryAdded?.Invoke(entry);
    }

    public List<AuditEntry> ReadRecent(int days = 7, int max = 2000)
    {
        var result = new List<AuditEntry>();
        lock (_gate)
        {
            var files = Directory.GetFiles(AppPaths.AuditDir, "audit-*.jsonl").OrderDescending().Take(days);
            foreach (var file in files)
            {
                foreach (var line in File.ReadAllLines(file).Reverse())
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }
                    try
                    {
                        var e = JsonSerializer.Deserialize<AuditEntry>(line, Options);
                        if (e != null)
                        {
                            result.Add(e);
                        }
                    }
                    catch (JsonException)
                    {
                    }
                    if (result.Count >= max)
                    {
                        return result;
                    }
                }
            }
        }
        return result;
    }

    public void Cleanup()
    {
        try
        {
            var cutoff = DateTime.Now.Date.AddDays(-RetentionDays);
            foreach (var file in Directory.GetFiles(AppPaths.AuditDir, "audit-*.jsonl"))
            {
                var stamp = Path.GetFileNameWithoutExtension(file)["audit-".Length..];
                if (DateTime.TryParseExact(stamp, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out var day) && day < cutoff)
                {
                    File.Delete(file);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error("Audit cleanup failed", ex);
        }
    }

    public string Folder => AppPaths.AuditDir;
}
