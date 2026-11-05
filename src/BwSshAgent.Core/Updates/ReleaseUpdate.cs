using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BwSshAgent.Core.Updates;

public sealed record ReleaseUpdate(string Version, Uri Url)
{
    public static readonly Uri LatestUrl = new("https://github.com/luoxiaoxin123/bwssh/releases/latest");
    private static readonly Regex VersionPattern = new(@"^[vV]?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant);

    private static (System.Version Version, bool Prerelease)? Parse(string value)
    {
        var match = VersionPattern.Match(value);
        if (!match.Success || match.Length != value.Length || !int.TryParse(match.Groups[1].Value, out var major) ||
            !int.TryParse(match.Groups[2].Value, out var minor) || !int.TryParse(match.Groups[3].Value, out var patch))
        {
            return null;
        }
        return (new System.Version(major, minor, patch), match.Groups[4].Success);
    }

    public static ReleaseUpdate? FromJson(string json, string currentVersion)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (!root.TryGetProperty("draft", out var draft) || draft.ValueKind != JsonValueKind.False ||
                !root.TryGetProperty("prerelease", out var prerelease) || prerelease.ValueKind != JsonValueKind.False ||
                !root.TryGetProperty("tag_name", out var tagValue) || tagValue.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            var tag = tagValue.GetString()!;
            var latest = Parse(tag);
            var current = Parse(currentVersion);
            if (latest == null || current == null || latest.Value.Prerelease ||
                latest.Value.Version < current.Value.Version ||
                (latest.Value.Version == current.Value.Version && !current.Value.Prerelease))
            {
                return null;
            }
            var version = tag.StartsWith('v') || tag.StartsWith('V') ? tag[1..] : tag;
            return new ReleaseUpdate(version, new Uri("https://github.com/luoxiaoxin123/bwssh/releases/tag/" + Uri.EscapeDataString(tag)));
        }
        catch (JsonException) { return null; }
        catch (InvalidOperationException) { return null; }
    }
}

public static class ReleaseChecker
{
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(8) };
    public static async Task<ReleaseUpdate?> CheckAsync(string currentVersion, CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/repos/luoxiaoxin123/bwssh/releases/latest");
            request.Headers.UserAgent.ParseAdd("bwssh");
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await Client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) { return null; }
            return ReleaseUpdate.FromJson(await response.Content.ReadAsStringAsync(cancellationToken), currentVersion);
        }
        catch (HttpRequestException) { return null; }
        catch (OperationCanceledException) { return null; }
    }
}
