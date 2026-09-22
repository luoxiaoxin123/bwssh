namespace BwSshAgent.Core.Bitwarden;

public enum ServerKind
{
    BitwardenUs,
    BitwardenEu,
    SelfHosted,
}

public sealed record ServerEnvironment(ServerKind Kind, string? BaseUrl = null, string? CustomIdentityUrl = null, string? CustomApiUrl = null)
{
    public static ServerEnvironment Us { get; } = new(ServerKind.BitwardenUs);
    public static ServerEnvironment Eu { get; } = new(ServerKind.BitwardenEu);

    public static ServerEnvironment SelfHosted(string baseUrl, string? identityUrl = null, string? apiUrl = null)
    {
        var normalized = Normalize(baseUrl) ?? throw new ArgumentException(L.T("服务器地址无效。", "Invalid server URL."));
        return new ServerEnvironment(ServerKind.SelfHosted, normalized, Normalize(identityUrl), Normalize(apiUrl));
    }

    public string IdentityUrl => Kind switch
    {
        ServerKind.BitwardenUs => "https://identity.bitwarden.com",
        ServerKind.BitwardenEu => "https://identity.bitwarden.eu",
        _ => CustomIdentityUrl ?? BaseUrl + "/identity",
    };

    public string ApiUrl => Kind switch
    {
        ServerKind.BitwardenUs => "https://api.bitwarden.com",
        ServerKind.BitwardenEu => "https://api.bitwarden.eu",
        _ => CustomApiUrl ?? BaseUrl + "/api",
    };

    public string DisplayName => Kind switch
    {
        ServerKind.BitwardenUs => "bitwarden.com",
        ServerKind.BitwardenEu => "bitwarden.eu",
        _ => BaseUrl ?? CustomApiUrl ?? L.T("自托管", "Self-hosted"),
    };

    private static string? Normalize(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }
        url = url.Trim().TrimEnd('/');
        if (!url.Contains("://", StringComparison.Ordinal))
        {
            url = "https://" + url;
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            return null;
        }
        return url;
    }
}
