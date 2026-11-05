using BwSshAgent.Core.Updates;
using System.Text.Json;

namespace BwSshAgent.Core.Tests;

public class ReleaseUpdateTests
{
    [Theory]
    [InlineData("0.3.0", "v0.3.1", true)]
    [InlineData("0.9.0", "v0.10.0", true)]
    [InlineData("0.3.0", "0.3.0", false)]
    [InlineData("1.0.0", "v0.9.9", false)]
    [InlineData("0.3.0-beta.1", "v0.3.0", true)]
    [InlineData("0.3.0+build.1", "v0.3.0+build.2", false)]
    [InlineData("0.3.0", "v0.4.0-beta", false)]
    [InlineData("0.3.0", "not-a-version", false)]
    [InlineData("invalid", "v0.4.0", false)]
    [InlineData("0.3.0", "v0.4.0/evil", false)]
    [InlineData("0.3.0", "v0.4.0\n", false)]
    [InlineData("0.3.0", "v9999999999999999.0.0", false)]
    public void ComparesVersionsNumerically(string current, string tag, bool expected)
    {
        var json = JsonSerializer.Serialize(new { tag_name = tag, draft = false, prerelease = false, html_url = "https://untrusted.example/" });
        var update = ReleaseUpdate.FromJson(json, current);
        Assert.Equal(expected, update != null);
        if (update != null)
        {
            Assert.Equal("github.com", update.Url.Host);
            Assert.StartsWith("/luoxiaoxin123/bwssh/releases/tag/", update.Url.AbsolutePath);
        }
    }

    [Fact]
    public void SkipsDraftsPrereleasesAndMalformedResponses()
    {
        Assert.Null(ReleaseUpdate.FromJson("{broken", "0.3.0"));
        Assert.Null(ReleaseUpdate.FromJson("[]", "0.3.0"));
        Assert.Null(ReleaseUpdate.FromJson("{}", "0.3.0"));
        Assert.Null(ReleaseUpdate.FromJson("{\"tag_name\":\"v0.4.0\",\"draft\":true,\"prerelease\":false}", "0.3.0"));
        Assert.Null(ReleaseUpdate.FromJson("{\"tag_name\":\"v0.4.0\",\"draft\":false,\"prerelease\":true}", "0.3.0"));
        var release = ReleaseUpdate.FromJson("{\"tag_name\":\"v0.3.1\",\"draft\":false,\"prerelease\":false}", "0.3.0");
        Assert.Equal("https://github.com/luoxiaoxin123/bwssh/releases/tag/v0.3.1", release?.Url.AbsoluteUri);
    }
}
