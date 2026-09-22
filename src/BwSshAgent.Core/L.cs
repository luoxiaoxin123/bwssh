using System.Globalization;

namespace BwSshAgent.Core;

/// <summary>UI language: Chinese when the Windows display language is Chinese, English otherwise.</summary>
public static class L
{
    public static bool Zh { get; set; } = Environment.GetEnvironmentVariable("BWSSH_LANG") switch
    {
        "zh" => true,
        "en" => false,
        _ => CultureInfo.CurrentUICulture.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase),
    };

    public static string T(string zh, string en) => Zh ? zh : en;
}
