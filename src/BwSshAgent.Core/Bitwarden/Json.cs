using System.Text.Json.Nodes;

namespace BwSshAgent.Core.Bitwarden;

/// <summary>Case-insensitive accessors: Bitwarden servers return PascalCase or camelCase depending on version.</summary>
internal static class J
{
    public static JsonNode? Get(JsonNode? node, string name)
    {
        if (node is not JsonObject obj)
        {
            return null;
        }
        if (obj.TryGetPropertyValue(name, out var direct))
        {
            return direct;
        }
        foreach (var kv in obj)
        {
            if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return kv.Value;
            }
        }
        return null;
    }

    public static string? Str(JsonNode? node, string name)
    {
        var v = Get(node, name);
        return v is JsonValue jv && jv.TryGetValue<string>(out var s) ? s : null;
    }

    public static int? Int(JsonNode? node, string name)
    {
        var v = Get(node, name);
        if (v is JsonValue jv)
        {
            if (jv.TryGetValue<int>(out var i))
            {
                return i;
            }
            if (jv.TryGetValue<long>(out var l))
            {
                return (int)l;
            }
            if (jv.TryGetValue<double>(out var d))
            {
                return (int)d;
            }
            if (jv.TryGetValue<string>(out var s) && int.TryParse(s, out var p))
            {
                return p;
            }
        }
        return null;
    }

    public static bool IsNull(JsonNode? node, string name) => Get(node, name) is null;

    public static JsonArray Arr(JsonNode? node, string name) => Get(node, name) as JsonArray ?? [];
}
