using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Contract;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2065: checks a browser_extensions_status block, with the rows it describes, against the
/// platform's contract exactly as the platform reads it. Compiled into Shared.Tests and linked
/// into Service.Tests, so both suites hold the Windows agent to one checker.
///
/// Structure: the block and the rows are serialised with the payload's own options and run
/// through the vendored schema, contracts/inventory-browser-extensions-status.schema.json (a
/// verbatim copy of patched.im's payload.schema.json properties). No JSON Schema library is
/// referenced by these projects, so <see cref="Validate"/> interprets the keywords that copy
/// uses and throws on any other, so a re-vendored schema that adds one cannot pass unchecked.
///
/// Consistency: <see cref="Problem"/> is a line-for-line port of browserExtensionsStatusProblem
/// in patched.im go-service/internal/extractor/validate_browser_extensions_status.go. Any reason
/// it returns is one the platform would withhold the block's authority for. The macOS twin is
/// check.py in macos/lib/test-browser-extensions.zsh.
/// </summary>
internal static class BrowserExtensionsStatusContract
{
    /// <summary>Mirrors InventoryPoster.JsonOpts, as InventoryPayloadSerializationTests does.</summary>
    internal static readonly JsonSerializerOptions WireOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    private static readonly string[] Browsers = ["chrome", "edge", "firefox"];

    /// <summary>"OK", or the first schema error or withheld reason.</summary>
    public static string Check(InventoryBrowserExtensionsStatus status, IReadOnlyList<InventoryBrowserExtension> rows)
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["browser_extensions_status"] = status,
            ["browser_extensions"] = rows,
        }, WireOptions);
        using var doc = JsonDocument.Parse(json);
        return CheckJson(doc.RootElement);
    }

    /// <summary><see cref="Check"/> over an already serialised {browser_extensions_status, browser_extensions}.</summary>
    public static string CheckJson(JsonElement payload)
    {
        // Opt-in: PATCHED_BX_STATUS_DUMP=<dir> keeps every checked payload, so it can also be
        // run through patched.im's own Go validator (see macos/lib/test-browser-extensions.zsh).
        if (Environment.GetEnvironmentVariable("PATCHED_BX_STATUS_DUMP") is { Length: > 0 } dump)
            File.WriteAllText(Path.Combine(dump, "win-" + Guid.NewGuid().ToString("N") + ".json"), payload.GetRawText());
        using var schemaDoc = JsonDocument.Parse(File.ReadAllText(LocateContract()));
        var error = Validate(schemaDoc.RootElement, payload, "");
        if (error is not null) return "schema: " + error;
        var reason = Problem(payload.GetProperty("browser_extensions_status"),
            payload.TryGetProperty("browser_extensions", out var rows) ? rows : default);
        return reason.Length == 0 ? "OK" : "withheld: " + reason;
    }

    private static readonly HashSet<string> Annotations =
        new(StringComparer.Ordinal) { "$schema", "$id", "$comment", "description", "examples", "title" };

    /// <summary>The first error of <paramref name="value"/> against <paramref name="schema"/>, or null.</summary>
    internal static string? Validate(JsonElement schema, JsonElement value, string at)
    {
        foreach (var keyword in schema.EnumerateObject())
        {
            if (Annotations.Contains(keyword.Name)) continue;
            switch (keyword.Name)
            {
                case "type":
                    var types = keyword.Value.ValueKind == JsonValueKind.Array
                        ? keyword.Value.EnumerateArray().Select(t => t.GetString()!).ToArray()
                        : [keyword.Value.GetString()!];
                    if (!types.Any(t => IsType(value, t)))
                        return $"{at}: {value.ValueKind} is not {string.Join("|", types)}";
                    break;
                case "enum":
                    if (!keyword.Value.EnumerateArray().Any(e => e.ValueKind == value.ValueKind && e.GetRawText() == value.GetRawText()))
                        return $"{at}: {value} is not in the enum";
                    break;
                case "required":
                    if (value.ValueKind != JsonValueKind.Object) break;
                    foreach (var name in keyword.Value.EnumerateArray())
                        if (!value.TryGetProperty(name.GetString()!, out _))
                            return $"{at}: required key {name.GetString()} is missing";
                    break;
                case "properties":
                    if (value.ValueKind != JsonValueKind.Object) break;
                    foreach (var prop in keyword.Value.EnumerateObject())
                        if (value.TryGetProperty(prop.Name, out var child) &&
                            Validate(prop.Value, child, at + "/" + prop.Name) is { } childError)
                            return childError;
                    break;
                case "additionalProperties":
                    if (value.ValueKind != JsonValueKind.Object) break;
                    if (keyword.Value.ValueKind == JsonValueKind.True) break;
                    if (keyword.Value.ValueKind != JsonValueKind.False)
                        throw new NotSupportedException("additionalProperties schema at " + at);
                    var declared = schema.TryGetProperty("properties", out var props)
                        ? props.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal)
                        : [];
                    foreach (var prop in value.EnumerateObject())
                        if (!declared.Contains(prop.Name))
                            return $"{at}: unknown key {prop.Name}";
                    break;
                case "items":
                    if (value.ValueKind != JsonValueKind.Array) break;
                    var i = 0;
                    foreach (var item in value.EnumerateArray())
                    {
                        if (Validate(keyword.Value, item, $"{at}[{i}]") is { } itemError) return itemError;
                        i++;
                    }
                    break;
                case "maxItems":
                    if (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() > keyword.Value.GetInt32())
                        return $"{at}: more than {keyword.Value.GetInt32()} items";
                    break;
                case "minLength":
                    if (value.ValueKind == JsonValueKind.String && value.GetString()!.Length < keyword.Value.GetInt32())
                        return $"{at}: shorter than {keyword.Value.GetInt32()}";
                    break;
                default:
                    throw new NotSupportedException(
                        $"schema keyword '{keyword.Name}' at {at} is not interpreted; extend BrowserExtensionsStatusContract.Validate");
            }
        }
        return null;
    }

    private static bool IsType(JsonElement v, string type) => type switch
    {
        "object"  => v.ValueKind == JsonValueKind.Object,
        "array"   => v.ValueKind == JsonValueKind.Array,
        "string"  => v.ValueKind == JsonValueKind.String,
        "boolean" => v.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "null"    => v.ValueKind == JsonValueKind.Null,
        "integer" => v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out _),
        "number"  => v.ValueKind == JsonValueKind.Number,
        _ => throw new NotSupportedException("type " + type),
    };

    private static bool Fits(string parent, string child) => parent switch
    {
        "complete"    => child is "complete" or "not_present",
        "not_present" => child == "not_present",
        _             => true,
    };

    /// <summary>Port of browserExtensionsStatusProblem, plus the structural rules the schema cannot say.</summary>
    internal static string Problem(JsonElement st, JsonElement rows)
    {
        var status = st.GetProperty("collection_status").GetString()!;
        if (status == "failed") return "";
        // validateBrowserExtensionsStatus: every other status sends cap_reached and users, and
        // every browser key unless the user is failed. These reject the payload (400).
        if (!st.TryGetProperty("cap_reached", out var capEl) || !st.TryGetProperty("users", out var usersEl))
            return "structure: cap_reached and users are required unless failed";
        foreach (var u in usersEl.EnumerateArray())
            if (u.GetProperty("collection_status").GetString() != "failed" &&
                Browsers.Any(b => !u.GetProperty("browsers").TryGetProperty(b, out _)))
                return "structure: every browser is required unless the user is failed";

        if (capEl.GetBoolean() && status != "partial") return "cap_reached_not_partial";
        if (usersEl.GetArrayLength() > 500) return "too_many_users";
        var pairs = new Dictionary<(string, string), string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var u in usersEl.EnumerateArray())
        {
            var user = u.GetProperty("user").GetString()!;
            if (!seen.Add(user)) return "duplicate_user";
            var ust = u.GetProperty("collection_status").GetString()!;
            if (!Fits(status, ust)) return "user_status_inconsistent";
            foreach (var b in Browsers)
            {
                if (!u.GetProperty("browsers").TryGetProperty(b, out var bEl)) continue;
                var bst = bEl.GetString()!;
                if (!Fits(status, bst) || !Fits(ust, bst)) return "browser_status_inconsistent";
                pairs[(user, b)] = bst;
            }
        }
        if (rows.ValueKind != JsonValueKind.Array) return "";
        foreach (var r in rows.EnumerateArray())
        {
            var account = r.TryGetProperty("user_account", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString()! : "";
            var browser = r.GetProperty("browser").GetString()!;
            if (account.Length == 0 || !Browsers.Contains(browser)) continue;
            var listed = pairs.TryGetValue((account, browser), out var pst);
            if (status == "not_present") return "rows_listed_when_not_present";
            if (listed && pst == "not_present") return "row_under_not_present_pair";
            if (status == "complete" && pst != "complete") return "row_not_reported_complete";
        }
        return "";
    }

    private static string LocateContract()
    {
        const string name = "inventory-browser-extensions-status.schema.json";
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "contracts", name);
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException($"contracts/{name} not found walking up from {AppContext.BaseDirectory}");
    }
}
