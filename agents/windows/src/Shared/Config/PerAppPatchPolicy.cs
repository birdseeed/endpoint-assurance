using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// Per-tenant app-update policy (PAT-167 / PAT-364 store), delivered inside the
/// signed agent config as <c>per_app_patch</c>. Windows parity with the macOS
/// PAT-365 consumer (macos-agent/patched-update.sh): the updater honours a
/// per-app on/off toggle layered over an estate-wide default.
///
/// Resolution order — identical to the macOS script's <c>policy_allows</c>:
///   1. an explicit override whose <c>platform == "windows"</c> and whose
///      <c>identifier</c> matches the app (winget id or the shared label) — wins;
///   2. otherwise the estate default (<c>fleet_default_enabled</c>);
///   3. a null / absent / malformed policy degrades to "all enabled" — the same
///      fail-open as the macOS script (updates keep flowing rather than silently
///      stopping when the policy can't be read).
///
/// The wire shape is <c>null | bool | object</c>; <see cref="PerAppPatchPolicyConverter"/>
/// tolerates all three so a malformed field never bricks agent-config deserialization.
/// </summary>
[JsonConverter(typeof(PerAppPatchPolicyConverter))]
public sealed record PerAppPatchPolicy
{
    /// <summary>"override" — an explicit per-app row matched.</summary>
    public const string SourceOverride = "override";

    /// <summary>"fleet_default" — no per-app row matched; the estate default applied.</summary>
    public const string SourceFleetDefault = "fleet_default";

    /// <summary>Fleet-wide on/off applied when no per-app override matches. Defaults to on.</summary>
    public bool FleetDefaultEnabled { get; init; } = true;

    /// <summary>Per-app overrides. Only rows whose platform matches are consulted.</summary>
    public IReadOnlyList<AppUpdateOverride> Overrides { get; init; } = Array.Empty<AppUpdateOverride>();

    /// <summary>
    /// True if updates are enabled for an app on <paramref name="platform"/> whose
    /// identity matches any of <paramref name="identifiers"/> (case-insensitive).
    /// An explicit override wins; otherwise the estate default applies.
    /// </summary>
    public bool Allows(string platform, params string?[] identifiers) =>
        FindOverride(platform, identifiers)?.Enabled ?? FleetDefaultEnabled;

    /// <summary>"override" if a matching per-app row exists, else "fleet_default".</summary>
    public string SourceFor(string platform, params string?[] identifiers) =>
        FindOverride(platform, identifiers) is null ? SourceFleetDefault : SourceOverride;

    /// <summary>
    /// Treats a null policy as "all enabled" — the macOS fail-open default — so
    /// callers don't have to null-check before resolving.
    /// </summary>
    public static bool AllowsOrDefault(PerAppPatchPolicy? policy, string platform, params string?[] identifiers) =>
        policy?.Allows(platform, identifiers) ?? true;

    private AppUpdateOverride? FindOverride(string platform, string?[] identifiers)
    {
        foreach (var o in Overrides)
        {
            if (!string.Equals(o.Platform, platform, StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var id in identifiers)
            {
                if (!string.IsNullOrEmpty(id) &&
                    string.Equals(o.Identifier, id, StringComparison.OrdinalIgnoreCase))
                    return o;
            }
        }
        return null;
    }
}

/// <summary>One per-app override row from the per-tenant app-update policy store.</summary>
public sealed record AppUpdateOverride
{
    public string Platform   { get; init; } = "";
    public string Identifier { get; init; } = "";
    public bool   Enabled    { get; init; } = true;
}

/// <summary>
/// Tolerant reader for <c>per_app_patch</c>. The platform emits <c>null</c> or an
/// object; a bare bool is accepted defensively. Anything unparseable degrades to
/// the fail-open default (null → "all enabled" at the call site) rather than
/// throwing and discarding the whole signed config.
/// </summary>
public sealed class PerAppPatchPolicyConverter : JsonConverter<PerAppPatchPolicy?>
{
    public override PerAppPatchPolicy? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;                                          // absent → all enabled
            case JsonTokenType.True:
                return new PerAppPatchPolicy();                       // bool true → estate default on
            case JsonTokenType.False:
                return new PerAppPatchPolicy { FleetDefaultEnabled = false };
            case JsonTokenType.StartObject:
                // ParseValue consumes the whole object and advances the reader
                // correctly even if mapping below decides to ignore a field.
                using (var doc = JsonDocument.ParseValue(ref reader))
                    return MapObject(doc.RootElement);
            default:
                reader.Skip();
                return null;                                          // unexpected shape → all enabled
        }
    }

    private static PerAppPatchPolicy MapObject(JsonElement el)
    {
        bool defaultEnabled = true;
        if (el.TryGetProperty("fleet_default_enabled", out var f) &&
            f.ValueKind == JsonValueKind.False)
            defaultEnabled = false;

        var overrides = new List<AppUpdateOverride>();
        if (el.TryGetProperty("overrides", out var ov) && ov.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in ov.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;

                string identifier = item.TryGetProperty("identifier", out var i) &&
                                    i.ValueKind == JsonValueKind.String
                    ? i.GetString()! : "";
                if (identifier.Length == 0) continue;                  // unkeyed row is meaningless

                string platform = item.TryGetProperty("platform", out var p) &&
                                  p.ValueKind == JsonValueKind.String
                    ? p.GetString()! : "";

                // Default enabled=true; only an explicit `false` disables (parity
                // with the macOS o.get('enabled', True) semantics).
                bool enabled = !item.TryGetProperty("enabled", out var e) ||
                               e.ValueKind != JsonValueKind.False;

                overrides.Add(new AppUpdateOverride
                {
                    Platform   = platform,
                    Identifier = identifier,
                    Enabled    = enabled,
                });
            }
        }

        return new PerAppPatchPolicy { FleetDefaultEnabled = defaultEnabled, Overrides = overrides };
    }

    public override void Write(
        Utf8JsonWriter writer, PerAppPatchPolicy? value, JsonSerializerOptions options)
    {
        if (value is null) { writer.WriteNullValue(); return; }

        writer.WriteStartObject();
        writer.WriteBoolean("fleet_default_enabled", value.FleetDefaultEnabled);
        writer.WriteStartArray("overrides");
        foreach (var o in value.Overrides)
        {
            writer.WriteStartObject();
            writer.WriteString("platform", o.Platform);
            writer.WriteString("identifier", o.Identifier);
            writer.WriteBoolean("enabled", o.Enabled);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
    }
}
