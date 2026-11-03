using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// PAT-1108/PAT-1110. Tenant-wide agent-decommission directive delivered inside the
/// signed agent-config (see contracts/agent-config.schema.json's "decommission" block).
/// This is the ONLY irreversible directive in the contract: once an agent removes
/// itself there is no channel left to correct a mistake. Every field here is only
/// ever trusted after it has passed through <see cref="AgentConfigFetcher"/>'s
/// existing Ed25519 + tenant + anti-rollback verification — this type itself performs
/// no verification, only defensive parsing.
///
/// Deliberately modelled on raw-string-plus-resolved-property, the same idiom
/// <see cref="BlockingProcessPolicy"/> uses for <c>action_on_timeout</c>: an
/// unrecognised or malformed value must degrade to a safe/inert reading rather than
/// throw a <see cref="JsonException"/> out of the whole <c>AgentConfig</c> document
/// (the PAT-737 proxy-port regression this mirrors the fix for) — but unlike
/// BlockingProcessPolicy, "safe" here always means "do not remove the agent", which
/// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/> enforces by treating
/// anything not cleanly resolvable as a fault, never as silently "none".
///
/// <see cref="Reason"/> is recorded and surfaced for operator/audit visibility only.
/// It MUST NEVER be evaluated as part of removal control flow — see the schema's own
/// warning on this field.
/// </summary>
[JsonConverter(typeof(DecommissionPolicyConverter))]
public sealed record DecommissionPolicy
{
    /// <summary>Raw wire value of "mode". Use <see cref="ResolvedMode"/>/<see cref="IsRecognisedMode"/>.</summary>
    [JsonPropertyName("mode")]
    public string? ModeRaw { get; init; }

    /// <summary>Raw wire value of "expires_at". Use <see cref="ExpiresAt"/>/<see cref="ExpiresAtPresent"/>.</summary>
    [JsonPropertyName("expires_at")]
    public string? ExpiresAtRaw { get; init; }

    /// <summary>
    /// When true, decommission also removes locally cached credentials/queue/state,
    /// not just the agent's own service+binaries. Default false — the minimum-scope
    /// removal. Must match the macOS purge split exactly (parity is a release gate,
    /// ADR-0007): credentials and queue removed when true, retained when false.
    /// </summary>
    [JsonPropertyName("purge")]
    public bool Purge { get; init; }

    /// <summary>
    /// Free-text operator-supplied context. Recorded/surfaced only — NEVER evaluated
    /// in control flow.
    /// </summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    /// <summary>
    /// True only for the three contract-recognised values. Anything else — including
    /// null (mode present but not a JSON string, or genuinely absent within a present
    /// object) — is NOT recognised and must be treated as a fault by
    /// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/>, never silently
    /// folded into "none".
    /// </summary>
    [JsonIgnore]
    public bool IsRecognisedMode => ModeRaw is "none" or "expiry" or "immediate";

    [JsonIgnore]
    public DecommissionMode ResolvedMode => ModeRaw switch
    {
        "expiry"    => DecommissionMode.Expiry,
        "immediate" => DecommissionMode.Immediate,
        _           => DecommissionMode.None, // "none" and every unrecognised value alike
    };

    [JsonIgnore]
    public bool ExpiresAtPresent => !string.IsNullOrWhiteSpace(ExpiresAtRaw);

    /// <summary>
    /// Non-author review (round 2, item 1): <see cref="DateTimeOffset.TryParse"/> is
    /// PERMISSIVE — it accepts a timezone-less, locale-style value (e.g.
    /// "2026-12-01 00:00:00") and silently resolves it using the ENDPOINT'S LOCAL
    /// timezone, not UTC. A malformed or truncated signed <c>expires_at</c> could
    /// therefore resolve to an earlier-than-intended (or simply wrong) instant and
    /// tip <see cref="Patched.Shared.Removal.DecommissionEvaluator"/> into
    /// <c>Due</c> on a value that was never a valid RFC3339 instant at all. Every
    /// format in <see cref="Rfc3339ZFormats"/>/<see cref="Rfc3339OffsetFormats"/>
    /// REQUIRES an explicit UTC designator to even match — a literal <c>'Z'</c>
    /// (paired with <see cref="DateTimeStyles.AssumeUniversal"/>, safe only because
    /// the literal match already proves the designator was present in the input) or
    /// an explicit <c>zzz</c> numeric offset (which <see cref="DateTimeStyles.None"/>
    /// parses directly from the input, needing no assumption at all) — so a value
    /// with no offset at all fails to parse by either array, not by ambiguous local
    /// resolution. This is the Windows equivalent of the macOS agent's strict-parse
    /// + trusted-time requirement for the same field.
    /// </summary>
    private static readonly string[] Rfc3339ZFormats =
    {
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
    };

    private static readonly string[] Rfc3339OffsetFormats =
    {
        "yyyy-MM-dd'T'HH:mm:sszzz",
        "yyyy-MM-dd'T'HH:mm:ss.fffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.fffffffzzz",
    };

    /// <summary>internal (not private): directly unit tested — see DecommissionPolicyTests.</summary>
    internal static bool TryParseStrictRfc3339(string? raw, out DateTimeOffset result)
    {
        if (raw is not null &&
            DateTimeOffset.TryParseExact(
                raw, Rfc3339ZFormats, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out result))
            return true;

        if (raw is not null &&
            DateTimeOffset.TryParseExact(
                raw, Rfc3339OffsetFormats, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out result))
            return true;

        result = default;
        return false;
    }

    /// <summary>
    /// Parsed RFC3339 timestamp, or null if absent/unparseable/missing an explicit
    /// UTC offset. A null result while <see cref="ExpiresAtPresent"/> is true means
    /// the raw value could not be strictly parsed —
    /// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/> treats that as a
    /// fault (malformed value), never as "no expiry".
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset? ExpiresAt =>
        ExpiresAtPresent && TryParseStrictRfc3339(ExpiresAtRaw, out var parsed) ? parsed : null;

    /// <summary>
    /// Inert defaults — used only when the wire object was present but its shape was
    /// unrecognisable (see <see cref="DecommissionPolicyConverter"/>). NOT used for
    /// "decommission absent from the document entirely": <c>AgentConfig.Decommission</c>
    /// has no object initializer, so it stays null in that case, which
    /// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/> treats as its own
    /// distinct fault ("object absent").
    /// </summary>
    public static DecommissionPolicy Defaults { get; } = new();
}

/// <summary>Type-safe resolved decommission mode. See <see cref="DecommissionPolicy.ResolvedMode"/>.</summary>
public enum DecommissionMode
{
    None,
    Expiry,
    Immediate,
}

/// <summary>
/// Never-throwing converter for the "decommission" block. A malformed shape (wrong
/// JSON type for a field, e.g. <c>"mode": 123</c> or <c>"purge": "true"</c>) must
/// degrade to an unrecognised/safe reading, never crash the whole
/// <c>AgentConfig.Deserialize</c> call the way default System.Text.Json object
/// binding would for a non-nullable <c>bool</c> or a type-mismatched property (the
/// class of bug PAT-737 already burned this codebase on once, for proxy.port).
///
/// Absence handling is NOT done here — System.Text.Json never invokes a converter
/// for a JSON property that is missing entirely, so <c>AgentConfig.Decommission</c>
/// (which has no object-initializer default) stays null in that case. That is
/// intentional: "decommission absent from the document" and "decommission present
/// but unrecognisable" are both faults, but distinct ones, and
/// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/> reports them with
/// different reasons.
/// </summary>
public sealed class DecommissionPolicyConverter : JsonConverter<DecommissionPolicy>
{
    public override DecommissionPolicy Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        try
        {
            using var doc = JsonDocument.ParseValue(ref reader);
            var el = doc.RootElement;

            // Not an object at all (e.g. "decommission": "oops") -> every raw field
            // stays null/false, which IsRecognisedMode reports as unrecognised.
            if (el.ValueKind != JsonValueKind.Object)
                return DecommissionPolicy.Defaults;

            return new DecommissionPolicy
            {
                ModeRaw      = GetString(el, "mode"),
                ExpiresAtRaw = GetString(el, "expires_at"),
                Reason       = GetString(el, "reason"),
                // Wrong JSON type (e.g. a string "true") degrades to the SAFER
                // (less destructive) default, false — never to true.
                Purge = TryGetPropertyIgnoreCase(el, "purge", out var p) && p.ValueKind == JsonValueKind.True,
            };
        }
        catch
        {
            // Any parse surprise (truncated value, reader in an unexpected state,
            // etc.) — fail closed to the inert/unrecognised default rather than let
            // the exception propagate out of AgentConfig.Deserialize.
            return DecommissionPolicy.Defaults;
        }
    }

    // JsonElement.TryGetProperty has no case-insensitive overload, but the rest of
    // AgentConfig.Deserialize IS case-insensitive (DeserializeOptions.PropertyNameCaseInsensitive),
    // so a nested object handled by manual JsonElement inspection (rather than
    // reflection-driven binding) must match that behaviour explicitly or it silently
    // becomes the one exception to an otherwise-documented contract property.
    private static bool TryGetPropertyIgnoreCase(JsonElement el, string name, out JsonElement value)
    {
        foreach (var prop in el.EnumerateObject())
        {
            if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }
        value = default;
        return false;
    }

    private static string? GetString(JsonElement el, string name) =>
        TryGetPropertyIgnoreCase(el, name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    public override void Write(Utf8JsonWriter writer, DecommissionPolicy value, JsonSerializerOptions options) =>
        throw new NotSupportedException("DecommissionPolicy is never serialized by the agent.");
}
