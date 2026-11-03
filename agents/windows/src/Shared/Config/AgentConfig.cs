using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// The separate authority for retained Application Control actions. This is not
/// the package-execution tier: report observes, block may manage browser
/// blocklists, and enforce additionally permits one-way admin or extension
/// removal.
/// </summary>
public enum AppControlAuthority
{
    Report,
    Block,
    Enforce,
}

/// <summary>Fail-closed authority checks shared by the App Control call sites.</summary>
public static class AppControlAuthorityGate
{
    public static bool AllowsBlocklist(AppControlAuthority authority) =>
        authority is AppControlAuthority.Block or AppControlAuthority.Enforce;

    public static bool AllowsDestructiveAction(AppControlAuthority authority) =>
        authority == AppControlAuthority.Enforce;
}

/// <summary>
/// The full per-tenant agent-config response (PAT-282 parity).
/// Fetched from GET /v1/agent-config, Ed25519-signed by the platform (PAT-281),
/// verified client-side by <see cref="Ed25519Verifier"/> before it is trusted.
///
/// Never construct this from an unverified response — go through
/// AgentConfigFetcher, which verifies the signature first.
/// </summary>
public sealed record AgentConfig
{
    /// <summary>
    /// PAT-1481's retained Application Control authority split. This deliberately
    /// does not grant any legacy package action: InstallRunner, RemovalRunner,
    /// DeviceRemovalRunner, Installomator, and legacy macOS install/update/uninstall
    /// paths remain controlled solely by LegacyAppExecutionEnabled and their existing
    /// gates. Missing, null, malformed, noncanonical, ambiguous, and unknown values
    /// become Report.
    /// </summary>
    [JsonPropertyName("app_control_authority")]
    [JsonConverter(typeof(AppControlAuthorityConverter))]
    public AppControlAuthority AppControlAuthority { get; init; } = AppControlAuthority.Report;

    /// <summary>
    /// PAT-1481 containment switch for the quarantined legacy application-execution
    /// paths only. This is deliberately independent of capability tier: exact JSON
    /// <c>true</c> is necessary but never sufficient, because the execution path
    /// still applies its tier, provenance, ring, queue and operation
    /// gates. Absent, null and malformed values deserialize as false so an older
    /// platform cannot accidentally re-enable a retained executor.
    ///
    /// It is not an assurance switch. Inventory, OS-update policy, app-control
    /// reporting, browser-extension controls, approved-admin assurance,
    /// decommission, agent self-update, evidence/status/provenance reporting and
    /// config fetch remain governed by their own existing policies.
    /// </summary>
    [JsonPropertyName("legacy_app_execution_enabled")]
    [JsonConverter(typeof(ExactTrueBooleanConverter))]
    public bool LegacyAppExecutionEnabled { get; init; }

    /// <summary>
    /// PAT-296. Per-tenant blocking-process policy — controls agent behaviour when
    /// an app that must close to update is currently running.
    /// null / absent = safe defaults apply (NotifyOnly; 2 deferrals; 300s timeout).
    /// The agent MUST NEVER silently force-quit a running app — see
    /// <see cref="BlockingProcessPolicy.ResolvedAction"/> which falls back to
    /// <see cref="BlockingProcessAction.NotifyOnly"/> for any unrecognised value.
    /// </summary>
    [JsonPropertyName("blocking_process_policy")]
    public BlockingProcessPolicy BlockingProcessPolicy { get; init; } = BlockingProcessPolicy.Defaults;

    [JsonPropertyName("catalog_scope")]
    public string CatalogScope { get; init; } = "all";

    [JsonPropertyName("config_version")]
    public int ConfigVersion { get; init; }

    [JsonPropertyName("issued_at")]
    public string IssuedAt { get; init; } = "";

    [JsonPropertyName("os_update_policy")]
    public OsUpdatePolicy OsUpdatePolicy { get; init; } = new();

    /// <summary>
    /// PAT-1624. Bounds on the never-interrupt gate, in the same shape as
    /// os_update_policy's own tunables. null / absent = the shipped defaults.
    ///
    /// The gate itself is UNCONDITIONAL and applies at every tier, assurance
    /// included: it is a restraint, not a capability, and agents evaluate
    /// camera, microphone, presenting and Focus state before raising any
    /// user-facing prompt whether or not this block is present. Only these four
    /// numbers are tunable, and only at tier="managed". See
    /// <see cref="Patched.Shared.Interruption.InterruptionPolicy.Resolve"/>,
    /// which is the single place that rule is enforced.
    /// </summary>
    [JsonPropertyName("interruption_policy")]
    public Patched.Shared.Interruption.InterruptionPolicyOverrides? InterruptionPolicy { get; init; }

    /// <summary>
    /// Per-tenant app-update policy (PAT-365 macOS parity / PAT-381 Windows).
    /// null = no policy delivered → all managed apps remain enabled (fail-open).
    /// See <see cref="PerAppPatchPolicy"/> for the resolution rules.
    /// </summary>
    [JsonPropertyName("per_app_patch")]
    public PerAppPatchPolicy? PerAppPatch { get; init; }

    [JsonPropertyName("proxy")]
    public ProxyConfig Proxy { get; init; } = new();

    /// <summary>
    /// PAT-506: this device's deployment ring (0=internal, 1=canary, 2=early-adopter,
    /// 3=GA). Absent = 3 (most permissive). The platform assigns rings at onboarding.
    /// </summary>
    [JsonPropertyName("ring")]
    public int Ring { get; init; } = 3;

    /// <summary>
    /// PAT-506: per-label ring promotion table. Key = label; value = the ring this
    /// version has soaked through. Absent label = no gate (install proceeds).
    /// </summary>
    [JsonPropertyName("ring_promotions")]
    public IReadOnlyDictionary<string, RingPromotion>? RingPromotions { get; init; }

    /// <summary>
    /// PAT-1134: authoritative platform-aware rollout decisions. When present,
    /// this replaces the conservative legacy label-only projection.
    /// </summary>
    [JsonPropertyName("ring_promotions_scoped")]
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, ScopedRingPromotion>>? RingPromotionsScoped { get; init; }

    /// <summary>
    /// PAT-108: bootstrap loader update channel ("stable" | "beta").
    /// Null/absent = "stable". Used by the bootstrap loader to resolve the
    /// correct artifact version from /v1/agent/artifact.
    /// </summary>
    [JsonPropertyName("update_channel")]
    public string? UpdateChannel { get; init; }

    [JsonPropertyName("device_channel_overrides")]
    public JsonElement DeviceChannelOverrides { get; init; }

    [JsonPropertyName("update_channel_source")]
    public string? UpdateChannelSource { get; init; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; init; }

    // This cannot be granted by JSON or a plaintext cache. Only the fetcher
    // sets it after pinned signature, tenant and rollback verification.
    [JsonIgnore]
    internal bool UpdateAuthorityVerified { get; init; }

    // System.Text.Json is case-insensitive and otherwise keeps the last
    // duplicate member. The signed self-update policy must not turn either
    // ambiguity into beta/pin authority. AgentConfig.Deserialize sets this
    // from the original verified bytes; UpdateChannelPolicy fails closed on it.
    [JsonIgnore]
    internal bool UpdateAuthorityShapeInvalid { get; init; }

    /// <summary>
    /// PAT-108: pinned collector version. Null/absent = always use latest for channel.
    /// When set, the bootstrap loader requests this specific version from /v1/agent/artifact.
    /// </summary>
    [JsonPropertyName("pinned_version")]
    public string? PinnedVersion { get; init; }

    /// <summary>
    /// PAT-508: per-label blocked version lists. key = label, value = list of version strings
    /// the agent must never install. Empty / absent = no versions blocked.
    ///
    /// Wire shape: { "googlechrome": ["125.0.6422.60"], "slack": ["4.38.125"] }
    ///
    /// The agent checks this BEFORE installing — if the winget available version matches
    /// any entry, the install is skipped and a "version_blocked" audit event is shipped.
    /// A signed config update containing this field is the primary kill switch when a
    /// compromised or broken version has been distributed to endpoints.
    /// Fail-open: null / absent = no versions blocked (safe default).
    /// </summary>
    [JsonPropertyName("blocked_versions")]
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? BlockedVersions { get; init; }

    [JsonPropertyName("scan_cadence")]
    public string ScanCadence { get; init; } = "daily";

    [JsonPropertyName("tenant_id")]
    public string TenantId { get; init; } = "";

    /// <summary>
    /// "assurance" | "managed" (PAT-1599 collapsed this from the former three-value
    /// vocabulary "report_deploy" | "patch" | "managed" — "assurance observes,
    /// managed acts", one bit, not a ladder). Drives the tier gate in PatchedWorker
    /// (ActuatingTierAllows / DestructiveActuatingTierAllows — Worker.cs). Stays a
    /// plain string, not an enum, so an unrecognised or future value (including the
    /// now-retired "report_deploy"/"patch"/"report"/"app_management") never fails
    /// deserialization and never actuates.
    /// </summary>
    [JsonPropertyName("tier")]
    public string Tier { get; init; } = "assurance";

    /// <summary>
    /// PAT-605 / PAT-551: Application Control policy — approved-admins enforcement.
    /// null / absent = safe defaults apply (enforcement disabled).
    /// The agent MUST NOT enforce unless this block is present with enabled=true and
    /// a non-empty approved_admins list (lockout protection).
    /// </summary>
    [JsonPropertyName("app_control")]
    public AppControlPolicy AppControl { get; init; } = AppControlPolicy.Defaults;

    /// <summary>
    /// PAT-1108/PAT-1110. Tenant-wide agent-decommission directive — the ONLY
    /// irreversible directive in the contract. Deliberately NULL by default (no
    /// object initializer), NOT <c>DecommissionPolicy.Defaults</c>: a config whose
    /// signed payload omits "decommission" entirely must be distinguishable from one
    /// that explicitly sets mode="none", because
    /// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/> treats the two as
    /// different fault/no-fault outcomes even though neither ever removes the agent.
    /// See <see cref="DecommissionPolicy"/> for why this never throws on a malformed
    /// wire value.
    /// </summary>
    [JsonPropertyName("decommission")]
    public DecommissionPolicy? Decommission { get; init; }

    /// <summary>
    /// Safe defaults used before any config has been fetched/verified, or when
    /// the cache is empty. Most conservative tier ("assurance") so the agent
    /// never actuates until the platform explicitly grants the "managed" tier.
    /// </summary>
    public static AgentConfig Defaults { get; } = new();

    private static readonly JsonSerializerOptions DeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Deserialize an AgentConfig from verified JSON bytes.</summary>
    public static AgentConfig? Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        // Inspect the raw, already-authenticated JSON before any typed field can
        // throw. A newer signed revocation must not leave an older in-memory
        // execution grant live merely because an unrelated optional field (for
        // example proxy.port) has a type this client does not understand.
        PropertyNameInspection names = InspectPropertyNames(utf8Json);
        try
        {
            return Canonicalize(
                JsonSerializer.Deserialize<AgentConfig>(utf8Json, DeserializeOptions),
                names);
        }
        catch (JsonException)
        {
            // AgentConfigFetcher verifies signature, tenant binding and version
            // ordering before calling this method. Preserve only the identity of
            // that trusted policy and resolve every authority-bearing value to its
            // deny default; no malformed typed field can retain a prior grant.
            return new AgentConfig
            {
                ConfigVersion = names.ConfigVersion ?? 0,
                TenantId = names.TenantId ?? "",
            };
        }
    }

    /// <summary>Deserialize an AgentConfig from a verified JSON string.</summary>
    public static AgentConfig? Deserialize(string json) =>
        Deserialize(System.Text.Encoding.UTF8.GetBytes(json));

    /// <summary>
    /// PAT-1418. AgentConfig.Tier is the other of the two places a tier string enters
    /// the Windows process (the first is Posture.Tier — see PostureModels.cs, same
    /// rationale). PatchedWorker reads _config.Current.Tier directly into ordinal
    /// comparisons (ActuatingTierAllows / DestructiveActuatingTierAllows: both
    /// <c>tier == "managed"</c> since PAT-1599 collapsed the vocabulary — Worker.cs),
    /// so a non-canonical-case value here is exactly the divergence PAT-1418 closes:
    /// canonicalize once, at the point the signed config is deserialized, so every
    /// downstream comparison can stay ordinal instead of each one needing its own
    /// case-insensitive guard.
    ///
    /// Narrow on purpose: only folds case and surrounding whitespace. A null Tier
    /// stays null and a missing Tier keeps the "assurance" default unchanged — this
    /// must never invent a value, and it must never throw on an unrecognised tier
    /// string. Tier stays a plain string (not an enum) precisely so a server-side
    /// vocabulary addition can never fail deserialization of the whole signed config;
    /// this canonicalization step preserves that — it only folds case, never rejects.
    /// </summary>
    private static AgentConfig? Canonicalize(AgentConfig? config, PropertyNameInspection names) =>
        config is null ? null : config with
        {
            Tier = NormalizeTierCase(config.Tier),
            // System.Text.Json otherwise uses the last duplicate property. For an
            // authority field that would turn a signed but ambiguous payload into a
            // privilege grant, so any duplicate at any object depth resolves every
            // privilege-bearing field to its deny value. It intentionally remains
            // case-insensitive for all existing properties, but these two new
            // privilege-bearing wire names must themselves be exact lowercase:
            // otherwise a signed payload with only a case variant would bind here.
            AppControlAuthority = names.HasDuplicatePropertyNames ||
                                  names.HasNonCanonicalAppControlAuthorityName
                ? AppControlAuthority.Report
                : config.AppControlAuthority,
            LegacyAppExecutionEnabled = !names.HasDuplicatePropertyNames &&
                                        !names.HasNonCanonicalLegacyAppExecutionEnabledName &&
                config.LegacyAppExecutionEnabled,
            UpdateAuthorityShapeInvalid = names.HasDuplicatePropertyNames ||
                                          names.HasNonCanonicalUpdateAuthorityName,
        };

    private static string NormalizeTierCase(string tier) =>
        tier is null ? tier : tier.Trim().ToLowerInvariant();

    private static PropertyNameInspection InspectPropertyNames(ReadOnlySpan<byte> utf8Json)
    {
        var objects = new Stack<HashSet<string>>();
        bool hasDuplicatePropertyNames = false;
        bool hasNonCanonicalAppControlAuthorityName = false;
        bool hasNonCanonicalLegacyAppExecutionEnabledName = false;
        bool hasNonCanonicalUpdateAuthorityName = false;
        int? configVersion = null;
        string? tenantId = null;
        string? pendingTopLevelProperty = null;
        var reader = new Utf8JsonReader(utf8Json);
        while (reader.Read())
        {
            if (pendingTopLevelProperty is not null)
            {
                if (pendingTopLevelProperty == "config_version" &&
                    reader.TokenType == JsonTokenType.Number &&
                    reader.TryGetInt32(out int rawConfigVersion))
                {
                    configVersion = rawConfigVersion;
                }
                else if (pendingTopLevelProperty == "tenant_id" &&
                         reader.TokenType == JsonTokenType.String)
                {
                    tenantId = reader.GetString();
                }
                pendingTopLevelProperty = null;
            }

            if (reader.TokenType == JsonTokenType.StartObject)
            {
                objects.Push(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            }
            else if (reader.TokenType == JsonTokenType.EndObject)
            {
                objects.Pop();
            }
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string propertyName = reader.GetString()!;
                if (!objects.Peek().Add(propertyName))
                    hasDuplicatePropertyNames = true;

                // AgentConfig's authority fields are top-level contract members.
                // Do not impose a casing change on unrelated nested legacy config.
                if (reader.CurrentDepth == 1)
                {
                    pendingTopLevelProperty = propertyName;
                    if (string.Equals(propertyName, "app_control_authority", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(propertyName, "app_control_authority", StringComparison.Ordinal))
                    {
                        hasNonCanonicalAppControlAuthorityName = true;
                    }
                    else if (string.Equals(propertyName, "legacy_app_execution_enabled", StringComparison.OrdinalIgnoreCase) &&
                             !string.Equals(propertyName, "legacy_app_execution_enabled", StringComparison.Ordinal))
                    {
                        hasNonCanonicalLegacyAppExecutionEnabledName = true;
                    }
                    else if (UpdateAuthorityPropertyNames.Contains(propertyName, StringComparer.OrdinalIgnoreCase) &&
                             !UpdateAuthorityPropertyNames.Contains(propertyName, StringComparer.Ordinal))
                    {
                        hasNonCanonicalUpdateAuthorityName = true;
                    }
                }
            }
        }

        return new(
            hasDuplicatePropertyNames,
            hasNonCanonicalAppControlAuthorityName,
            hasNonCanonicalLegacyAppExecutionEnabledName,
            hasNonCanonicalUpdateAuthorityName,
            configVersion,
            tenantId);
    }

    private static readonly string[] UpdateAuthorityPropertyNames =
    [
        "tenant_id",
        "config_version",
        "update_channel",
        "device_channel_overrides",
        "device_id",
        "update_channel_source",
        "pinned_version",
    ];

    private static PropertyNameInspection InspectPropertyNames(string json) =>
        InspectPropertyNames(System.Text.Encoding.UTF8.GetBytes(json));

    private readonly record struct PropertyNameInspection(
        bool HasDuplicatePropertyNames,
        bool HasNonCanonicalAppControlAuthorityName,
        bool HasNonCanonicalLegacyAppExecutionEnabledName,
        bool HasNonCanonicalUpdateAuthorityName,
        int? ConfigVersion,
        string? TenantId);

    /// <summary>
    /// Tolerant reader for a fail-closed permission bit. A malformed optional field
    /// must not reject an otherwise valid signed config and leave an earlier true
    /// value in force; only the exact JSON token <c>true</c> enables this bit.
    /// </summary>
    private sealed class ExactTrueBooleanConverter : JsonConverter<bool>
    {
        public override bool HandleNull => true;

        public override bool Read(ref Utf8JsonReader reader, Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType is JsonTokenType.StartArray or JsonTokenType.StartObject)
                reader.Skip();

            return reader.TokenType == JsonTokenType.True;
        }

        public override void Write(Utf8JsonWriter writer, bool value,
            JsonSerializerOptions options) => writer.WriteBooleanValue(value);
    }

    private sealed class AppControlAuthorityConverter : JsonConverter<AppControlAuthority>
    {
        public override bool HandleNull => true;

        public override AppControlAuthority Read(ref Utf8JsonReader reader,
            Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                return reader.GetString() switch
                {
                    "block" => AppControlAuthority.Block,
                    "enforce" => AppControlAuthority.Enforce,
                    "report" => AppControlAuthority.Report,
                    _ => AppControlAuthority.Report,
                };
            }

            if (reader.TokenType is JsonTokenType.StartArray or JsonTokenType.StartObject)
                reader.Skip();

            return AppControlAuthority.Report;
        }

        public override void Write(Utf8JsonWriter writer, AppControlAuthority value,
            JsonSerializerOptions options) => writer.WriteStringValue(value.ToString().ToLowerInvariant());
    }
}
