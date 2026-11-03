using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Posture;

/// <summary>
/// Platform-neutral model for GET /v1/posture — the device posture the Windows
/// desktop surfaces (tray agent + Self Service) render from. The contract is
/// vendored at contracts/posture.schema.json (server-owned, patched.im). This is
/// the Windows half of the U0 shared read-client; the macOS half is
/// menubar/PatchedUpdater/Posture.swift and must stay content-equivalent.
///
/// The tray/Self Service apps NEVER fetch this — they hold no credentials. The
/// Service (LocalSystem) fetches /v1/posture via <c>PostureFetcher</c> and writes
/// a world-readable posture.json cache; <c>PostureReader</c> reads that cache
/// (last-known-good). See PostureFetcher.cs / PostureReader.cs.
///
/// Open-vocabulary fields (tier, policy, severity, status, …) are modelled as
/// strings rather than enums so a server-side vocabulary addition can never make
/// the whole document fail to deserialize — the reader stays crash-safe and falls
/// back to last-known-good only on genuinely malformed JSON. Gating semantics live
/// in <see cref="PostureGating"/>, the single seam shared by every surface.
/// </summary>
public sealed record Posture
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("generated_at")]
    public DateTimeOffset GeneratedAt { get; init; }

    [JsonPropertyName("device")]
    public PostureDevice Device { get; init; } = new();

    /// <summary>"assurance" | "managed" (PAT-1599 collapsed the former "report" | "report_deploy" | "patch" | "managed" vocabulary to this pair — "assurance observes, managed acts", one bit, not a ladder). Drives honest gating via <see cref="PostureGating"/>. An unrecognised or now-retired value never throws and never actuates.</summary>
    [JsonPropertyName("tier")]
    public string Tier { get; init; } = "assurance";

    [JsonPropertyName("app_count")]
    public int AppCount { get; init; }

    [JsonPropertyName("compliance")]
    public Compliance Compliance { get; init; } = new();

    [JsonPropertyName("evidence")]
    public Evidence Evidence { get; init; } = new();

    /// <summary>Optional — absent on older server builds; guard on null.</summary>
    [JsonPropertyName("findings")]
    public IReadOnlyList<Finding>? Findings { get; init; }

    [JsonPropertyName("updates")]
    public IReadOnlyList<AppUpdate>? Updates { get; init; }

    [JsonPropertyName("app_policy")]
    public AppPolicy? AppPolicy { get; init; }

    /// <summary>Patch &amp; Deploy enabled for this device. Convenience over <see cref="PostureGating"/>.</summary>
    [JsonIgnore]
    public bool CanPatchDeploy => PostureGating.GrantsPatchDeploy(Tier);

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Deserialize a Posture from cache bytes. Returns null on malformed JSON.</summary>
    public static Posture? Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        try { return Canonicalize(JsonSerializer.Deserialize<Posture>(utf8Json, ReadOptions)); }
        catch (JsonException) { return null; }
    }

    public static Posture? Deserialize(string json)
    {
        try { return Canonicalize(JsonSerializer.Deserialize<Posture>(json, ReadOptions)); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// PAT-1418. Posture.Tier is one of the two places a tier string enters the
    /// Windows process (the other is AgentConfig.Tier — see AgentConfig.cs); the UI
    /// gating seam (<see cref="PostureGating"/>) reads case-insensitively, but the
    /// daemon's own gates (PatchedWorker.ActuatingTierAllows /
    /// DestructiveActuatingTierAllows in Worker.cs) compare ordinal, since C# pattern
    /// matching and == on string constants are both ordinal. A server that ever emits
    /// "MANAGED" instead of "managed" would previously make the UI offer Install / Get
    /// / Uninstall while the daemon refused to actuate the resulting trigger — a dead
    /// button, which is exactly what PostureGating's doc comment above says the UI must
    /// never show. Rather than adding OrdinalIgnoreCase to the daemon predicates (which
    /// only patches this one gap and leaves the next comparison free to drift), this
    /// canonicalizes the tier string once, here, at the boundary where it enters the
    /// process — mirroring macOS's Tier(rawString:) (menubar/PatchedUpdater/Posture.swift),
    /// which lowercases once at its own boundary so both platforms read the same
    /// normalised case.
    ///
    /// Deliberately narrow: only folds case and surrounding whitespace. A null Tier
    /// (an explicit "tier": null in the payload) stays null, and a missing Tier keeps
    /// the "assurance" default — this must never turn a null/missing value into a
    /// different one, and it must never throw on an unrecognised tier string, per the
    /// open-vocabulary contract on <see cref="Tier"/> above.
    /// </summary>
    private static Posture? Canonicalize(Posture? posture) =>
        posture is null ? null : posture with { Tier = NormalizeTierCase(posture.Tier) };

    private static string NormalizeTierCase(string tier) =>
        tier is null ? tier : tier.Trim().ToLowerInvariant();
}

public sealed record PostureDevice
{
    [JsonPropertyName("id")]            public string Id { get; init; } = "";
    [JsonPropertyName("serial")]        public string? Serial { get; init; }
    [JsonPropertyName("hw_uuid")]       public string? HwUuid { get; init; }
    [JsonPropertyName("hostname")]      public string? Hostname { get; init; }
    [JsonPropertyName("computer_name")] public string? ComputerName { get; init; }
    [JsonPropertyName("hw_model")]      public string? HwModel { get; init; }
    [JsonPropertyName("arch")]          public string? Arch { get; init; }
    [JsonPropertyName("os")]            public string Os { get; init; } = "";
    [JsonPropertyName("os_version")]    public string? OsVersion { get; init; }
    [JsonPropertyName("os_build")]      public string? OsBuild { get; init; }
    [JsonPropertyName("agent_version")] public string? AgentVersion { get; init; }
    [JsonPropertyName("first_seen")]    public DateTimeOffset? FirstSeen { get; init; }
    [JsonPropertyName("last_seen")]     public DateTimeOffset? LastSeen { get; init; }
}

public sealed record Compliance
{
    [JsonPropertyName("platform")]   public string Platform { get; init; } = "";
    [JsonPropertyName("benchmarks")] public IReadOnlyList<Benchmark> Benchmarks { get; init; } = [];

    /// <summary>The benchmark the headline surfaces summarise (first declared).</summary>
    [JsonIgnore]
    public Benchmark? Primary => Benchmarks.Count > 0 ? Benchmarks[0] : null;
}

public sealed record Benchmark
{
    [JsonPropertyName("benchmark")]         public string Name { get; init; } = "";
    [JsonPropertyName("benchmark_version")] public string Version { get; init; } = "";
    [JsonPropertyName("implemented")]       public int Implemented { get; init; }
    [JsonPropertyName("benchmark_total")]   public int BenchmarkTotal { get; init; }
    [JsonPropertyName("passed")]            public int Passed { get; init; }
    [JsonPropertyName("failed")]            public int Failed { get; init; }
    [JsonPropertyName("not_applicable")]    public int NotApplicable { get; init; }
    [JsonPropertyName("errors")]            public int Errors { get; init; }
    [JsonPropertyName("compliance_pct")]    public double CompliancePct { get; init; }
    [JsonPropertyName("sections")]          public IReadOnlyList<Section> Sections { get; init; } = [];

    /// <summary>"87 of 134" — coverage, never a hardcoded total (see U1/U3 rule).</summary>
    [JsonIgnore]
    public string CoverageText => $"{Implemented} of {BenchmarkTotal}";
}

public sealed record Section
{
    [JsonPropertyName("section")]  public string Number { get; init; } = "";
    [JsonPropertyName("passed")]   public int Passed { get; init; }
    [JsonPropertyName("total")]    public int Total { get; init; }
    [JsonPropertyName("controls")] public IReadOnlyList<Control> Controls { get; init; } = [];
}

public sealed record Control
{
    [JsonPropertyName("rule_key")]       public string RuleKey { get; init; } = "";
    [JsonPropertyName("title")]          public string Title { get; init; } = "";
    /// <summary>"low" | "medium" | "high" | "critical" (open vocab — string for crash-safety).</summary>
    [JsonPropertyName("severity")]       public string Severity { get; init; } = "";
    /// <summary>"pass" | "fail" | "not_applicable" | "error".</summary>
    [JsonPropertyName("status")]         public string Status { get; init; } = "";
    [JsonPropertyName("observed_value")] public string? ObservedValue { get; init; }
    [JsonPropertyName("evaluated_at")]   public DateTimeOffset EvaluatedAt { get; init; }
}

public sealed record Evidence
{
    [JsonPropertyName("coverage_window_days")]      public int CoverageWindowDays { get; init; }
    [JsonPropertyName("scans_logged")]              public int ScansLogged { get; init; }
    [JsonPropertyName("last_signed_report_digest")] public string? LastSignedReportDigest { get; init; }
    [JsonPropertyName("recent_scan_times")]         public IReadOnlyList<DateTimeOffset> RecentScanTimes { get; init; } = [];

    [JsonIgnore]
    public DateTimeOffset? LastScan => RecentScanTimes.Count > 0 ? RecentScanTimes[0] : null;
}

public sealed record Finding
{
    [JsonPropertyName("cve_id")]           public string CveId { get; init; } = "";
    [JsonPropertyName("description")]      public string Description { get; init; } = "";
    [JsonPropertyName("cvss_v3_score")]    public double? CvssV3Score { get; init; }
    [JsonPropertyName("severity")]         public string Severity { get; init; } = "";
    [JsonPropertyName("published_at")]     public DateTimeOffset? PublishedAt { get; init; }
    [JsonPropertyName("app_name")]         public string AppName { get; init; } = "";
    [JsonPropertyName("app_version")]      public string AppVersion { get; init; } = "";
    /// <summary>"version_confirmed" | "version_unverified".</summary>
    [JsonPropertyName("match_confidence")] public string MatchConfidence { get; init; } = "";
    [JsonPropertyName("last_seen_at")]     public DateTimeOffset LastSeenAt { get; init; }
}

public sealed record AppUpdate
{
    [JsonPropertyName("app_name")]        public string AppName { get; init; } = "";
    [JsonPropertyName("identifier")]      public string Identifier { get; init; } = "";
    [JsonPropertyName("current_version")] public string CurrentVersion { get; init; } = "";
    [JsonPropertyName("target_version")]  public string TargetVersion { get; init; } = "";
    /// <summary>"catalog" | "manual".</summary>
    [JsonPropertyName("source")]          public string Source { get; init; } = "";
    [JsonPropertyName("linked_cve_ids")]  public IReadOnlyList<string> LinkedCveIds { get; init; } = [];
}

public sealed record AppPolicy
{
    [JsonPropertyName("apps")]  public IReadOnlyList<AppPolicyEntry> Apps { get; init; } = [];
    [JsonPropertyName("drift")] public IReadOnlyList<DriftEntry> Drift { get; init; } = [];
}

public sealed record AppPolicyEntry
{
    [JsonPropertyName("app_name")]   public string AppName { get; init; } = "";
    [JsonPropertyName("identifier")] public string Identifier { get; init; } = "";
    /// <summary>"mandatory" | "approved" | "unapproved" | "unmanaged".</summary>
    [JsonPropertyName("policy")]     public string Policy { get; init; } = "";
    [JsonPropertyName("user_removable")]   public bool UserRemovable { get; init; }
    /// <summary>"report_deploy" | "report" | "patch" | "app_management" | "managed" | "assurance" ("report_deploy"/"patch" canonical; "report"/"app_management" accepted legacy aliases; "assurance" is a PAT-1505 phase-1 additional accepted value, not yet emitted by the platform).</summary>
    [JsonPropertyName("enforcement_tier")] public string EnforcementTier { get; init; } = "";

    /// <summary>"Required by your IT" badge — no Uninstall affordance.</summary>
    [JsonIgnore]
    public bool IsRequired => string.Equals(Policy, "mandatory", StringComparison.OrdinalIgnoreCase);
}

public sealed record DriftEntry
{
    /// <summary>"mandatory_missing" | "unapproved_present".</summary>
    [JsonPropertyName("drift_type")]       public string DriftType { get; init; } = "";
    [JsonPropertyName("app_name")]         public string AppName { get; init; } = "";
    [JsonPropertyName("identifier")]       public string Identifier { get; init; } = "";
    [JsonPropertyName("policy")]           public string Policy { get; init; } = "";
    /// <summary>"report_deploy" | "report" | "patch" | "app_management" | "managed" | "assurance" ("report_deploy"/"patch" canonical; "report"/"app_management" accepted legacy aliases; "assurance" is a PAT-1505 phase-1 additional accepted value, not yet emitted by the platform).</summary>
    [JsonPropertyName("enforcement_tier")] public string EnforcementTier { get; init; } = "";
}

/// <summary>
/// The single seam for honest tier gating — content-equivalent to the Swift
/// Posture.Tier helpers (menubar/PatchedUpdater/Posture.swift). Every Windows
/// surface asks this rather than hardcoding a tier string.
///
/// The agent has NO installer: Patch &amp; Deploy and Uninstall are gated
/// affordances that hand off to Self Service / upgrade, never inline acts.
///
/// PAT-1599 collapsed the tier vocabulary from three values (report_deploy /
/// patch / managed) to two (assurance / managed) — "assurance observes, managed
/// acts", one bit, not a ladder. Only "managed" is now an actuating tier; this
/// matches the daemon's real gate (PatchedWorker.ActuatingTierAllows /
/// DestructiveActuatingTierAllows, both <c>tier == "managed"</c> — Worker.cs),
/// which PAT-1418 (see <see cref="Posture.Canonicalize"/> above) deliberately
/// keeps agreeing with this seam so neither surface can offer an action the
/// other then refuses (a dead button). "assurance" (or anything unrecognised,
/// including the now-retired "report", "report_deploy", "patch" and
/// "app_management") presents these actions but gated.
/// </summary>
public static class PostureGating
{
    /// <summary>
    /// The actuating-tier predicate shared by both device-level gates below, so
    /// they cannot drift apart. Case-insensitive; fails closed on anything else.
    /// Only "managed" grants — there is no more "patch" rung between "assurance"
    /// and "managed" (PAT-1599).
    /// </summary>
    private static bool ActuatingTierGrants(string tier) =>
        string.Equals(tier, "managed", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Patch &amp; Deploy (Install / Get / one-click deploy) is enabled.
    ///
    /// Kept as a name distinct from <see cref="GrantsAppManagement"/>, even though
    /// both now delegate to the same <see cref="ActuatingTierGrants"/> check under
    /// the 2-value scheme, for the same reason Worker.cs keeps ActuatingTierAllows
    /// and DestructiveActuatingTierAllows separate: each name documents which UI
    /// affordance a call site is gating (Patch &amp; Deploy vs. Uninstall), which
    /// stays useful for readers and future audits even where the checks coincide
    /// today.
    /// </summary>
    public static bool GrantsPatchDeploy(string tier) => ActuatingTierGrants(tier);

    /// <summary>App-management (user Uninstall) is enabled at the device level.</summary>
    public static bool GrantsAppManagement(string tier) => ActuatingTierGrants(tier);

    /// <summary>
    /// The app's policy permits enforcement at app-management tier or above. Accepts both the
    /// canonical enforcement_tier vocabulary ("patch", "managed") and the legacy vocabulary
    /// ("app_management", "managed") that today's deployed agents still emit/consume — see PAT-1121.
    /// </summary>
    public static bool EnforcementActuates(string enforcementTier) =>
        string.Equals(enforcementTier, "patch", StringComparison.OrdinalIgnoreCase)
        || string.Equals(enforcementTier, "app_management", StringComparison.OrdinalIgnoreCase)
        || string.Equals(enforcementTier, "managed", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the user may be offered an Uninstall for this app. Three gates,
    /// all required: device tier grants app management, the app allows enforcement
    /// at app-management tier or above, and the app is user_removable (false for
    /// mandatory apps). When false, the UI shows the honest gated/"Required" state
    /// — never a dead/fake button.
    /// </summary>
    public static bool CanUninstall(string tier, AppPolicyEntry app) =>
        GrantsAppManagement(tier)
        && app.UserRemovable
        && EnforcementActuates(app.EnforcementTier);
}
