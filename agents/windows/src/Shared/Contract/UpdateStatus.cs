using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// Contract between the privileged Windows Service (writer) and the tray app (reader).
/// Written atomically to %ProgramData%\Patched\update-status.json, world-readable.
/// Mirrors contracts/update-status.schema.json (schema_version = 1) exactly.
/// Windows fills verified_signer with the Authenticode publisher, not an Apple Team ID.
///
/// Serialization: use ContractJsonOptions.Default — it applies SnakeCaseLower to all
/// enums, which maps e.g. OverallState.UpdatesAvailable → "updates_available".
/// </summary>
public sealed record UpdateStatus
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("generated_at")]
    public DateTimeOffset GeneratedAt { get; init; }

    [JsonPropertyName("device")]
    public DeviceInfo? Device { get; init; }

    [JsonPropertyName("last_run")]
    public LastRunInfo? LastRun { get; init; }

    [JsonPropertyName("next_scheduled_run")]
    public DateTimeOffset? NextScheduledRun { get; init; }

    [JsonPropertyName("overall_state")]
    public OverallState OverallState { get; init; }

    [JsonPropertyName("counts")]
    public Counts? Counts { get; init; }

    [JsonPropertyName("apps")]
    public IReadOnlyList<AppEntry> Apps { get; init; } = [];

    [JsonPropertyName("os_update")]
    public OsUpdateInfo? OsUpdate { get; init; }

    /// <summary>PAT-300. Configuration/CIS advisory findings. Null until the service has run with compliance detection enabled.</summary>
    [JsonPropertyName("compliance_findings")]
    public IReadOnlyList<ComplianceFinding>? ComplianceFindings { get; init; }
}

public sealed record DeviceInfo
{
    [JsonPropertyName("hw_uuid")]
    public string? HwUuid { get; init; }

    [JsonPropertyName("computer_name")]
    public string? ComputerName { get; init; }
}

public sealed record LastRunInfo
{
    [JsonPropertyName("started_at")]
    public DateTimeOffset? StartedAt { get; init; }

    [JsonPropertyName("finished_at")]
    public DateTimeOffset? FinishedAt { get; init; }

    [JsonPropertyName("trigger")]
    public string? Trigger { get; init; }

    /// <summary>
    /// Windows: winget version tag used for this run (mirrors installomator_tag).
    /// E.g. "winget-1.9.25180".
    /// </summary>
    [JsonPropertyName("installomator_tag")]
    public string? InstallomatorTag { get; init; }
}

public sealed record Counts
{
    [JsonPropertyName("total")]
    public int Total { get; init; }

    [JsonPropertyName("up_to_date")]
    public int UpToDate { get; init; }

    [JsonPropertyName("updates_available")]
    public int UpdatesAvailable { get; init; }

    [JsonPropertyName("errors")]
    public int Errors { get; init; }
}

public sealed record AppEntry
{
    [JsonPropertyName("label")]
    public required string Label { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("installed_version")]
    public string? InstalledVersion { get; init; }

    [JsonPropertyName("available_version")]
    public string? AvailableVersion { get; init; }

    [JsonPropertyName("state")]
    public AppState State { get; init; }

    [JsonPropertyName("last_action")]
    public string? LastAction { get; init; }

    [JsonPropertyName("last_action_at")]
    public DateTimeOffset? LastActionAt { get; init; }

    /// <summary>
    /// Authenticode publisher confirmed at last successful verification.
    /// null when verification was not performed or failed.
    /// </summary>
    [JsonPropertyName("verified_signer")]
    public string? VerifiedSigner { get; init; }

    [JsonPropertyName("failure_reason")]
    public FailureReason? FailureReason { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }

    // ---------------------------------------------------------------------
    // PAT-381: per-app update-policy carriers. These travel with the entry so
    // ProvenancePoster can record the policy decision, but they are NOT part of
    // the update-status.json tray contract (schema_version 1, additionalProperties
    // false) — exactly as the macOS PAT-365 script records the policy only in
    // provenance, never in the tray status. [JsonIgnore] keeps them off the wire.
    // ---------------------------------------------------------------------

    /// <summary>Winget package id (the Windows neutral identifier; macOS uses bundle id).</summary>
    [JsonIgnore]
    public string? WingetId { get; init; }

    /// <summary>"override" | "fleet_default" when the app-update policy was evaluated; else null.</summary>
    [JsonIgnore]
    public string? PolicySource { get; init; }

    /// <summary>True when an install was suppressed because policy disabled this app.</summary>
    [JsonIgnore]
    public bool PolicyDisabled { get; init; }

    /// <summary>
    /// PAT-506: true when an install was suppressed because the version has not yet
    /// been approved for this device's deployment ring.
    /// </summary>
    [JsonIgnore]
    public bool RingGated { get; init; }
}

// -------------------------------------------------------------------------
// Enums — serialized as snake_case strings via ContractJsonOptions.Default.
// PascalCase member names map directly: UpdatesAvailable → "updates_available".
// -------------------------------------------------------------------------

public enum OverallState
{
    UpToDate,
    UpdatesAvailable,
    Updating,
    Error,
    Unknown,
}

public enum AppState
{
    UpToDate,
    UpdateAvailable,
    Updating,
    Installed,
    VerificationFailed,
    Error,
    NotInstalled,
    Unknown,
}

public enum FailureReason
{
    MissingExpectedSigner,
    SignatureUntrusted,
    SignerMismatch,
    // PAT-508: a blocked version is reported as VerificationFailed state with this reason
    // (the shared representation the macOS daemon uses), not a distinct state.
    BlockedVersion,   // version is in blocked_versions in agent-config
    // PAT-1238: macOS refuses an active blocked_versions policy if its paired
    // catalogue version cannot be evaluated safely before installation.
    BlockedVersionResolutionFailed,
    Sha256Mismatch,   // legacy wire value: a pinned SHA-256 did not match the downloaded artifact
}

// PAT-273: OS update awareness (Windows fills from WUA, same shape as macOS).
public sealed record OsUpdateInfo
{
    [JsonPropertyName("installed_os")]
    public required string InstalledOs { get; init; }

    [JsonPropertyName("latest_os")]
    public string? LatestOs { get; init; }

    /// <summary>
    /// PAT-2123: null when neither policy nor WUA gives a target build (e.g. a
    /// pending update with no version string attached, common for cumulative
    /// updates). Never falls back to installed_os -- that read as "update
    /// required to the version you already have." Omitted on the wire when
    /// null (ContractJsonOptions/InventoryPoster both ignore-on-null).
    /// </summary>
    [JsonPropertyName("target_os")]
    public string? TargetOs { get; init; }

    [JsonPropertyName("state")]
    public OsUpdateState State { get; init; }

    [JsonPropertyName("severity")]
    public OsUpdateSeverity Severity { get; init; }

    [JsonPropertyName("security_relevant")]
    public bool SecurityRelevant { get; init; }

    [JsonPropertyName("actively_exploited")]
    public bool ActivelyExploited { get; init; }

    [JsonPropertyName("deadline")]
    public DateTimeOffset? Deadline { get; init; }

    [JsonPropertyName("deferrals_remaining")]
    public int DeferralsRemaining { get; init; }

    [JsonPropertyName("release_age_days")]
    public int? ReleaseAgeDays { get; init; }

    [JsonPropertyName("checked_at")]
    public DateTimeOffset CheckedAt { get; init; }
}

public enum OsUpdateState
{
    UpToDate,
    UpdateRecommended,
    UpdateRequired,
    DeadlinePassed,
    UnsupportedHardware,
    Unknown,
}

public enum OsUpdateSeverity
{
    None,
    Low,
    Medium,
    High,
    Critical,
}

// PAT-300/481: compliance findings (configuration/CIS advisory findings).
public sealed record ComplianceFinding
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("severity")]
    public ComplianceSeverity Severity { get; init; }

    /// <summary>PAT-481. Per-volume detail for removable_storage_unencrypted. Null for other finding ids.</summary>
    [JsonPropertyName("volumes")]
    public IReadOnlyList<ComplianceFindingVolume>? Volumes { get; init; }
}

/// <summary>PAT-481. One plaintext removable volume observed at collect time.</summary>
public sealed record ComplianceFindingVolume
{
    [JsonPropertyName("mount_point")]
    public required string MountPoint { get; init; }

    [JsonPropertyName("filesystem")]
    public required string Filesystem { get; init; }

    [JsonPropertyName("encryption_state")]
    public required string EncryptionState { get; init; }

    [JsonPropertyName("provenance_source")]
    public required string ProvenanceSource { get; init; }
}

/// <summary>Serialized as snake_case via ContractJsonOptions.Default: Critical → "critical".</summary>
public enum ComplianceSeverity { Low, Medium, High, Critical }
