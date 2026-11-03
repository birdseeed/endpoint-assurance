using System.Text.Json.Serialization;

namespace Patched.Shared.Removal;

/// <summary>
/// Windows app uninstall-execution contracts (PAT-379), the parity mirror of the
/// macOS PAT-376 engine (endpoint/patched-uninstall.sh + uninstall-status.schema.json).
///
/// The platform-neutral pieces — the outcome / verify-result vocabulary and the
/// uninstall-status.json shape — are shared verbatim with macOS so the dashboard
/// renders removals from both OSes identically. Only the <see cref="RemovalMethod"/>
/// values are OS-specific (registry/winget/msi vs pkg/app-bundle).
/// </summary>

/// <summary>One queued removal from GET /v1/allowlist/pending-removals (PAT-376 #83).</summary>
public sealed record PendingRemoval
{
    [JsonPropertyName("entry_id")]
    public long EntryId { get; init; }

    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("publisher")]
    public string? Publisher { get; init; }

    /// <summary>"windows" | "macos" | "any".</summary>
    [JsonPropertyName("platform")]
    public string Platform { get; init; } = "any";

    [JsonPropertyName("match_mode")]
    public string MatchMode { get; init; } = "exact_name";

    [JsonPropertyName("queued_at")]
    public DateTimeOffset QueuedAt { get; init; }
}

/// <summary>Envelope returned by GET /v1/allowlist/pending-removals.</summary>
public sealed record PendingRemovalsResponse
{
    [JsonPropertyName("tenant_id")]
    public string TenantId { get; init; } = "";

    [JsonPropertyName("window_hours")]
    public int WindowHours { get; init; } = 24;

    [JsonPropertyName("items")]
    public IReadOnlyList<PendingRemoval> Items { get; init; } = [];
}

/// <summary>
/// Terminal outcome of one removal — neutral vocabulary, identical to the macOS
/// engine's enum. Serialized snake_case via ContractJsonOptions.
/// </summary>
public enum RemovalOutcome
{
    Removed,                  // gone + verified
    RemovedResidual,          // program entry gone but install files/registry remnants remain
    AlreadyRemoved,           // not present at run time (idempotent)
    ManualRemovalRequired,    // no method resolved
    DeferredAppRunning,       // app was running and did not close; retry next cycle
    FailedTransient,          // still present; classified transient — retry next cycle
    FailedHard,               // still present; OS/Store/MDM-protected — surface as a finding
    AuthorityRefused,         // signed execution authority absent, stale, or revoked — terminal
    SkippedBaselineProtected, // safety guard blocked a Windows/Microsoft baseline app
    SkippedUserPolicy,        // user_removable=false in posture — policy refused removal
    Unknown,
}

/// <summary>Result of post-execution re-inspection (never the process exit code).</summary>
public enum VerifyResult
{
    Gone,
    Residual,
    StillPresent,
    NotChecked,
}

/// <summary>Resolved removal method. OS-native first, then catalogue fallback.</summary>
public enum RemovalMethod
{
    RegistryQuietUninstall,   // QuietUninstallString (vendor-provided silent)
    RegistryUninstall,        // UninstallString (generic)
    Winget,                   // winget uninstall --id
    Msi,                      // msiexec /x {ProductCode} /qn /norestart
    Catalogue,                // catalogue/allowlist recipe override
    None,                     // no attempt made
    Unresolvable,             // no method could be resolved
}

/// <summary>One row in uninstall-status.json removals[] (mirrors the macOS schema).</summary>
public sealed record RemovalResult
{
    [JsonPropertyName("entry_id")]
    public long EntryId { get; init; }

    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("outcome")]
    public RemovalOutcome Outcome { get; init; }

    [JsonPropertyName("verify_result")]
    public VerifyResult? VerifyResult { get; init; }

    [JsonPropertyName("method")]
    public RemovalMethod Method { get; init; }

    [JsonPropertyName("recorded_at")]
    public DateTimeOffset RecordedAt { get; init; }
}

public sealed record UninstallRunInfo
{
    [JsonPropertyName("started_at")]
    public DateTimeOffset StartedAt { get; init; }

    [JsonPropertyName("finished_at")]
    public DateTimeOffset FinishedAt { get; init; }
}

/// <summary>
/// %ProgramData%\Patched\uninstall-status.json — mirrors the macOS
/// uninstall-status.schema.json (schema_version 1) exactly.
/// </summary>
public sealed record UninstallStatus
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("generated_at")]
    public DateTimeOffset GeneratedAt { get; init; }

    [JsonPropertyName("last_run")]
    public UninstallRunInfo? LastRun { get; init; }

    [JsonPropertyName("removals")]
    public IReadOnlyList<RemovalResult> Removals { get; init; } = [];
}

// ---------------------------------------------------------------------------
// Provenance — record_type "app_uninstall", posted to /v1/provenance per attempt.
// Field-for-field identical to the macOS engine's emit_uninstall_provenance, so the
// dashboard ingests Mac and Windows removal provenance through one code path.
// ---------------------------------------------------------------------------

public sealed record UninstallProvenance
{
    [JsonPropertyName("record_type")]
    public string RecordType { get; init; } = "app_uninstall";

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("tenant_id")]
    public string TenantId { get; init; } = "";

    [JsonPropertyName("device")]
    public UninstallProvenanceDevice Device { get; init; } = new();

    [JsonPropertyName("app")]
    public UninstallProvenanceApp App { get; init; } = new();

    [JsonPropertyName("uninstall")]
    public UninstallProvenanceMethod Uninstall { get; init; } = new();

    [JsonPropertyName("outcome")]
    public RemovalOutcome Outcome { get; init; }

    [JsonPropertyName("verify_result")]
    public VerifyResult? VerifyResult { get; init; }

    /// <summary>"transient" | "hard" | null — drives retry vs surface-as-finding.</summary>
    [JsonPropertyName("failure_class")]
    public string? FailureClass { get; init; }

    [JsonPropertyName("recorded_at")]
    public DateTimeOffset RecordedAt { get; init; }
}

public sealed record UninstallProvenanceDevice
{
    [JsonPropertyName("hw_uuid")]
    public string? HwUuid { get; init; }

    [JsonPropertyName("computer_name")]
    public string? ComputerName { get; init; }
}

public sealed record UninstallProvenanceApp
{
    [JsonPropertyName("entry_id")]
    public long EntryId { get; init; }

    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("publisher")]
    public string? Publisher { get; init; }

    [JsonPropertyName("platform")]
    public string Platform { get; init; } = "windows";

    [JsonPropertyName("match_mode")]
    public string MatchMode { get; init; } = "exact_name";
}

public sealed record UninstallProvenanceMethod
{
    [JsonPropertyName("method")]
    public RemovalMethod Method { get; init; }

    [JsonPropertyName("method_detail")]
    public string? MethodDetail { get; init; }

    [JsonPropertyName("queued_at")]
    public DateTimeOffset QueuedAt { get; init; }

    [JsonPropertyName("window_hours")]
    public int WindowHours { get; init; } = 24;
}
