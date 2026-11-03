using System.Text.Json.Serialization;

namespace Patched.Shared.Installation;

/// <summary>
/// Windows catalogue-install contracts (PAT-661), the install-side twin of the
/// removal contracts in Patched.Shared.Removal (PAT-379).
///
/// Mirrors the macOS patched-install.sh shape so the dashboard ingests install
/// events from both OSes through one code path.
/// </summary>

/// <summary>One queued install from GET /v1/allowlist/pending-installs (PAT-659).</summary>
public sealed record PendingInstall
{
    [JsonPropertyName("package_id")]
    public string PackageId { get; init; } = "";

    /// <summary>"winget" | "mas" | "vendor".</summary>
    [JsonPropertyName("package_source")]
    public string PackageSource { get; init; } = "";

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = "";
}

/// <summary>Envelope returned by GET /v1/allowlist/pending-installs.</summary>
public sealed record PendingInstallsResponse
{
    [JsonPropertyName("installs")]
    public IReadOnlyList<PendingInstall> Installs { get; init; } = [];
}

/// <summary>
/// Terminal outcome of one catalogue install — neutral vocabulary mirroring
/// the macOS engine's outcome values so the dashboard renders installs from
/// both OSes identically.
/// </summary>
public enum InstallOutcome
{
    /// <summary>Install succeeded and app is now present.</summary>
    Success,
    /// <summary>App was already installed; no action taken (idempotent).</summary>
    AlreadyInstalled,
    /// <summary>Install attempted but failed (see ErrorMessage).</summary>
    Failed,
    /// <summary>Signed endpoint execution authority refused the operation.</summary>
    AuthorityRefused,
}

public enum InstallFailureKind
{
    InstallFailed,
    VerificationBlocked,
    ExecutionAuthorityRefused,
}

/// <summary>One row in install-status.json installs[] (mirrors uninstall-status shape).</summary>
public sealed record InstallResult
{
    [JsonPropertyName("package_id")]
    public string PackageId { get; init; } = "";

    [JsonPropertyName("package_source")]
    public string PackageSource { get; init; } = "";

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = "";

    [JsonPropertyName("outcome")]
    public InstallOutcome Outcome { get; init; }

    [JsonPropertyName("error_message")]
    public string? ErrorMessage { get; init; }

    [JsonPropertyName("failure_kind")]
    public InstallFailureKind? FailureKind { get; init; }

    [JsonPropertyName("recorded_at")]
    public DateTimeOffset RecordedAt { get; init; }
}

/// <summary>
/// Structured event payload posted to POST /v1/agent-logs (PAT-651) after each
/// install attempt. Shape is identical to the macOS patched-install.sh
/// report_install_event() JSON so the server parses it platform-neutrally.
/// </summary>
public sealed record CatalogueInstallEvent
{
    [JsonPropertyName("event")]
    public string Event { get; init; } = "catalogue_install";

    [JsonPropertyName("package_id")]
    public string PackageId { get; init; } = "";

    [JsonPropertyName("package_source")]
    public string PackageSource { get; init; } = "";

    /// <summary>"success" | "already_installed" | "failed"</summary>
    [JsonPropertyName("outcome")]
    public string Outcome { get; init; } = "";

    /// <summary>Only present on "failed" outcome.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }
}

public sealed record InstallRunInfo
{
    [JsonPropertyName("started_at")]
    public DateTimeOffset StartedAt { get; init; }

    [JsonPropertyName("finished_at")]
    public DateTimeOffset FinishedAt { get; init; }
}

/// <summary>
/// %ProgramData%\Patched\install-status.json — mirrors the macOS
/// install-status.json shape produced by patched-install.sh.
/// </summary>
public sealed record InstallStatus
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("generated_at")]
    public DateTimeOffset GeneratedAt { get; init; }

    [JsonPropertyName("last_run")]
    public InstallRunInfo? LastRun { get; init; }

    [JsonPropertyName("installs")]
    public IReadOnlyList<InstallResult> Installs { get; init; } = [];
}
