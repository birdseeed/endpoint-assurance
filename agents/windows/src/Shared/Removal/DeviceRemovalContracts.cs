using System.Text.Json.Serialization;

namespace Patched.Shared.Removal;

/// <summary>
/// Per-device removal-task contracts (PAT-781) — the device-scoped counterpart to
/// the tenant-wide allowlist queue (<see cref="PendingRemoval"/>). An operator
/// queues a removal for one app on one specific device via the dashboard; the
/// agent polls, executes it with the same engine as the allowlist path, and
/// reports the resulting state back. The server task row is the source of truth
/// (no local status file), so there is no uninstall-status.json equivalent here.
/// </summary>

/// <summary>One task from GET /v1/devices/{deviceID}/removal-tasks/pending.</summary>
public sealed record DeviceRemovalTask
{
    [JsonPropertyName("task_id")]
    public string TaskId { get; init; } = "";

    [JsonPropertyName("app_name")]
    public string AppName { get; init; } = "";

    [JsonPropertyName("state")]
    public string State { get; init; } = "";

    [JsonPropertyName("queued_at")]
    public DateTimeOffset QueuedAt { get; init; }

    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>Envelope returned by GET /v1/devices/{deviceID}/removal-tasks/pending.</summary>
public sealed record DeviceRemovalTasksResponse
{
    [JsonPropertyName("device_id")]
    public string DeviceId { get; init; } = "";

    [JsonPropertyName("tasks")]
    public IReadOnlyList<DeviceRemovalTask> Tasks { get; init; } = [];
}

/// <summary>One entry in the POST .../removal-tasks/report body.</summary>
public sealed record DeviceRemovalReport
{
    [JsonPropertyName("task_id")]
    public string TaskId { get; init; } = "";

    [JsonPropertyName("state")]
    public string State { get; init; } = "";

    [JsonPropertyName("detail")]
    public string Detail { get; init; } = "";
}

/// <summary>Body of POST /v1/devices/{deviceID}/removal-tasks/report.</summary>
public sealed record DeviceRemovalReportRequest
{
    [JsonPropertyName("reports")]
    public IReadOnlyList<DeviceRemovalReport> Reports { get; init; } = [];
}

/// <summary>
/// Maps the engine's <see cref="RemovalOutcome"/> to the closed set of states the
/// server accepts from an agent: in-progress | removed | residual | manual | failed.
/// Terminal states (removed/residual/manual/failed) end the task; "in-progress"
/// keeps it live so an interrupted or deferred removal is retried next cycle.
/// </summary>
public static class DeviceRemovalStateMap
{
    public static string ToReportState(RemovalOutcome outcome) => outcome switch
    {
        // Desired end state (app absent) reached — including the idempotent case
        // where it was never installed at run time.
        RemovalOutcome.Removed
            or RemovalOutcome.AlreadyRemoved            => "removed",

        RemovalOutcome.RemovedResidual                  => "residual",

        // No method / a baseline app an operator queued anyway — needs a human.
        RemovalOutcome.ManualRemovalRequired
            or RemovalOutcome.SkippedBaselineProtected
            or RemovalOutcome.SkippedUserPolicy         => "manual",

        // Not done yet, but retryable — keep the task live.
        RemovalOutcome.DeferredAppRunning
            or RemovalOutcome.FailedTransient           => "in-progress",

        // Still present and not retryable (OS/Store/MDM-protected).
        RemovalOutcome.FailedHard
            or RemovalOutcome.AuthorityRefused          => "failed",

        _                                               => "failed",
    };
}
