namespace Patched.Shared.Metering;

/// <summary>
/// Windows software-metering contracts (PAT-380), the parity mirror of the macOS
/// PAT-356 Spotlight collector. Usage is written to the SAME neutral columns
/// (device_apps.last_used_at / launch_count) and a device-level metering_status, so
/// the PAT-366 aggregates endpoint and PAT-362 screen light up for Windows with no
/// upstream change. See docs/windows-metering-adr.md for the source rationale.
/// </summary>

/// <summary>
/// Device-level source provenance. Neither an ok source nor no_record proves non-use.
/// </summary>
public static class MeteringStatus
{
    /// <summary>At least one usable record, with no failed or explicitly disabled loaded hive.</summary>
    public const string Ok = "ok";

    /// <summary>No user hive was loaded (service ran with no interactive profile); nulls are unknown.</summary>
    public const string NoUserSession = "no_user_session";

    /// <summary>No usable records, a disabled loaded hive or an incomplete read; no absence claims.</summary>
    public const string Unavailable = "userassist_unavailable";
}

/// <summary>One decoded UserAssist execution record (path + run count + last run).</summary>
public sealed record UserAssistUsage
{
    public required string Path { get; init; }
    public int RunCount { get; init; }
    public DateTimeOffset? LastUsed { get; init; }
    /// <summary>Ephemeral hive ordinal for alias deduplication, never sent on the wire.</summary>
    public int UserHive { get; init; }
}

/// <summary>An installed program the matcher correlates UserAssist paths against.</summary>
public sealed record MeteredApp
{
    /// <summary>device_apps identifier (the registry Uninstall key name).</summary>
    public required string Identifier { get; init; }
    public string? InstallLocation { get; init; }
    /// <summary>Main executable path from DisplayIcon, when present.</summary>
    public string? ExePath { get; init; }
    /// <summary>Only the reviewed Office App Paths bindings; never shortcut targets.</summary>
    public IReadOnlyList<string> OfficeExePaths { get; init; } = [];
}

/// <summary>Aggregated usage for one app: lifetime launch count + most-recent run.</summary>
public readonly record struct AppUsage(DateTimeOffset? LastUsed, int? LaunchCount,
    string UsageEvidence = MeteringEvidence.Recorded);

public static class MeteringEvidence
{
    public const string Recorded = "recorded";
    public const string NoRecord = "no_record";
    public const string Unmapped = "unmapped";
    public const string Unavailable = "unavailable";
}
