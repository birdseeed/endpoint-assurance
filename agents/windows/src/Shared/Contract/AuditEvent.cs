using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// Security audit event shipped to POST /v1/events (PAT-499).
/// Mirrors the verification/install outcome fields captured in provenance records
/// but targets a write-only SIEM endpoint with append-only storage semantics.
/// </summary>
public sealed record AuditEvent
{
    [JsonPropertyName("event_type")]
    public string EventType { get; init; } = "";

    [JsonPropertyName("tenant_id")]
    public string TenantId { get; init; } = "";

    [JsonPropertyName("device_id")]
    public string DeviceId { get; init; } = "";

    [JsonPropertyName("label")]
    public string? Label { get; init; }

    [JsonPropertyName("version")]
    public string? Version { get; init; }

    [JsonPropertyName("verified_signer")]
    public string? VerifiedSigner { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("expected")]
    public string? Expected { get; init; }

    [JsonPropertyName("actual")]
    public string? Actual { get; init; }

    [JsonPropertyName("platform")]
    public string Platform { get; init; } = "windows";

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; init; } =
        DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

/// <summary>Well-known event_type values for PAT-499 audit events.</summary>
public static class AuditEventTypes
{
    public const string VerificationPassed = "verification_passed";
    public const string VerificationFailed = "verification_failed";
    public const string InstallCompleted   = "install_completed";
    public const string InstallFailed      = "install_failed";
    public const string VersionBlocked     = "version_blocked";
    public const string PostureWarning     = "posture_warning";
    public const string AllowlistTamper    = "allowlist_tamper_detected";

    // Keep update-result mapping platform-neutral and unit-testable. Both
    // agents record a blocked candidate as last_action=version_blocked.
    public static string? ForUpdateLastAction(string? lastAction) => lastAction switch
    {
        "installed"           => InstallCompleted,
        "already_current"     => VerificationPassed,
        "verification_failed" => VerificationFailed,
        "version_blocked"     => VersionBlocked,
        "error"               => InstallFailed,
        _                     => null,
    };

    /// <summary>
    /// Select the version represented by an update audit event. A blocked update
    /// never changes the installed version, so its evidence is the refused candidate.
    /// </summary>
    public static string? VersionForUpdateLastAction(
        string? lastAction, string? installedVersion, string? availableVersion) =>
        lastAction == VersionBlocked
            ? availableVersion ?? installedVersion
            : installedVersion ?? availableVersion;

    /// <summary>Build the exact event queued for one security-relevant update result.</summary>
    public static AuditEvent? ForUpdateEntry(AppEntry entry)
    {
        var eventType = ForUpdateLastAction(entry.LastAction);
        if (eventType is null) return null;

        return new AuditEvent
        {
            EventType      = eventType,
            Label          = entry.Label,
            Version        = VersionForUpdateLastAction(
                entry.LastAction, entry.InstalledVersion, entry.AvailableVersion),
            VerifiedSigner = entry.VerifiedSigner,
            Reason         = entry.FailureReason is { } reason
                ? JsonNamingPolicy.SnakeCaseLower.ConvertName(reason.ToString())
                : null,
            Platform       = "windows",
        };
    }
}
