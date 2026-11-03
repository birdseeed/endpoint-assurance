using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// One event in a batch submitted to POST /v1/inventory/enforcement-audit (PAT-603).
/// </summary>
public sealed record EnforcementAuditEvent
{
    [JsonPropertyName("event_type")]
    public required string EventType { get; init; }

    [JsonPropertyName("subject")]
    public required string Subject { get; init; }

    [JsonPropertyName("details")]
    public object? Details { get; init; }

    [JsonPropertyName("occurred_at")]
    public required string OccurredAt { get; init; }
}

/// <summary>Well-known event_type values for the enforcement audit endpoint.</summary>
public static class EnforcementAuditEventTypes
{
    public const string AdminRemoved        = "admin_removed";
    public const string AdminRemovalSkipped = "admin_removal_skipped";
    public const string AppBlocked          = "app_blocked";
    public const string AppBlockSkipped     = "app_block_skipped";

    /// <summary>PAT-828: a browser-extension managed-policy blocklist was pushed or cleared.</summary>
    public const string ExtensionBlocklistPushed = "extension_blocklist_pushed";

    /// <summary>PAT-829: a browser extension was destructively removed from a user profile.</summary>
    public const string ExtensionRemoved = "extension_removed";

    /// <summary>
    /// PAT-1329: a browser-extension removal mutation was refused because its
    /// target failed the belt-and-braces containment or reparse-point check
    /// (<c>ExtensionRemovalLogic.GuardTarget</c>) — see <c>details.reason</c>
    /// ("path_containment" or "reparse_point").
    /// </summary>
    public const string ExtensionRemovalRefused = "extension_removal_refused";
}
