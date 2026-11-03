using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// A trigger file dropped by the tray app into %ProgramData%\Patched\triggers\
/// and consumed by the service. The directory is ACL-hardened so authenticated
/// users can only create their own files (PAT-307).
/// </summary>
public sealed record TriggerRequest
{
    /// <summary>
    /// App labels to update, or ["*"] for all pending.
    /// Present on deploy triggers; absent on os_defer triggers.
    /// </summary>
    [JsonPropertyName("labels")]
    public IReadOnlyList<string>? Labels { get; init; }

    /// <summary>
    /// "os_defer" | "scan" | "uninstall" | "removal_defer" for typed markers;
    /// absent for normal deploy triggers. (desktop chain U5: scan + uninstall
    /// are user-initiated. removal_defer added PAT-1623 — see IsRemovalDeferRequest.)
    /// </summary>
    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("requested_by")]
    public string? RequestedBy { get; init; }

    [JsonPropertyName("requested_at")]
    public DateTimeOffset? RequestedAt { get; init; }

    /// <summary>
    /// Only present on os_defer and removal_defer triggers.
    /// </summary>
    [JsonPropertyName("deferred_at")]
    public DateTimeOffset? DeferredAt { get; init; }

    /// <summary>
    /// Only present on removal_defer triggers: the allowlist entry_id of the
    /// app being deferred (matches RemovalResult.EntryId / RemovalOutcome).
    /// </summary>
    [JsonPropertyName("entry_id")]
    public long? EntryId { get; init; }

    /// <summary>
    /// Only present on removal_defer triggers: the app name, for audit
    /// readability alongside entry_id.
    /// </summary>
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    /// <summary>"deploy-window" | "menubar" | "manual" | "tray"</summary>
    [JsonPropertyName("source")]
    public string? Source { get; init; }

    public bool IsOsDefer => string.Equals(Type, "os_defer", StringComparison.Ordinal);

    /// <summary>Local, user-initiated scan (collect + posture refresh; no install).</summary>
    public bool IsScanRequest => string.Equals(Type, "scan", StringComparison.Ordinal);

    /// <summary>User-initiated uninstall of the app identifier(s) in Labels.</summary>
    public bool IsUninstallRequest =>
        string.Equals(Type, "uninstall", StringComparison.Ordinal) && Labels is { Count: > 0 };

    /// <summary>
    /// PAT-1623: the removal notify/defer surface's own deferral marker,
    /// mirroring os_defer's shape but per-app (EntryId) rather than global —
    /// the two deferral budgets (OS-update deferrals_remaining vs. removal's
    /// own audit tally) must never be counted against each other, which is
    /// why this is a distinct type rather than a reused "os_defer" with an
    /// added entry_id. PAT-1620 narrowed accepted trigger types to
    /// scan/uninstall/os_defer; this is the minimal, documented extension —
    /// same directory, same file shape, same narrow validation below, no new
    /// privileged channel.
    /// </summary>
    public bool IsRemovalDeferRequest =>
        string.Equals(Type, "removal_defer", StringComparison.Ordinal) && EntryId is not null;

    /// <summary>A deploy trigger is an untyped trigger carrying labels.</summary>
    public bool IsDeployRequest => Type is null && Labels is { Count: > 0 };
}

public static class TriggerRequestValidator
{
    public const int MaxFileSizeBytes = 4 * 1024;   // 4 KB hard cap
    private const int MaxLabelCount    = 50;
    private const int MaxLabelLength   = 128;
    private const int MaxStringLength  = 256;

    public static bool TryValidate(string json, long fileSizeBytes, out TriggerRequest? request, out string? error)
    {
        request = null;
        error   = null;

        if (fileSizeBytes > MaxFileSizeBytes)
        {
            error = $"Trigger file exceeds {MaxFileSizeBytes} byte limit ({fileSizeBytes} bytes)";
            return false;
        }

        TriggerRequest? parsed;
        try
        {
            parsed = System.Text.Json.JsonSerializer.Deserialize<TriggerRequest>(
                json,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = false });
        }
        catch (Exception ex)
        {
            error = $"Malformed JSON: {ex.Message}";
            return false;
        }

        if (parsed is null)
        {
            error = "Empty trigger payload";
            return false;
        }

        // Checked ahead of the general type-vocabulary check below so a
        // removal_defer trigger missing entry_id gets this specific message
        // rather than the generic "must be one of" one.
        if (string.Equals(parsed.Type, "removal_defer", StringComparison.Ordinal) && parsed.EntryId is null)
        {
            error = "removal_defer trigger requires entry_id";
            return false;
        }

        if (!parsed.IsDeployRequest && !parsed.IsOsDefer && !parsed.IsScanRequest
            && !parsed.IsUninstallRequest && !parsed.IsRemovalDeferRequest)
        {
            error = "Trigger must be a deploy (labels[]), type=os_defer, type=scan, "
                  + "type=uninstall (labels[]), or type=removal_defer (entry_id)";
            return false;
        }

        // Deploy + uninstall both carry labels[] (app labels / identifiers) — validate them.
        if (parsed.IsDeployRequest || parsed.IsUninstallRequest)
        {
            if (parsed.Labels!.Count > MaxLabelCount)
            {
                error = $"labels[] exceeds {MaxLabelCount} entries";
                return false;
            }
            foreach (var label in parsed.Labels!)
            {
                if (label.Length > MaxLabelLength || label.Contains('/') || label.Contains('\\') || label.Contains('\0'))
                {
                    error = $"Label '{label}' is invalid";
                    return false;
                }
            }
        }

        if (parsed.RequestedBy is { Length: > MaxStringLength })
        {
            error = "requested_by field too long";
            return false;
        }

        if (parsed.Source is { Length: > MaxStringLength })
        {
            error = "source field too long";
            return false;
        }

        if (parsed.Name is { Length: > MaxStringLength })
        {
            error = "name field too long";
            return false;
        }

        request = parsed;
        return true;
    }
}
