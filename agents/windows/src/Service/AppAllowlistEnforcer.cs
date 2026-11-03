using System.Runtime.Versioning;
using Patched.Shared.Config;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// PAT-552: Application Control — app-allowlist enforcement (Windows, alert-only v1).
///
/// On each run cycle (when app_control.enabled = true and app_allowlist is non-empty):
///   1. Reads the app_allowlist from the signed agent-config (list of strings;
///      compared case-insensitively against DisplayName and Publisher from
///      HKLM Uninstall registry keys).
///   2. Scans currently-installed applications via <see cref="InstalledAppScanner"/>.
///   3. Reports any installed application whose DisplayName and Publisher both
///      fail to match an allowlist entry as an <c>app_block_skipped</c> audit event.
///
/// V1 is alert-only: the agent never blocks or uninstalls. The caller ships the
/// returned events to /v1/inventory/enforcement-audit so the dashboard can surface
/// violations. Blocking is a later escalation (PAT-551 scope).
///
/// Matching rules (at least one must pass for the app to be considered allowed):
///   - The allowlist entry matches the app's DisplayName (case-insensitive, contains).
///   - The allowlist entry matches the app's Publisher (case-insensitive, contains).
///
/// This deliberately uses a "contains" match rather than exact equality so that
/// entries like "Google Chrome" match "Google LLC" (publisher) or partial names.
/// Exact-match requirements can be added in a later iteration.
///
/// Fail-safe: never throws into the run cycle.
/// </summary>
[SupportedOSPlatform("windows")]
internal class AppAllowlistEnforcer
{
    private readonly ILogger<AppAllowlistEnforcer> _log;
    private readonly InstalledAppScanner           _scanner;

    public AppAllowlistEnforcer(
        ILogger<AppAllowlistEnforcer> log,
        InstalledAppScanner           scanner)
    {
        _log     = log;
        _scanner = scanner;
    }

    /// <summary>
    /// Runs the app-allowlist check pass.  Never throws.
    /// </summary>
    /// <param name="policy">The AppControlPolicy from the current signed agent-config.</param>
    /// <returns>
    /// <c>app_block_skipped</c> events for every installed app not matched by the allowlist.
    /// Empty list if AC is disabled, the allowlist is empty, or no violations are found.
    /// </returns>
    public IReadOnlyList<EnforcementAuditEvent> Enforce(AppControlPolicy policy)
    {
        var auditEvents = new List<EnforcementAuditEvent>();

        // 1. Feature gate.
        if (!policy.Enabled)
        {
            _log.LogDebug("AppAllowlistEnforcer: app_control.enabled=false — skipping");
            return auditEvents;
        }

        // 2. If allowlist is empty, there's no policy to enforce.
        if (policy.AppAllowlist.Count == 0)
        {
            _log.LogDebug("AppAllowlistEnforcer: app_allowlist is empty — skipping (no policy configured)");
            return auditEvents;
        }

        bool dryRun = string.Equals(
            Environment.GetEnvironmentVariable("PATCHED_DRY_RUN"), "1",
            StringComparison.Ordinal);

        // 3. Scan installed applications.
        IReadOnlyList<InventoryApp> installedApps;
        try
        {
            installedApps = GetInstalledApps();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "AppAllowlistEnforcer: failed to scan installed apps — skipping enforcement");
            return auditEvents;
        }

        _log.LogDebug("AppAllowlistEnforcer: {AppCount} installed apps, {AllowlistCount} allowlist entries",
            installedApps.Count, policy.AppAllowlist.Count);

        // Build allowlist as a list of lowercase patterns for contains-matching.
        var allowlistLower = policy.AppAllowlist
            .Select(e => e.Trim().ToLowerInvariant())
            .Where(e => e.Length > 0)
            .ToList();

        var occurredAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        int violationCount = 0;

        // 4. Compare each installed app against the allowlist.
        foreach (var app in installedApps)
        {
            if (IsAllowed(app, allowlistLower))
                continue;

            violationCount++;
            var subject = app.Name;

            if (dryRun)
            {
                _log.LogInformation(
                    "AppAllowlistEnforcer [DRY RUN]: unlisted app '{Name}' (publisher: '{Publisher}')",
                    app.Name, app.Publisher ?? "(none)");
            }
            else
            {
                _log.LogWarning(
                    "AppAllowlistEnforcer: unlisted app '{Name}' (publisher: '{Publisher}') — " +
                    "reporting as app_block_skipped (alert-only v1)",
                    app.Name, app.Publisher ?? "(none)");
            }

            auditEvents.Add(new EnforcementAuditEvent
            {
                EventType  = EnforcementAuditEventTypes.AppBlockSkipped,
                Subject    = subject,
                Details    = new Dictionary<string, object?>
                {
                    ["app_name"]  = app.Name,
                    ["publisher"] = app.Publisher,
                    ["version"]   = app.Version,
                    ["reason"]    = "alert_only_v1",
                    ["dry_run"]   = dryRun,
                },
                OccurredAt = occurredAt,
            });
        }

        _log.LogInformation("AppAllowlistEnforcer: {ViolationCount} unlisted app(s) found", violationCount);
        return auditEvents;
    }

    // -------------------------------------------------------------------------
    // Overridable helpers (internal for unit testing)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns the installed-app list.  Virtual so tests can override without P/Invoke.
    /// </summary>
    internal virtual IReadOnlyList<InventoryApp> GetInstalledApps() => _scanner.Scan();

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns true if any allowlist entry is a case-insensitive substring of
    /// the app's DisplayName or Publisher.
    /// </summary>
    private static bool IsAllowed(InventoryApp app, IReadOnlyList<string> allowlistLower)
    {
        var nameLower      = app.Name.ToLowerInvariant();
        var publisherLower = app.Publisher?.ToLowerInvariant() ?? "";

        foreach (var entry in allowlistLower)
        {
            if (nameLower.Contains(entry, StringComparison.OrdinalIgnoreCase))
                return true;
            if (publisherLower.Length > 0 &&
                publisherLower.Contains(entry, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
