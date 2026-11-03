using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Config;
using Patched.Shared.Contract;

namespace Patched.Shared.BrowserExtensions;

/// <summary>
/// PAT-828: platform-neutral decision logic for browser-extension managed-policy
/// blocklist enforcement. Lives in Shared (no Windows TFM) so its tests run on
/// macOS/Linux CI, mirroring the BrowserExtensionScanLogic / BackupStatusLogic
/// split. The Windows-only <c>BrowserExtensionBlocklistEnforcer</c> (Service)
/// supplies the loaded sidecar state, applies each returned change to the
/// registry, then persists the returned next-state.
///
/// Mechanism parity with the macOS enforcer (macos/lib/browser_extension_control.sh):
/// Chrome/Edge get an ExtensionInstallBlocklist policy, Firefox gets
/// ExtensionSettings installation_mode=blocked. A sidecar records exactly which
/// ids we manage per browser so reconciliation removes only our own entries,
/// never a third party's (GPO/admin) policy.
/// </summary>
internal static class ExtensionBlocklistLogic
{
    /// <summary>Supported browsers → (HKLM-relative registry path, mechanism tag).</summary>
    private static readonly IReadOnlyDictionary<string, (string RegistryKey, string Mechanism)> Targets =
        new Dictionary<string, (string, string)>(StringComparer.Ordinal)
        {
            ["chrome"]  = (@"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist",  "chromium_registry_blocklist"),
            ["edge"]    = (@"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist", "chromium_registry_blocklist"),
            ["firefox"] = (@"SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings",        "firefox_registry_extensionsettings"),
        };

    public static bool IsSupportedBrowser(string browser) => Targets.ContainsKey(browser);

    public static (string RegistryKey, string Mechanism) TargetFor(string browser) => Targets[browser];

    /// <summary>Full HKLM path for the audit event.</summary>
    public static string AuditPath(string browser) => @"HKLM\" + Targets[browser].RegistryKey;

    /// <summary>
    /// Group the config's extension_blocklist by browser into sorted, de-duplicated
    /// id lists. Empty when app_control is disabled or the list is absent/empty —
    /// the fail-safe: enforce nothing the config didn't explicitly list.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> NormalizeDesired(AppControlPolicy policy)
    {
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        if (policy is null || !policy.Enabled || policy.ExtensionBlocklist.Count == 0)
            return result;

        var grouped = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var entry in policy.ExtensionBlocklist)
        {
            if (entry is null) continue;
            var browser = (entry.Browser ?? "").Trim().ToLowerInvariant();
            var id = (entry.ExtensionId ?? "").Trim();
            if (browser.Length == 0 || id.Length == 0) continue;
            if (!grouped.TryGetValue(browser, out var set))
            {
                set = new SortedSet<string>(StringComparer.Ordinal);
                grouped[browser] = set;
            }
            set.Add(id);
        }

        foreach (var (browser, ids) in grouped)
            result[browser] = ids.ToList();
        return result;
    }

    /// <summary>
    /// Diff the desired blocklist against the previously-managed sidecar state.
    /// Returns one <see cref="BrowserBlocklistChange"/> per browser whose managed
    /// set changed (including a shrink to empty = "cleared"), the optimistic
    /// next-state assuming every change applies, and any unsupported browser names
    /// present in the config (no registry mechanism — logged, never enforced).
    /// </summary>
    public static ReconcileResult Reconcile(
        IReadOnlyDictionary<string, IReadOnlyList<string>> desired,
        ExtensionBlocklistState previous)
    {
        var changes = new List<BrowserBlocklistChange>();
        var next = new ExtensionBlocklistState();
        var unsupported = new List<string>();

        var allBrowsers = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var b in desired.Keys) allBrowsers.Add(b);
        foreach (var b in previous.Browsers.Keys) allBrowsers.Add(b);

        foreach (var browser in allBrowsers)
        {
            var desiredIds = desired.TryGetValue(browser, out var d) ? d : (IReadOnlyList<string>)[];
            var prevIds = previous.Browsers.TryGetValue(browser, out var p) ? p : new List<string>();

            if (!IsSupportedBrowser(browser))
            {
                // No registry mechanism for this browser name; never enforce or
                // persist it (so we don't falsely claim it's managed).
                if (desiredIds.Count > 0) unsupported.Add(browser);
                continue;
            }

            var desiredSet = new HashSet<string>(desiredIds, StringComparer.Ordinal);
            var prevSet = new HashSet<string>(prevIds, StringComparer.Ordinal);

            if (desiredSet.SetEquals(prevSet))
            {
                // Already in the intended state — carry it forward unchanged.
                if (desiredIds.Count > 0) next.Browsers[browser] = desiredIds.ToList();
                continue;
            }

            var toAdd = desiredIds.Where(x => !prevSet.Contains(x)).ToList();
            var toRemove = prevIds.Where(x => !desiredSet.Contains(x)).ToList();
            var (registryKey, mechanism) = Targets[browser];

            changes.Add(new BrowserBlocklistChange
            {
                Browser      = browser,
                DesiredIds   = desiredIds.ToList(),
                ToAdd        = toAdd,
                ToRemove     = toRemove,
                RegistryKey  = registryKey,
                AuditPath    = AuditPath(browser),
                Mechanism    = mechanism,
                IsClear      = desiredIds.Count == 0,
            });

            if (desiredIds.Count > 0) next.Browsers[browser] = desiredIds.ToList();
        }

        return new ReconcileResult(changes, next, unsupported);
    }

    /// <summary>Build the enforcement_audit event for one applied (or dry-run) change.</summary>
    public static EnforcementAuditEvent BuildEvent(BrowserBlocklistChange change, string occurredAt, bool dryRun) =>
        new()
        {
            EventType  = EnforcementAuditEventTypes.ExtensionBlocklistPushed,
            Subject    = change.Browser,
            OccurredAt = occurredAt,
            Details = new
            {
                browser       = change.Browser,
                mechanism     = change.Mechanism,
                registry_path = change.AuditPath,
                action        = change.IsClear ? "cleared" : "set",
                blocked_count = change.DesiredIds.Count,
                extension_ids = change.DesiredIds,
                dry_run       = dryRun,
            },
        };
}

/// <summary>Sidecar record of which extension ids the agent manages per browser.</summary>
internal sealed class ExtensionBlocklistState
{
    [JsonPropertyName("browsers")]
    public Dictionary<string, List<string>> Browsers { get; init; } =
        new(StringComparer.Ordinal);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    public static ExtensionBlocklistState Parse(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<ExtensionBlocklistState>(json, JsonOpts)
                   ?? new ExtensionBlocklistState();
        }
        catch
        {
            return new ExtensionBlocklistState();
        }
    }

    public string Serialize() => JsonSerializer.Serialize(this, JsonOpts);
}

/// <summary>One browser whose managed blocklist changed this cycle.</summary>
internal sealed record BrowserBlocklistChange
{
    public required string Browser { get; init; }
    public required IReadOnlyList<string> DesiredIds { get; init; }
    public required IReadOnlyList<string> ToAdd { get; init; }
    public required IReadOnlyList<string> ToRemove { get; init; }
    public required string RegistryKey { get; init; }
    public required string AuditPath { get; init; }
    public required string Mechanism { get; init; }
    public required bool IsClear { get; init; }
}

/// <summary>Result of diffing desired blocklist against previously-managed state.</summary>
internal sealed record ReconcileResult(
    IReadOnlyList<BrowserBlocklistChange> Changes,
    ExtensionBlocklistState NextState,
    IReadOnlyList<string> UnsupportedBrowsers);
