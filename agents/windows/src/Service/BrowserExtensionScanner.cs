using System.Runtime.Versioning;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// PAT-827: Windows browser-extension inventory — Chrome, Edge, and Firefox,
/// per user and per browser profile. Parity with the macOS collector
/// (macos/lib/browser_extensions.sh, PAT-125): same field set, same
/// device_browser_extensions target (migration 0018), same "never throw"
/// contract — every collection path is wrapped so a single failure never aborts
/// the wider inventory run.
///
/// Unlike <see cref="BackupCollector"/>'s loaded-SID-only scope, this walks every
/// profile registered in HKLM ProfileList, not just currently loaded sessions:
/// extension state lives entirely on disk (manifest.json / extensions.json, no
/// registry hive required to read it), so a logged-off user's extensions are
/// just as inventoriable as a logged-in one's. Restricting to loaded sessions
/// would silently under-report the estate — the macOS collector has the same
/// "walk every /Users/* directory regardless of session state" behaviour.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class BrowserExtensionScanner
{
    /// <summary>
    /// Bounds payload size: mirrors browser_extensions.sh's device-wide MAX_EXTENSIONS. PAT-2065:
    /// shared fairly, each profile may use (rows left) / (profiles left), so one profile with a
    /// pathological number of extensions cannot crowd out the profiles after it.
    /// </summary>
    internal const int MaxExtensions = 1000;

    /// <summary>
    /// PAT-2052: the agent_health (kind, subject) this collector reports a degraded collection
    /// under. browser_extensions[] itself has no partial state on the wire, so a profile the
    /// scan refused or could only partly read would otherwise look exactly like one with no
    /// extensions; this entry is how the server learns the list is incomplete.
    /// </summary>
    internal const string HealthKind = "collection_partial";
    internal const string HealthSubject = "browser_extensions";

    private readonly ILogger<BrowserExtensionScanner> _log;
    private readonly AgentHealthStore _agentHealth;

    public BrowserExtensionScanner(ILogger<BrowserExtensionScanner> log, AgentHealthStore agentHealth)
    {
        _log = log;
        _agentHealth = agentHealth;
    }

    /// <summary>
    /// Every registered profile. PAT-2065: read through <see cref="WindowsUserProfiles.Snapshot"/>,
    /// not Enumerate, because an unreadable ProfileList must be a failed block, never an empty
    /// roster that reads as "no browser anywhere". A registered profile whose directory is gone
    /// is scanned as absent (not_present) and sends no rows, exactly as before.
    /// </summary>
    public BrowserExtensionCollection Collect() =>
        Collect(() => WindowsUserProfiles.Snapshot(_log) is { } snapshot
            ? (snapshot.Profiles.Select(p => new BrowserExtensionProfileRef(p.ProfilePath, p.UserAccount, p.Sid)).ToList(),
               snapshot.Unreadable)
            : null);

    /// <summary>Tests: profiles as (path, account), none unreadable, no SID.</summary>
    internal BrowserExtensionCollection Collect(Func<IEnumerable<(string ProfilePath, string UserAccount)>> profiles) =>
        Collect(() => (profiles().Select(p => new BrowserExtensionProfileRef(p.ProfilePath, p.UserAccount, null)).ToList(), 0));

    /// <summary>
    /// The collection over <paramref name="profiles"/>: the profiles and how many registry entries
    /// could not be read, or null when the profile list itself could not be read. Never throws:
    /// a failure anywhere outside one profile's scan sends no rows and a failed block.
    /// </summary>
    internal BrowserExtensionCollection Collect(
        Func<(IReadOnlyList<BrowserExtensionProfileRef> Profiles, int Unreadable)?> profiles)
    {
        BrowserExtensionCollection result;
        List<string> partial;
        try
        {
            if (profiles() is not { } snapshot)
            {
                _log.LogWarning("BrowserExtensionScanner: the profile list could not be read, emitting [] with status failed");
                RecordHealth("collection_failed");
                return new BrowserExtensionCollection([], BrowserExtensionStatusLogic.Failed());
            }
            (result, partial) = CollectInner(snapshot.Profiles, snapshot.Unreadable);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "BrowserExtensionScanner: collection failed, emitting [] with status failed");
            RecordHealth("collection_failed");
            return new BrowserExtensionCollection([], BrowserExtensionStatusLogic.Failed());
        }

        if (partial.Count > 0)
        {
            // PAT-2052 review: Warning, not Debug. A machine that moved a browser's data
            // behind a junction now reports none of that profile's extensions; that must be
            // visible, not silent.
            _log.LogWarning(
                "BrowserExtensionScanner: {Count} profile(s) only partly readable, their extensions are incomplete: {Paths}",
                partial.Count, string.Join(", ", partial));
            RecordHealth($"profiles_partly_unreadable:{partial.Count}");
        }
        else
        {
            RecordHealth(null);
        }
        return result;
    }

    private void RecordHealth(string? reason)
    {
        try
        {
            if (reason is null) _agentHealth.RecordSuccess(HealthKind, HealthSubject);
            else _agentHealth.RecordFailure(HealthKind, HealthSubject, reason);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "BrowserExtensionScanner: could not record collection health");
        }
    }

    private (BrowserExtensionCollection Result, List<string> Partial) CollectInner(
        IReadOnlyList<BrowserExtensionProfileRef> profiles, int unreadable)
    {
        var results = new List<InventoryBrowserExtension>();
        var partial = new List<string>();
        var users = new List<BrowserExtensionUserScan>();
        var capped = false;
        var remaining = MaxExtensions;

        for (var i = 0; i < profiles.Count; i++)
        {
            var (profilePath, userAccount, sid) = profiles[i];
            // Fair share: what is left, split over this profile and those after it. The cap is
            // a work bound, not just a post-hoc truncation: the scan stops at the first row past
            // the share and never parses further manifests.
            var share = remaining / (profiles.Count - i);
            try
            {
                var scan = BrowserExtensionScanLogic.Scan(profilePath, userAccount, share);
                results.AddRange(scan.Extensions);
                remaining -= scan.Extensions.Count;
                capped |= scan.Capped;
                if (scan.Partial) partial.Add(profilePath);
                users.Add(new BrowserExtensionUserScan(userAccount, sid, scan.Browsers, scan.UserFailed));
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "BrowserExtensionScanner: scan failed for profile {Path}", profilePath);
                partial.Add(profilePath);
                users.Add(new BrowserExtensionUserScan(userAccount, sid,
                    BrowserExtensionBrowserStatuses.All(BrowserExtensionCollectionStatus.Failed), UserFailed: true));
            }
        }

        var status = BrowserExtensionStatusLogic.Build(users, capped, unreadable);
        _log.LogDebug(
            "BrowserExtensionScanner: collected {Count} extension(s) across {ProfileCount} profile(s), status {Status}, cap reached {Capped}",
            results.Count, profiles.Count, status.CollectionStatus, capped);

        return (new BrowserExtensionCollection(results, status), partial);
    }
}

/// <summary>PAT-2065: one registered profile to scan: its root, the account its rows carry, and its SID.</summary>
internal readonly record struct BrowserExtensionProfileRef(string ProfilePath, string UserAccount, string? Sid);

/// <summary>PAT-2065: the browser_extensions rows and the browser_extensions_status block that describes them.</summary>
internal sealed record BrowserExtensionCollection(
    IReadOnlyList<InventoryBrowserExtension> Extensions, InventoryBrowserExtensionsStatus Status);
