using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// PAT-828: Browser Extension Control — managed-policy blocklist enforcement
/// (Windows). Consumes app_control.extension_blocklist from the signed
/// agent-config and writes the browser-managed policy that blocks each
/// unapproved extension:
///
///   - Chrome / Edge: ids under HKLM\SOFTWARE\Policies\&lt;vendor&gt;\&lt;browser&gt;\
///     ExtensionInstallBlocklist (read as mandatory managed policy).
///   - Firefox: HKLM\SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings\&lt;id&gt;
///     with Installation_mode=blocked.
///
/// All keys live under HKLM, so a single push covers every user and browser
/// profile on the device (the multi-user/multi-profile acceptance criterion).
///
/// The decision logic (grouping, reconcile diff, audit events) is the
/// platform-neutral <see cref="ExtensionBlocklistLogic"/> in Shared; this class
/// is the thin Windows glue: load the sidecar state, apply each change to the
/// registry, persist the reconciled state, and return one enforcement_audit
/// event per applied change for POST /v1/inventory/enforcement-audit.
///
/// A sidecar state file records exactly which ids we manage, so reconciliation
/// removes only our own entries — never a GPO/admin policy. Fail-safe: never
/// throws into the run cycle.
///
/// Dry-run: $env:PATCHED_DRY_RUN = '1' → compute + emit events but apply no
/// registry writes and persist no state.
/// </summary>
[SupportedOSPlatform("windows")]
internal class BrowserExtensionBlocklistEnforcer
{
    private readonly ILogger<BrowserExtensionBlocklistEnforcer> _log;

    public BrowserExtensionBlocklistEnforcer(ILogger<BrowserExtensionBlocklistEnforcer> log)
    {
        _log = log;
    }

    /// <summary>
    /// Runs the blocklist enforcement pass. Never throws.
    ///
    /// <paramref name="actuationAllowed"/> (PAT-858): the caller's local Tier gate
    /// (defence-in-depth — config enforcement is advisory-only below Tier 3). When
    /// false, desired state is forced to empty regardless of policy content — this
    /// still runs the full reconcile-and-apply below, so any blocklist policy already
    /// pushed while the tenant WAS actuating is torn down, not left in place. A below-
    /// patch client must not continue enforcing merely because it stops adding NEW
    /// entries; leaving stale entries in place is itself still actuating enforcement.
    /// Defaults to true so existing callers/tests are unaffected.
    /// </summary>
    /// <returns>One event per browser whose managed policy was pushed or cleared.</returns>
    public IReadOnlyList<EnforcementAuditEvent> Enforce(AppControlPolicy policy, bool actuationAllowed = true)
    {
        var events = new List<EnforcementAuditEvent>();
        try
        {
            bool dryRun = IsDryRun();

            var desired = actuationAllowed
                ? ExtensionBlocklistLogic.NormalizeDesired(policy)
                : new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
            if (!actuationAllowed)
            {
                _log.LogDebug(
                    "ext_blocklist: Tier gate disallows actuation — reconciling to empty " +
                    "(rolling back any previously-pushed policy, not adding any new entries)");
            }
            var previous = LoadState();
            var result = ExtensionBlocklistLogic.Reconcile(desired, previous);

            foreach (var b in result.UnsupportedBrowsers)
                _log.LogWarning("ext_blocklist: no managed-policy mechanism for browser '{Browser}' — skipping", b);

            if (result.Changes.Count == 0)
            {
                _log.LogDebug("ext_blocklist: no policy change needed");
                return events;
            }

            var occurredAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var nextState = result.NextState;

            foreach (var change in result.Changes)
            {
                if (dryRun)
                {
                    _log.LogInformation(
                        "ext_blocklist [DRY RUN]: would {Action} {Count} id(s) for {Browser} ({Path})",
                        change.IsClear ? "clear" : "set", change.DesiredIds.Count, change.Browser, change.AuditPath);
                    events.Add(ExtensionBlocklistLogic.BuildEvent(change, occurredAt, dryRun: true));
                    continue;
                }

                try
                {
                    Apply(change);
                    _log.LogInformation("ext_blocklist: {Action} {Count} id(s) for {Browser}",
                        change.IsClear ? "cleared" : "set", change.DesiredIds.Count, change.Browser);
                    events.Add(ExtensionBlocklistLogic.BuildEvent(change, occurredAt, dryRun: false));
                }
                catch (Exception ex)
                {
                    _log.LogError(ex,
                        "ext_blocklist: registry apply failed for {Browser} — will retry next cycle", change.Browser);
                    // Revert this browser to its prior managed set so the next cycle
                    // re-attempts, and we don't record an unapplied state as managed.
                    if (previous.Browsers.TryGetValue(change.Browser, out var prev) && prev.Count > 0)
                        nextState.Browsers[change.Browser] = prev;
                    else
                        nextState.Browsers.Remove(change.Browser);
                }
            }

            if (!dryRun)
                SaveState(nextState);

            return events;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ext_blocklist: unexpected error — skipping enforcement");
            return events;
        }
    }

    // -------------------------------------------------------------------------
    // Registry application (Windows-only). Each method touches only the ids in
    // ToAdd / ToRemove, leaving any third-party (GPO/admin) entries intact.
    // -------------------------------------------------------------------------

    private static void Apply(BrowserBlocklistChange change)
    {
        if (string.Equals(change.Mechanism, "firefox_registry_extensionsettings", StringComparison.Ordinal))
            ApplyFirefox(change);
        else
            ApplyChromium(change);
    }

    private static void ApplyChromium(BrowserBlocklistChange change)
    {
        using var key = Registry.LocalMachine.CreateSubKey(change.RegistryKey)
            ?? throw new InvalidOperationException($"could not open {change.AuditPath}");

        // Remove our stale ids: delete the numbered value(s) whose content matches.
        // Content-match (not value-name) so we don't assume a fixed layout. If a GPO
        // also blocked the exact same id, unblocking it here removes that shared value
        // too — acceptable: overlap is unusual and GPO reasserts on its next refresh.
        if (change.ToRemove.Count > 0)
        {
            var removeSet = new HashSet<string>(change.ToRemove, StringComparer.Ordinal);
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string v && removeSet.Contains(v))
                    key.DeleteValue(name, throwOnMissingValue: false);
            }
        }

        // Add new ids at fresh integer indices. Ids already present (possibly set
        // by GPO) are left untouched — never duplicated.
        if (change.ToAdd.Count > 0)
        {
            var present = new HashSet<string>(StringComparer.Ordinal);
            var used = new HashSet<int>();
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string v) present.Add(v);
                if (int.TryParse(name, out var n)) used.Add(n);
            }

            int nextIdx = 1;
            foreach (var id in change.ToAdd)
            {
                if (present.Contains(id)) continue;
                while (used.Contains(nextIdx)) nextIdx++;
                key.SetValue(nextIdx.ToString(), id, RegistryValueKind.String);
                used.Add(nextIdx);
                present.Add(id);
            }
        }
    }

    private static void ApplyFirefox(BrowserBlocklistChange change)
    {
        using var baseKey = Registry.LocalMachine.CreateSubKey(change.RegistryKey)
            ?? throw new InvalidOperationException($"could not open {change.AuditPath}");

        // Remove only entries we own — exactly Installation_mode=blocked with no
        // other values/subkeys — so a richer admin policy for the same id survives.
        foreach (var id in change.ToRemove)
        {
            bool ours;
            var sub = baseKey.OpenSubKey(id, writable: false);
            if (sub is null) continue;
            try
            {
                var mode = sub.GetValue("Installation_mode") as string;
                ours = string.Equals(mode, "blocked", StringComparison.Ordinal)
                       && sub.ValueCount == 1 && sub.SubKeyCount == 0;
            }
            finally
            {
                sub.Dispose();
            }
            if (ours)
                baseKey.DeleteSubKeyTree(id, throwOnMissingSubKey: false);
        }

        foreach (var id in change.ToAdd)
        {
            using var sub = baseKey.CreateSubKey(id);
            sub?.SetValue("Installation_mode", "blocked", RegistryValueKind.String);
        }
    }

    // -------------------------------------------------------------------------
    // Sidecar state IO. Virtual so tests can substitute an in-memory store.
    // -------------------------------------------------------------------------

    /// <summary>
    /// Path to the sidecar state file. Virtual (like <see cref="LoadState"/>/
    /// <see cref="SaveState"/> themselves) so a test subclass can redirect real
    /// file I/O to a scratch path — <see cref="PathConstants.ExtensionBlocklistStateFile"/>
    /// is a fixed <c>static readonly</c> under %ProgramData% with no constructor/env
    /// seam of its own.
    /// </summary>
    internal virtual string StateFilePath => PathConstants.ExtensionBlocklistStateFile;

    /// <summary>
    /// Whether dry-run mode is active ($env:PATCHED_DRY_RUN = '1'). Virtual so tests
    /// can override it per-instance instead of mutating the real process environment
    /// variable — see <see cref="AdminEnforcer.IsDryRun"/> for the PAT-1110
    /// verification finding this mirrors (a cross-test-class race via the same
    /// process-wide variable, exposed by xUnit's default parallel collection
    /// execution, fixed by removing the shared mutable global from tests entirely
    /// rather than fencing access to it).
    /// </summary>
    internal virtual bool IsDryRun() =>
        string.Equals(Environment.GetEnvironmentVariable("PATCHED_DRY_RUN"), "1", StringComparison.Ordinal);

    internal virtual ExtensionBlocklistState LoadState()
    {
        try
        {
            var path = StateFilePath;

            // PAT-1044 non-author-review finding: checking only the leaf file isn't
            // enough — if the CONTAINING directory itself is a pre-planted reparse
            // point, everything underneath (this read included) actually resolves
            // through whatever that directory points to, regardless of what the leaf
            // path looks like. Check the directory first, before touching the leaf at
            // all.
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && IsReparsePoint(dir))
            {
                _log.LogWarning(
                    "ext_blocklist: refusing to read state — containing directory '{Dir}' is " +
                    "a reparse point/junction, not a plain directory (possible symlink attack); " +
                    "starting from empty",
                    dir);
                return new ExtensionBlocklistState();
            }

            if (!File.Exists(path)) return new ExtensionBlocklistState();

            // A LocalSystem-run read through a reparse point planted by a
            // lower-privileged local user at this predictable path could be redirected
            // to read attacker-controlled content back into the service. Lower severity
            // than the write path below (nothing is written through the link), but the
            // same refuse-don't-follow posture applies: don't read through it.
            if (IsReparsePoint(path))
            {
                _log.LogWarning(
                    "ext_blocklist: refusing to read state at '{Path}' — it is a reparse " +
                    "point/junction, not a plain file (possible symlink attack); starting from empty",
                    path);
                return new ExtensionBlocklistState();
            }

            return ExtensionBlocklistState.Parse(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "ext_blocklist: could not read state — starting from empty");
            return new ExtensionBlocklistState();
        }
    }

    /// <summary>
    /// Persists <paramref name="state"/> via a write-to-temp-then-rename. PAT-1044:
    /// this runs as LocalSystem against a predictable path
    /// (<see cref="StateFilePath"/> and its ".tmp" sibling), so a lower-privileged
    /// local user could pre-plant an NTFS reparse point (symlink/junction) at either
    /// path to redirect a SYSTEM-owned write. <see cref="File.WriteAllText(string, string)"/>
    /// and <see cref="File.Move(string, string, bool)"/> both follow reparse points
    /// transparently, so both the intermediate ".tmp" write and the final move are
    /// checked with <see cref="IsReparsePoint"/> (detects the link without following
    /// it) before anything touches that path. <see cref="FileMode.CreateNew"/>
    /// is used for the actual write as defense-in-depth alongside — not instead of —
    /// the explicit check, since CreateNew's own "already exists" failure is evaluated
    /// after the OS follows a reparse point, so it does not by itself guarantee refusal.
    /// Same class of vulnerability as PAT-1043 (macOS root-run write following a
    /// symlink at a user-writable predictable path); Windows has no direct O_NOFOLLOW
    /// equivalent, so the mechanism differs, but a planted reparse point must cause a
    /// hard, logged refusal here too, never a silent redirect.
    ///
    /// Non-author-review finding: the leaf-level checks below aren't sufficient on
    /// their own — if the CONTAINING directory (<see cref="PathConstants.StateDir"/> in
    /// production) is itself a pre-planted reparse point, <see cref="Directory.CreateDirectory"/>
    /// on an already-existing path is a no-op from its perspective, and everything
    /// underneath (the ".tmp" write, the move, a subsequent LoadState) actually
    /// resolves through whatever that directory points to — no leaf-path check catches
    /// a swapped parent. So the directory is checked FIRST, before CreateDirectory ever
    /// runs against it.
    /// </summary>
    internal virtual void SaveState(ExtensionBlocklistState state)
    {
        var path = StateFilePath;
        string? tmp = null;
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && IsReparsePoint(dir))
            {
                _log.LogWarning(
                    "ext_blocklist: refusing to persist state — containing directory '{Dir}' " +
                    "is a reparse point/junction, not a plain directory (possible symlink " +
                    "attack); not creating or writing anything under it",
                    dir);
                return;
            }

            Directory.CreateDirectory(dir!);
            var candidateTmp = path + ".tmp";

            if (IsReparsePoint(candidateTmp))
            {
                _log.LogWarning(
                    "ext_blocklist: refusing to persist state — temp path '{Path}' is already " +
                    "a reparse point/junction, not a plain file (possible symlink attack); " +
                    "leaving it untouched and not writing",
                    candidateTmp);
                return;
            }

            // Only track tmp for cleanup once we've confirmed it's safe to create/delete —
            // a reparse point caught above must never be deleted by the finally block below.
            tmp = candidateTmp;

            // CreateNew: defense-in-depth alongside the explicit check above. Throws if
            // anything (reparse point or ordinary file) already exists at this exact path.
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(fs))
            {
                writer.Write(state.Serialize());
            }

            if (IsReparsePoint(path))
            {
                _log.LogWarning(
                    "ext_blocklist: refusing to persist state — destination '{Path}' is a " +
                    "reparse point/junction, not a plain file (possible symlink attack); not " +
                    "moving the freshly-written state through it",
                    path);
                return; // finally below deletes the freshly-written tmp
            }

            File.Move(tmp, path, overwrite: true);
            tmp = null; // moved successfully; nothing left to clean up
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "ext_blocklist: could not persist state");
        }
        finally
        {
            if (tmp is not null)
            {
                try { File.Delete(tmp); }
                catch { /* best-effort cleanup; a failed save must not throw further */ }
            }
        }
    }

    /// <summary>
    /// True if a filesystem object already exists at <paramref name="path"/> and is a
    /// reparse point (NTFS symlink OR junction) — checked without following it.
    ///
    /// Uses <see cref="File.GetAttributes"/> and tests <see cref="FileAttributes.ReparsePoint"/>,
    /// exactly matching <c>SecureStagingDirectory.IsReparsePoint</c> (the existing, already-
    /// audited precedent in this repo) rather than <see cref="File.ResolveLinkTarget"/>.
    /// FILE_ATTRIBUTE_REPARSE_POINT is set uniformly for both IO_REPARSE_TAG_SYMLINK and
    /// IO_REPARSE_TAG_MOUNT_POINT (junction), so this one check covers both attack vectors
    /// the ticket calls out; ResolveLinkTarget is documented as .NET's symlink-oriented API
    /// and its junction coverage is less certain. Keeping a single detection mechanism
    /// across the repo (rather than two different APIs doing the same job) is also its own
    /// reason to prefer this over introducing a second approach.
    ///
    /// False (not a reparse point) for both the ordinary-file case and the doesn't-exist-yet
    /// case, matching <c>SecureStagingDirectory.IsReparsePoint</c>'s not-found-is-not-a-link
    /// convention.
    /// </summary>
    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }
}
