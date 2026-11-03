using System.Text.Json.Nodes;
using System.Globalization;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Security;

namespace Patched.Shared.BrowserExtensions;

/// <summary>
/// PAT-829: platform-neutral, profile-aware browser-extension removal — the
/// destructive escalation path after the PAT-828 managed-policy blocklist. Lives
/// in Shared (no Windows TFM) so the whole removal engine is unit-tested on macOS
/// CI, mirroring the <see cref="BrowserExtensionScanLogic"/> split: the file work
/// (delete the Extensions/&lt;id&gt; directory + prune the Secure Preferences /
/// Preferences settings entry for Chrome/Edge; drop the addon from extensions.json
/// + delete the XPI for Firefox) is all plain <c>System.IO</c>, so only the Windows
/// per-user profile enumeration (SID → account, ProfileList roots) needs the
/// Windows-only glue in <c>BrowserExtensionRemover</c> (Service).
///
/// Explicitly NOT the UninstallPlanner/RemovalRunner path — extensions have no
/// Add/Remove-Programs registry entry. Directory layout mirrors
/// browser_extensions.sh / the macOS remover (browser_extension_removal.sh) so both
/// platforms honour the same scope semantics and emit the same audit shape.
///
/// Every actual removal (a real artifact deleted for a (browser, user, profile,
/// extension) tuple) yields one <c>extension_removed</c> enforcement_audit event.
/// Nothing on disk to remove ⇒ no event, so a directive that stays in the config
/// doesn't re-post every cycle once the extension is gone (idempotent).
///
/// PAT-1329: this is a privileged recursive deleter running as SYSTEM against
/// paths seeded from every local user's own, unprivileged-writable profile —
/// the same threat class the macOS remover was hardened against twice
/// (PAT-856 root path traversal, PAT-916 symlink/TOCTOU). Two independent
/// defences close the gap here: (1) <see cref="IsSafePathSegment"/>, applied
/// in <see cref="NormalizeDirectives"/>, rejects any ExtensionId/Profile that
/// isn't a single plain path component — the primary defence, since it means
/// Path.Combine can never be handed a segment that traverses or (worse) is
/// itself rooted and silently discards every earlier segment; and (2)
/// <see cref="GuardTarget"/>, a belt-and-braces containment + reparse-point
/// chain check run immediately before every delete/move this file performs,
/// in case a future change to the path-building logic here reopens a gap (1)
/// doesn't cover. Junctions need no special Windows privilege (unlike
/// symlinks), so any local standard user can plant one inside their own
/// profile before this pass ever runs; see <see cref="GuardTarget"/> and
/// <see cref="Patched.Shared.Security.SecureStagingDirectory"/> for the
/// fail-closed philosophy this follows.
/// </summary>
internal static class ExtensionRemovalLogic
{
    /// <summary>Removal scope values, mirrored in the macOS remover and PAT-829's audit details.</summary>
    public static class Scopes
    {
        public const string OneProfile  = "one_profile";
        public const string OneObservation = "one_observation";
        public const string OneUser     = "one_user";
        public const string AllProfiles = "all_profiles";
        public const string AllDevices  = "all_devices";
    }

    private static readonly HashSet<string> KnownScopes =
        new(StringComparer.Ordinal) { Scopes.OneProfile, Scopes.OneObservation, Scopes.OneUser, Scopes.AllProfiles, Scopes.AllDevices };

    /// <summary>Supported browser name → Chromium "User Data" vendor path under AppData\Local.</summary>
    private static readonly IReadOnlyDictionary<string, string> ChromiumVendorPaths =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["chrome"] = Path.Combine("Google", "Chrome"),
            ["edge"]   = Path.Combine("Microsoft", "Edge"),
        };

    /// <summary>
    /// Validate + canonicalise the config's removal directives. Drops entries with
    /// no browser/id, an unknown scope, an unsupported browser, or a narrow scope
    /// missing the context (user/profile) it needs to target safely. Empty when
    /// app_control is disabled or the list is absent — the fail-safe (delete nothing
    /// the config didn't explicitly, sufficiently, ask for).
    /// </summary>
    public static IReadOnlyList<ExtensionRemovalDirective> NormalizeDirectives(AppControlPolicy policy) =>
        NormalizeDirectives(policy, out _, out _);

    /// <summary>
    /// Same as <see cref="NormalizeDirectives(AppControlPolicy)"/>, additionally
    /// reporting the raw scope string of every directive dropped for scope
    /// unrecognised by this agent build (PAT-1316). A dropped directive must not
    /// be indistinguishable from one the server never sent — the caller
    /// (<c>BrowserExtensionRemover</c>) logs and records an
    /// <c>AgentHealthStore</c> fault from this list; a directive dropped for any
    /// OTHER reason (missing browser/id, unsupported browser, narrow scope
    /// missing user/profile, malformed approved_before) is not included here —
    /// this list is specifically "the agent build does not know this scope",
    /// the one rejection class that previously had no signal at all, matching
    /// the macOS remover's equivalent `ext_removal: REJECT unrecognised scope`
    /// addition.
    /// </summary>
    public static IReadOnlyList<ExtensionRemovalDirective> NormalizeDirectives(
        AppControlPolicy policy, out IReadOnlyList<string> unknownScopes) =>
        NormalizeDirectives(policy, out unknownScopes, out _);

    /// <summary>
    /// Same as <see cref="NormalizeDirectives(AppControlPolicy, out IReadOnlyList{string})"/>,
    /// additionally reporting every ExtensionId/Profile value dropped by
    /// <see cref="IsSafePathSegment"/> (PAT-1329, Defect A) — a value that
    /// wasn't a single, plain path component (e.g. contained "..", a
    /// separator, or was drive/UNC-rooted). Same visibility rule as
    /// <paramref name="unknownScopes"/>: a directive dropped for this reason
    /// must not look, to the caller, like one the server never sent.
    /// </summary>
    public static IReadOnlyList<ExtensionRemovalDirective> NormalizeDirectives(
        AppControlPolicy policy, out IReadOnlyList<string> unknownScopes, out IReadOnlyList<string> invalidSegments)
    {
        var result = new List<ExtensionRemovalDirective>();
        var unknown = new List<string>();
        var invalid = new List<string>();
        if (policy is null || !policy.Enabled || policy.ExtensionRemovals.Count == 0)
        {
            unknownScopes = unknown;
            invalidSegments = invalid;
            return result;
        }

        foreach (var e in policy.ExtensionRemovals)
        {
            if (e is null) continue;
            var browser = (e.Browser ?? "").Trim().ToLowerInvariant();
            var id      = (e.ExtensionId ?? "").Trim();
            var scope   = (e.Scope ?? "").Trim().ToLowerInvariant();
            if (browser.Length == 0 || id.Length == 0) continue;

            // PAT-1329 Defect A: reject, don't sanitise. ExtensionId flows
            // straight into Path.Combine (Extensions/<id>, or <id>.xpi) with no
            // further validation downstream, so an unsafe value must never
            // leave this loop — a rooted value like "C:\Windows\System32"
            // would otherwise make Path.Combine silently discard every
            // earlier segment and hand a mutation the server never asked for.
            if (!IsSafePathSegment(id))
            {
                invalid.Add("extension_id:" + id);
                continue;
            }
            if (!KnownScopes.Contains(scope))
            {
                unknown.Add(scope);
                continue;
            }
            if (!IsSupportedBrowser(browser)) continue;

            var user    = string.IsNullOrWhiteSpace(e.UserAccount) ? null : e.UserAccount.Trim();
            var profile = string.IsNullOrWhiteSpace(e.Profile) ? null : e.Profile.Trim();

            // Same reasoning as the ExtensionId check above — Profile flows into
            // Path.Combine(userDataDir, profile) for the one_profile/
            // one_observation scopes (ChromiumProfileNames).
            if (profile is not null && !IsSafePathSegment(profile))
            {
                invalid.Add("profile:" + profile);
                continue;
            }

            // Narrow scopes must carry enough to target, or we'd have to widen the
            // blast radius to act at all — never do that for a destructive op.
            if (scope == Scopes.OneUser && user is null) continue;
            if ((scope is Scopes.OneProfile or Scopes.OneObservation) && (user is null || profile is null)) continue;
            DateTimeOffset? approvedBefore = null;
            if (scope == Scopes.OneObservation)
            {
                var raw = (e.ApprovedBefore ?? "").Trim();
                var hasExplicitOffset = raw.EndsWith('Z') ||
                    (raw.Length >= 6 && (raw[^6] == '+' || raw[^6] == '-') && raw[^3] == ':');
                if (!hasExplicitOffset || !DateTimeOffset.TryParse(
                        raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                        out var parsedBoundary)) continue;
                approvedBefore = parsedBoundary;
            }

            result.Add(new ExtensionRemovalDirective
            {
                Browser     = browser,
                ExtensionId = id,
                Scope       = scope,
                UserAccount = user,
                Profile     = profile,
                ApprovedBefore = approvedBefore,
                ApprovedBeforeRaw = e.ApprovedBefore,
            });
        }
        unknownScopes = unknown;
        invalidSegments = invalid;
        return result;
    }

    public static bool IsSupportedBrowser(string browser) =>
        browser == "firefox" || ChromiumVendorPaths.ContainsKey(browser);

    /// <summary>
    /// PAT-1329 (Defect A): true when <paramref name="segment"/> is safe to use
    /// as exactly one path component — an ExtensionId or Profile name — with no
    /// possibility of traversing outside, or resetting (see the class doc's
    /// Path.Combine footgun note), the path it's later Path.Combine'd into.
    ///
    /// Deliberately manual character checks rather than Path.IsPathRooted /
    /// Path.GetInvalidPathChars: this file has no Windows TFM and is
    /// unit-tested on macOS CI (see the class doc), where those APIs answer
    /// the *host* OS's rules, not Windows'. A drive-qualified id like
    /// "C:\Windows\System32" must be rejected identically whether this runs
    /// in a macOS test process or the Windows box that actually executes it.
    ///
    /// Reject, don't sanitise — same philosophy as
    /// <see cref="Patched.Shared.Security.SecureStagingDirectory"/>'s reparse-point
    /// handling: a segment failing any of these is dropped whole by the
    /// caller, never repaired.
    /// </summary>
    internal static bool IsSafePathSegment(string? segment)
    {
        if (string.IsNullOrEmpty(segment)) return false;
        if (segment is "." or "..") return false;
        if (segment.IndexOfAny(['/', '\\']) >= 0) return false; // separator, incl. UNC (\\server\share)
        if (segment.Contains(':')) return false;                 // drive-qualified (C:) or NTFS ADS
        foreach (var c in Path.GetInvalidFileNameChars())
            if (segment.Contains(c)) return false;
        return true;
    }

    /// <summary>
    /// Execute every in-scope directive against one Windows user's profile root
    /// (e.g. <c>C:\Users\alice</c>), returning one audit event per artifact actually
    /// removed. Never throws — per-directive/per-profile failures are swallowed so
    /// one corrupt profile can't abort the rest of the device's removal pass. The
    /// caller (BrowserExtensionRemover) invokes this once per enumerated user, which
    /// is what makes the device-wide scopes cover every user.
    /// </summary>
    public static IReadOnlyList<EnforcementAuditEvent> RemoveForUser(
        string profileRoot, string userAccount,
        IReadOnlyList<ExtensionRemovalDirective> directives,
        string deviceId, bool dryRun, string occurredAt)
    {
        var events = new List<EnforcementAuditEvent>();
        foreach (var d in directives)
        {
            try
            {
                if (!UserInScope(d, userAccount)) continue;
                if (d.Browser == "firefox")
                    RemoveFirefox(profileRoot, userAccount, d, deviceId, dryRun, occurredAt, events);
                else
                    RemoveChromium(profileRoot, userAccount, d, deviceId, dryRun, occurredAt, events);
            }
            catch
            {
                // Skip this directive for this user; the next cycle retries.
            }
        }
        return events;
    }

    /// <summary>Whether a directive's scope selects this user account at all.</summary>
    public static bool UserInScope(ExtensionRemovalDirective d, string userAccount) =>
        d.Scope is Scopes.AllProfiles or Scopes.AllDevices
            ? true
            : d.UserAccount is not null &&
              string.Equals(d.UserAccount, userAccount, StringComparison.OrdinalIgnoreCase);

    // -------------------------------------------------------------------------
    // Chromium (Chrome / Edge)
    // -------------------------------------------------------------------------

    private static void RemoveChromium(
        string profileRoot, string userAccount, ExtensionRemovalDirective d,
        string deviceId, bool dryRun, string occurredAt, List<EnforcementAuditEvent> events)
    {
        var userDataDir = Path.Combine(
            profileRoot, "AppData", "Local", ChromiumVendorPaths[d.Browser], "User Data");
        if (!Directory.Exists(userDataDir)) return;

        foreach (var profileName in ChromiumProfileNames(userDataDir, d))
        {
            var profileDir = Path.Combine(userDataDir, profileName);
            if (!Directory.Exists(profileDir)) continue;

            // PAT-1329: belt-and-braces containment + reparse-point check.
            // profileName is already a validated single segment (Defect A), so
            // this should never actually trip — a refusal here means something
            // upstream of this file's own validation is wrong, and the whole
            // profile is untrusted, not just one mutation within it.
            if (!GuardTarget(profileRoot, userDataDir, profileDir, d, profileName,
                    userAccount, deviceId, occurredAt, events))
                continue;

            var removed = false;

            var extDir = Path.Combine(profileDir, "Extensions", d.ExtensionId);
            var extGuarded = GuardTarget(profileRoot, userDataDir, extDir, d, profileName,
                userAccount, deviceId, occurredAt, events);
            var observationMatches = d.Scope != Scopes.OneObservation;
            if (d.Scope == Scopes.OneObservation)
            {
                removed = extGuarded && RemoveObservedDirectory(extDir, d.ApprovedBefore, dryRun);
                observationMatches = removed;
            }
            else if (extGuarded && Directory.Exists(extDir) && DeleteDirectory(extDir, dryRun))
                removed = true;

            // Prune the settings entry from Secure Preferences (preferred) and
            // Preferences — same precedence the collector reads it from.
            //
            // PAT-1316: one_observation is not a functionally distinct removal —
            // the server compiles every broader scope down to one_observation
            // directives at delivery time (same removal request, narrowed to one
            // already-observed target, with ApprovedBefore as the only added safety
            // check). So once the boundary check has cleared (observationMatches —
            // for every OTHER scope this is unconditionally true, matching this
            // block's pre-PAT-1316 behaviour exactly), prune the settings entry the
            // same as any other scope. Also gating this on
            // `d.Scope != Scopes.OneObservation` (as an earlier version of this
            // diff did) would silently skip prefs pruning for every successful
            // one_observation removal — the very silent-partial-removal failure
            // mode this ticket exists to eliminate.
            if (observationMatches)
                foreach (var prefsName in new[] { "Secure Preferences", "Preferences" })
                {
                    var prefsPath = Path.Combine(profileDir, prefsName);
                    if (GuardTarget(profileRoot, userDataDir, prefsPath, d, profileName,
                            userAccount, deviceId, occurredAt, events) &&
                        RemoveChromiumSettingsEntry(prefsPath, d.ExtensionId, dryRun))
                        removed = true;
                }

            if (removed)
                events.Add(BuildEvent(d, profileName, userAccount, deviceId, occurredAt, dryRun));
        }
    }

    /// <summary>
    /// Profile directory names to act on: just the named one for one_profile scope,
    /// else "Default" plus every "Profile N". Chrome/Edge always use those internal
    /// names regardless of display name — same assumption as the scanner.
    /// </summary>
    private static IEnumerable<string> ChromiumProfileNames(string userDataDir, ExtensionRemovalDirective d)
    {
        if ((d.Scope is Scopes.OneProfile or Scopes.OneObservation) && d.Profile is not null)
            return new[] { d.Profile };

        var names = new List<string> { "Default" };
        try
        {
            names.AddRange(Directory.GetDirectories(userDataDir, "Profile *")
                .Select(Path.GetFileName)
                .Where(n => !string.IsNullOrEmpty(n))!);
        }
        catch
        {
            // Enumeration failure — still try "Default".
        }
        return names.Distinct(StringComparer.Ordinal);
    }

    /// <summary>
    /// Remove extensions.settings.&lt;id&gt; from a Chromium prefs file. Returns true if
    /// the entry existed (and was removed, unless dry-run). A write failure after a
    /// real edit returns false so we don't audit an unpersisted removal — the file
    /// on disk is untouched and the next cycle retries.
    /// </summary>
    private static bool RemoveChromiumSettingsEntry(string prefsPath, string extId, bool dryRun)
    {
        if (!File.Exists(prefsPath)) return false;

        JsonNode? root;
        try { root = JsonNode.Parse(File.ReadAllText(prefsPath)); }
        catch { return false; }

        if (root is not JsonObject obj ||
            obj["extensions"] is not JsonObject ext ||
            ext["settings"] is not JsonObject settings ||
            !settings.ContainsKey(extId))
            return false;

        if (dryRun) return true;

        settings.Remove(extId);
        return AtomicWrite(prefsPath, root.ToJsonString());
    }

    // -------------------------------------------------------------------------
    // Firefox
    // -------------------------------------------------------------------------

    private static void RemoveFirefox(
        string profileRoot, string userAccount, ExtensionRemovalDirective d,
        string deviceId, bool dryRun, string occurredAt, List<EnforcementAuditEvent> events)
    {
        var profilesDir = Path.Combine(profileRoot, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
        if (!Directory.Exists(profilesDir)) return;

        string[] profileDirs;
        try { profileDirs = Directory.GetDirectories(profilesDir); }
        catch { return; }

        foreach (var profileDir in profileDirs)
        {
            var profileName = Path.GetFileName(
                profileDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if ((d.Scope is Scopes.OneProfile or Scopes.OneObservation) &&
                !string.Equals(profileName, d.Profile, StringComparison.Ordinal))
                continue;

            // PAT-1329: belt-and-braces containment + reparse-point check.
            // profileDir came from a real Directory.GetDirectories enumeration
            // (not built from directive-supplied data), so this should never
            // trip; checked anyway since everything mutated below hangs off it.
            if (!GuardTarget(profileRoot, profilesDir, profileDir, d, profileName,
                    userAccount, deviceId, occurredAt, events))
                continue;

            var removed = false;

            var xpi = Path.Combine(profileDir, "extensions", d.ExtensionId + ".xpi");
            var xpiGuarded = GuardTarget(profileRoot, profilesDir, xpi, d, profileName,
                userAccount, deviceId, occurredAt, events);
            var observationMatches = d.Scope != Scopes.OneObservation;
            if (d.Scope == Scopes.OneObservation)
            {
                removed = xpiGuarded && RemoveObservedFile(xpi, d.ApprovedBefore, dryRun);
                observationMatches = removed;
            }
            else if (xpiGuarded && File.Exists(xpi) && DeleteFile(xpi, dryRun))
                removed = true;
            // PAT-1316: see the matching comment in RemoveChromium above — the same
            // "prune only after the boundary check passed" rule applies here,
            // without an extra scope check that would otherwise silently skip the
            // extensions.json prune for every one_observation removal.
            var extFile = Path.Combine(profileDir, "extensions.json");
            if (observationMatches &&
                GuardTarget(profileRoot, profilesDir, extFile, d, profileName,
                    userAccount, deviceId, occurredAt, events) &&
                RemoveFirefoxAddonEntry(extFile, d.ExtensionId, dryRun))
                removed = true;

            if (removed)
                events.Add(BuildEvent(d, profileName, userAccount, deviceId, occurredAt, dryRun));
        }
    }

    /// <summary>
    /// Drop the addon(s) with this id from extensions.json's addons[]. Returns true
    /// if any matched (and were removed, unless dry-run). Write failure after a real
    /// edit returns false so the removal isn't audited until it actually persisted.
    /// </summary>
    private static bool RemoveFirefoxAddonEntry(string extFile, string extId, bool dryRun)
    {
        if (!File.Exists(extFile)) return false;

        JsonNode? root;
        try { root = JsonNode.Parse(File.ReadAllText(extFile)); }
        catch { return false; }

        if (root is not JsonObject obj || obj["addons"] is not JsonArray addons)
            return false;

        var matched = false;
        for (var i = addons.Count - 1; i >= 0; i--)
        {
            if (addons[i] is JsonObject a &&
                a["id"] is JsonValue idVal &&
                idVal.TryGetValue<string>(out var id) &&
                id == extId)
            {
                matched = true;
                if (!dryRun) addons.RemoveAt(i);
            }
        }
        if (!matched) return false;
        if (dryRun) return true;

        return AtomicWrite(extFile, root.ToJsonString());
    }

    // -------------------------------------------------------------------------
    // Audit + IO helpers
    // -------------------------------------------------------------------------

    /// <summary>Build the extension_removed audit event with PAT-829's details shape.</summary>
    public static EnforcementAuditEvent BuildEvent(
        ExtensionRemovalDirective d, string profile, string userAccount,
        string deviceId, string occurredAt, bool dryRun) =>
        new()
        {
            EventType  = EnforcementAuditEventTypes.ExtensionRemoved,
            Subject    = d.ExtensionId,
            OccurredAt = occurredAt,
            Details = new
            {
                approved_before = d.ApprovedBeforeRaw,
                browser      = d.Browser,
                profile,
                user_account = userAccount,
                device_id    = deviceId,
                scope        = d.Scope,
                dry_run      = dryRun,
            },
        };

    /// <summary>PAT-1329: audit shape for a mutation refused by <see cref="GuardTarget"/> —
    /// visible signal mirroring <see cref="BuildEvent"/>, with <c>details.reason</c>
    /// distinguishing "path_containment" from "reparse_point".</summary>
    private static EnforcementAuditEvent BuildRefusalEvent(
        ExtensionRemovalDirective d, string profile, string userAccount,
        string deviceId, string occurredAt, string reason) =>
        new()
        {
            EventType  = EnforcementAuditEventTypes.ExtensionRemovalRefused,
            Subject    = d.ExtensionId,
            OccurredAt = occurredAt,
            Details = new
            {
                browser      = d.Browser,
                profile,
                user_account = userAccount,
                device_id    = deviceId,
                scope        = d.Scope,
                reason,
            },
        };

    /// <summary>
    /// PAT-1329 (Defect B) belt-and-braces guard: call immediately before any
    /// delete/move mutation this file performs on a path built from
    /// directive-supplied data. Two independent, fail-closed checks:
    ///
    ///  1. containment — <paramref name="target"/> must canonicalise
    ///     (<see cref="Path.GetFullPath"/>) to strictly inside
    ///     <paramref name="expectedRoot"/> (the browser's User Data dir for
    ///     Chromium, the Profiles dir for Firefox) — see <see cref="Patched.Shared.Security.PathSafety.IsContained"/>.
    ///     Defence-in-depth behind <see cref="IsSafePathSegment"/> (Defect A):
    ///     once ExtensionId/Profile can only ever be a single safe path
    ///     component, Path.Combine can no longer escape <paramref name="expectedRoot"/>,
    ///     so this should never actually trip for a well-formed directive.
    ///  2. reparse point — no path component from <paramref name="profileRoot"/>
    ///     (the enumerated, trusted per-user profile root, e.g. C:\Users\alice)
    ///     down to and including <paramref name="target"/> may be a reparse
    ///     point (NTFS junction/symlink) — see <see cref="Patched.Shared.Security.PathSafety.HasReparsePointInChain"/>.
    ///     Junctions need no special Windows privilege, so any local standard
    ///     user can plant one inside their own profile — anywhere along that
    ///     chain, not just at the leaf — before this SYSTEM-privileged pass
    ///     ever runs.
    ///
    /// On failure, appends an <see cref="EnforcementAuditEventTypes.ExtensionRemovalRefused"/>
    /// event and returns <see langword="false"/> — refusing is the expected,
    /// visible outcome; the caller skips only this one mutation, and
    /// <see cref="RemoveForUser"/>'s outer per-directive try/catch remains a
    /// last resort, not the normal path. Never throws past this method.
    /// </summary>
    private static bool GuardTarget(
        string profileRoot, string expectedRoot, string target,
        ExtensionRemovalDirective d, string profile, string userAccount,
        string deviceId, string occurredAt, List<EnforcementAuditEvent> events)
    {
        if (!PathSafety.IsContained(expectedRoot, target))
        {
            events.Add(BuildRefusalEvent(d, profile, userAccount, deviceId, occurredAt, "path_containment"));
            return false;
        }
        if (PathSafety.HasReparsePointInChain(profileRoot, target))
        {
            events.Add(BuildRefusalEvent(d, profile, userAccount, deviceId, occurredAt, "reparse_point"));
            return false;
        }
        return true;
    }

    /// <summary>
    /// A path that doesn't exist is not (yet) a reparse point — nothing to
    /// refuse; the caller's own Exists check governs whether it proceeds.
    /// </summary>
    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private static bool AtomicWrite(string path, string contents)
    {
        try
        {
            // PAT-1329 (Defect B) leaf-level defence-in-depth: refuse to move
            // through a destination that is itself a reparse point (a planted
            // file symlink could redirect this write anywhere). GuardTarget at
            // the call site already checked the full chain; this re-check is
            // deliberate per-mutation belt-and-braces, not trust in the caller.
            if (IsReparsePoint(path)) return false;
            var tmp = path + ".patched.tmp";
            File.WriteAllText(tmp, contents);
            File.Move(tmp, path, overwrite: true);
            return true;
        }
        catch { return false; }
    }

    /// <summary>Dry-run reports "would remove" (true) without touching disk; else deletes and reports success.</summary>
    private static bool DeleteDirectory(string path, bool dryRun)
    {
        if (dryRun) return true;
        // PAT-1329 (Defect B): this leaf check covers `path` itself being a
        // reparse point (belt-and-braces behind GuardTarget's chain walk at
        // the call site). It does NOT cover a reparse point nested somewhere
        // *inside* `path`'s own subtree (e.g. a planted junction under the
        // extension's own version folder) — that's a separate question about
        // Directory.Delete's own recursion behaviour, which we do not rely on
        // either way. Verified empirically on the Windows staging VM (real
        // .NET 8.0.28, 2026-08-13): given a plain directory containing a
        // nested NTFS junction (`mklink /J`) to an outside directory,
        // Directory.Delete(path, recursive: true) does NOT follow the
        // junction and delete through it — it throws IOException ("The
        // parameter is incorrect.") and deletes NOTHING, leaving the whole
        // tree (including the junction and its target) intact. That's
        // fail-safe (caught below, reported as "not removed", next cycle
        // retries) but it is .NET's behaviour to keep, not this file's
        // guarantee to assert — hence the explicit leaf check above stays
        // regardless of what a future .NET version does here.
        if (IsReparsePoint(path)) return false;
        try { Directory.Delete(path, recursive: true); return true; }
        catch { return false; }
    }

    private static bool DeleteFile(string path, bool dryRun)
    {
        if (dryRun) return true;
        if (IsReparsePoint(path)) return false; // PAT-1329, see DeleteDirectory.
        try { File.Delete(path); return true; }
        catch { return false; }
    }

    internal static bool RemoveObservedDirectory(
        string path, DateTimeOffset? approvedBefore, bool dryRun,
        Action<string>? afterQuarantine = null)
    {
        if (approvedBefore is null) return false;
        try
        {
            if (!Directory.Exists(path) ||
                Directory.GetLastWriteTimeUtc(path) > approvedBefore.Value.UtcDateTime) return false;
            if (dryRun) return true;
            if (IsReparsePoint(path)) return false; // PAT-1329, see DeleteDirectory.
            var quarantine = path + ".patched-observed-" + Guid.NewGuid().ToString("N");
            Directory.Move(path, quarantine);
            afterQuarantine?.Invoke(quarantine);
            if (Directory.GetLastWriteTimeUtc(quarantine) > approvedBefore.Value.UtcDateTime)
            {
                if (!Directory.Exists(path)) Directory.Move(quarantine, path);
                return false;
            }
            if (DeleteDirectory(quarantine, dryRun: false)) return true;
            // The active browser path is gone even if quarantine cleanup was
            // partial; emit evidence for that real removal state.
            return !Directory.Exists(path);
        }
        catch { return false; }
    }

    internal static bool RemoveObservedFile(
        string path, DateTimeOffset? approvedBefore, bool dryRun,
        Action<string>? afterQuarantine = null)
    {
        if (approvedBefore is null) return false;
        try
        {
            if (!File.Exists(path) ||
                File.GetLastWriteTimeUtc(path) > approvedBefore.Value.UtcDateTime) return false;
            if (dryRun) return true;
            if (IsReparsePoint(path)) return false; // PAT-1329, see DeleteDirectory.
            var quarantine = path + ".patched-observed-" + Guid.NewGuid().ToString("N");
            File.Move(path, quarantine);
            afterQuarantine?.Invoke(quarantine);
            if (File.GetLastWriteTimeUtc(quarantine) > approvedBefore.Value.UtcDateTime)
            {
                if (!File.Exists(path)) File.Move(quarantine, path);
                return false;
            }
            if (DeleteFile(quarantine, dryRun: false)) return true;
            return !File.Exists(path);
        }
        catch { return false; }
    }
}

/// <summary>One validated removal directive from the agent-config app_control block.</summary>
internal sealed record ExtensionRemovalDirective
{
    public DateTimeOffset? ApprovedBefore { get; init; }
    public string? ApprovedBeforeRaw { get; init; }
    public required string Browser { get; init; }
    public required string ExtensionId { get; init; }
    public required string Scope { get; init; }
    public string? UserAccount { get; init; }
    public string? Profile { get; init; }
}
