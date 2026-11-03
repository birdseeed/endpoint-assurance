using System.Text.Json;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-829: platform-neutral tests for <see cref="ExtensionRemovalLogic"/> — the
/// profile-aware, audited browser-extension removal engine. Because the file work
/// is plain System.IO, the whole engine (not just a decision layer) is exercised
/// here against temp Windows-layout profile trees, so these run on macOS CI; the
/// Windows-only glue (ProfileList/SID enumeration) lives in BrowserExtensionRemover.
///
/// Multi-user / multi-profile coverage is explicit: fixtures build two users each
/// with two Chrome profiles plus Firefox, and the scope tests assert removal hits
/// exactly the intended (user, profile) set and nothing else.
/// </summary>
public sealed class ExtensionRemovalLogicTests : IDisposable
{
    private readonly string _work;

    public ExtensionRemovalLogicTests()
    {
        _work = Path.Combine(Path.GetTempPath(), ".ext-removal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_work);
    }

    public void Dispose()
    {
        try { Directory.Delete(_work, recursive: true); } catch { /* best-effort */ }
    }

    // -------------------------------------------------------------------------
    // Fixture builders — mirror the Windows on-disk layout the logic walks.
    // -------------------------------------------------------------------------

    private string UserRoot(string user)
    {
        var root = Path.Combine(_work, user);
        Directory.CreateDirectory(root);
        return root;
    }

    private static string ChromiumUserData(string userRoot, string browser)
    {
        var vendor = browser == "edge" ? Path.Combine("Microsoft", "Edge") : Path.Combine("Google", "Chrome");
        return Path.Combine(userRoot, "AppData", "Local", vendor, "User Data");
    }

    /// <summary>Creates Extensions/&lt;id&gt;/1.0/manifest.json and a Secure Preferences settings entry.</summary>
    private static void SeedChromiumExtension(string userRoot, string browser, string profile, string id, bool withSettings = true)
    {
        var profileDir = Path.Combine(ChromiumUserData(userRoot, browser), profile);
        var versionDir = Path.Combine(profileDir, "Extensions", id, "1.0");
        Directory.CreateDirectory(versionDir);
        File.WriteAllText(Path.Combine(versionDir, "manifest.json"), """{"name":"X","version":"1.0"}""");

        if (withSettings)
        {
            var prefs = "{\"extensions\":{\"settings\":{\"" + id + "\":{\"state\":1},\"keep-me\":{\"state\":1}}}}";
            File.WriteAllText(Path.Combine(profileDir, "Secure Preferences"), prefs);
        }
    }

    private static bool ChromiumExtensionDirExists(string userRoot, string browser, string profile, string id) =>
        Directory.Exists(Path.Combine(ChromiumUserData(userRoot, browser), profile, "Extensions", id));

    private static bool ChromiumSettingsHas(string userRoot, string browser, string profile, string id)
    {
        var prefs = Path.Combine(ChromiumUserData(userRoot, browser), profile, "Secure Preferences");
        if (!File.Exists(prefs)) return false;
        using var doc = JsonDocument.Parse(File.ReadAllText(prefs));
        return doc.RootElement.GetProperty("extensions").GetProperty("settings").TryGetProperty(id, out _);
    }

    private static string FirefoxProfileDir(string userRoot, string profile) =>
        Path.Combine(userRoot, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", profile);

    private static void SeedFirefoxExtension(string userRoot, string profile, string id, bool withXpi = true)
    {
        var profileDir = FirefoxProfileDir(userRoot, profile);
        Directory.CreateDirectory(profileDir);
        var json = "{\"addons\":[{\"id\":\"" + id + "\",\"type\":\"extension\"},{\"id\":\"keep@x\",\"type\":\"extension\"}]}";
        File.WriteAllText(Path.Combine(profileDir, "extensions.json"), json);

        if (withXpi)
        {
            var extDir = Path.Combine(profileDir, "extensions");
            Directory.CreateDirectory(extDir);
            File.WriteAllText(Path.Combine(extDir, id + ".xpi"), "PK-fake-xpi");
        }
    }

    private static bool FirefoxAddonPresent(string userRoot, string profile, string id)
    {
        var f = Path.Combine(FirefoxProfileDir(userRoot, profile), "extensions.json");
        if (!File.Exists(f)) return false;
        using var doc = JsonDocument.Parse(File.ReadAllText(f));
        foreach (var a in doc.RootElement.GetProperty("addons").EnumerateArray())
            if (a.TryGetProperty("id", out var idEl) && idEl.GetString() == id) return true;
        return false;
    }

    private static bool FirefoxXpiExists(string userRoot, string profile, string id) =>
        File.Exists(Path.Combine(FirefoxProfileDir(userRoot, profile), "extensions", id + ".xpi"));

    private static AppControlPolicy Policy(bool enabled, params ExtensionRemovalEntry[] entries) =>
        new() { Enabled = enabled, ExtensionRemovals = entries.ToList() };

    private static ExtensionRemovalEntry Entry(
        string browser, string id, string scope, string? user = null, string? profile = null,
        string? approvedBefore = null) =>
        new() { Browser = browser, ExtensionId = id, Scope = scope, UserAccount = user,
            Profile = profile, ApprovedBefore = approvedBefore };

    private static IReadOnlyList<EnforcementAuditEvent> Run(
        AppControlPolicy policy, string userRoot, string userAccount, bool dryRun = false) =>
        ExtensionRemovalLogic.RemoveForUser(
            userRoot, userAccount,
            ExtensionRemovalLogic.NormalizeDirectives(policy),
            "DEVICE-1", dryRun, "2026-07-11T00:00:00Z");

    // -------------------------------------------------------------------------
    // NormalizeDirectives
    // -------------------------------------------------------------------------

    [Fact]
    public void Normalize_DisabledOrEmpty_ReturnsEmpty()
    {
        Assert.Empty(ExtensionRemovalLogic.NormalizeDirectives(
            Policy(false, Entry("chrome", "aaaa", "all_devices"))));
        Assert.Empty(ExtensionRemovalLogic.NormalizeDirectives(Policy(true)));
    }

    [Fact]
    public void Normalize_DropsUnknownScopeAndUnsupportedBrowser()
    {
        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", "aaaa", "everywhere"),      // unknown scope
            Entry("brave", "bbbb", "all_devices"),       // unsupported browser
            Entry("edge", "cccc", "all_profiles")));      // valid
        var only = Assert.Single(d);
        Assert.Equal("edge", only.Browser);
        Assert.Equal("cccc", only.ExtensionId);
    }

    [Fact]
    public void NormalizeDirectives_OutParam_ReportsOnlyUnrecognisedScopes()
    {
        // PAT-1316: the out-param overload feeds BrowserExtensionRemover's
        // ext_removal: REJECT logging + AgentHealthStore fault. It must report
        // exactly the unrecognised-scope drops — not the other, differently
        // reasoned drops (unsupported browser here) — since those already have
        // their own signal (or, for the merely-incomplete browser/id case,
        // don't need one).
        ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", "aaaa", "everywhere"),        // unknown scope
            Entry("brave", "bbbb", "all_devices"),         // unsupported browser, KNOWN scope
            Entry("edge", "cccc", "all_profiles")),         // valid
            out var unknownScopes);
        Assert.Equal(new[] { "everywhere" }, unknownScopes);
    }

    [Fact]
    public void KnownScopes_IsSupersetOf_CrossRepoContract()
    {
        // PAT-1316: contracts/extension-removal-scopes.json is vendored VERBATIM
        // in both this repo (updater) and Patched-LTD/patched.im — see that
        // file's own note. Neither repo's CI can see the other, so this test
        // only catches an agent build whose accepted-scope vocabulary regresses
        // out from under a scope the contract says the server may emit; it
        // cannot catch the patched.im copy being edited alone with nothing
        // changed here — that half of the pairing has no enforcement at all.
        //
        // Deliberately a SUPERSET assertion, not equality: the server currently
        // emits only "one_observation" (broader operator scopes are compiled
        // down to it server-side — go-service's dbGetExtensionRemovalsForDevice
        // projects only per-device one_observation directives), while this agent
        // still accepts the four legacy scope values too, for directives issued
        // by, or still in flight from, an older server build. The agent is
        // allowed to accept more than the contract requires; it must never
        // accept less.
        //
        // Exercises the real NormalizeDirectives validation path (not a
        // hand-copied shadow list of the private KnownScopes set) — for every
        // contract scope, a minimally-valid directive using it must NOT come
        // back in the unrecognised-scope list.
        var path = LocateContractsFile("extension-removal-scopes.json");
        if (path is null) return; // contracts/ not reachable in this build context

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var contractScopes = doc.RootElement.GetProperty("scopes")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();
        Assert.NotEmpty(contractScopes);

        var entries = contractScopes.Select(scope => scope switch
        {
            "one_user" => Entry("chrome", "aaaa", scope, user: "alice"),
            "one_profile" => Entry("chrome", "aaaa", scope, user: "alice", profile: "Default"),
            "one_observation" => Entry("chrome", "aaaa", scope, user: "alice", profile: "Default",
                approvedBefore: "2026-07-11T00:00:00Z"),
            _ => Entry("chrome", "aaaa", scope), // all_profiles / all_devices need no context
        }).ToArray();

        ExtensionRemovalLogic.NormalizeDirectives(Policy(true, entries), out var unknownScopes);

        Assert.Empty(unknownScopes);
    }

    private static string? LocateContractsFile(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "contracts", fileName);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    [Fact]
    public void Normalize_NarrowScopeMissingContext_IsDropped()
    {
        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", "aaaa", "one_user"),                       // no user → drop
            Entry("chrome", "bbbb", "one_profile", user: "alice"),      // no profile → drop
            Entry("chrome", "cccc", "one_profile", user: "alice", profile: "Default"),  // ok
            Entry("chrome", "dddd", "one_user", user: "bob")));          // ok
        Assert.Equal(new[] { "cccc", "dddd" }, d.Select(x => x.ExtensionId).ToArray());
    }

    [Fact]
    public void Normalize_ObservationRequiresExplicitTimezone()
    {
        var directives = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", "aaaa", "one_observation", "alice", "Default", "2026-07-11T00:00:00"),
            Entry("chrome", "bbbb", "one_observation", "alice", "Default", "2026-07-11T00:00:00Z")));
        var only = Assert.Single(directives);
        Assert.Equal("bbbb", only.ExtensionId);
    }

    [Fact]
    public void Normalize_LowercasesBrowserAndScope_TrimsFields()
    {
        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("CHROME", " aaaa ", "ALL_DEVICES")));
        var one = Assert.Single(d);
        Assert.Equal("chrome", one.Browser);
        Assert.Equal("aaaa", one.ExtensionId);
        Assert.Equal("all_devices", one.Scope);
    }

    // -------------------------------------------------------------------------
    // PAT-1329 Defect A — plain-path-segment validation (ExtensionId/Profile)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"\\server\share")]
    [InlineData("bad\0id")]   // NUL — in Path.GetInvalidFileNameChars() on every OS
    [InlineData(".")]
    public void Normalize_RejectsUnsafeExtensionId(string unsafeId)
    {
        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", unsafeId, "all_devices")));
        Assert.Empty(d);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"\\server\share")]
    [InlineData("bad\0profile")]
    [InlineData(".")]
    public void Normalize_RejectsUnsafeProfile(string unsafeProfile)
    {
        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", "goodid", "one_profile", user: "alice", profile: unsafeProfile)));
        Assert.Empty(d);
    }

    [Fact]
    public void Normalize_RejectsRootedExtensionId_PathCombineResetCase()
    {
        // The bug this ticket closes: Path.Combine discards every earlier
        // segment once it hits a rooted one, so an unvalidated ExtensionId of
        // "C:\Windows\System32" would make Path.Combine(profileDir,
        // "Extensions", id) equal exactly "C:\Windows\System32" — not a path
        // under Extensions at all. NormalizeDirectives must never let this
        // value reach Path.Combine in the first place.
        Assert.False(ExtensionRemovalLogic.IsSafePathSegment(@"C:\Windows\System32"));

        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", @"C:\Windows\System32", "all_devices")));
        Assert.Empty(d);
    }

    [Fact]
    public void Normalize_AcceptsOrdinaryIdsAndProfiles_NoBehaviourChange()
    {
        // Well-formed directives must sail through unchanged — the acceptance
        // bar for this ticket, not just "bad things get rejected".
        var d = ExtensionRemovalLogic.NormalizeDirectives(Policy(true,
            Entry("chrome", "abcdefghijklmnopqrstuvwxyz012345", "one_profile",
                user: "alice", profile: "Profile 1"),
            Entry("firefox", "my-addon@example.com", "all_devices")));
        Assert.Equal(2, d.Count);
    }

    // -------------------------------------------------------------------------
    // Chromium removal — directory + settings
    // -------------------------------------------------------------------------

    [Fact]
    public void Chromium_RemovesDirectoryAndSettingsEntry_KeepsOthers()
    {
        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "badext");

        var events = Run(Policy(true, Entry("chrome", "badext", "all_profiles")), alice, "alice");

        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "badext"));
        Assert.False(ChromiumSettingsHas(alice, "chrome", "Default", "badext"));
        Assert.True(ChromiumSettingsHas(alice, "chrome", "Default", "keep-me"));  // untouched
        var evt = Assert.Single(events);
        Assert.Equal(EnforcementAuditEventTypes.ExtensionRemoved, evt.EventType);
        Assert.Equal("badext", evt.Subject);
    }

    [Fact]
    public void ObservationBoundRemoval_RejectsNewerReinstall_AndAcceptsApprovedInstall()
    {
        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "newext");
        var extDir = Path.Combine(ChromiumUserData(alice, "chrome"), "Default", "Extensions", "newext");
        Directory.SetLastWriteTimeUtc(extDir, new DateTime(2026, 7, 12, 0, 0, 0, DateTimeKind.Utc));

        var staleApproval = Policy(true, Entry(
            "chrome", "newext", "one_observation", "alice", "Default",
            "2026-07-11T00:00:00Z"));
        Assert.Empty(Run(staleApproval, alice, "alice"));
        Assert.True(ChromiumExtensionDirExists(alice, "chrome", "Default", "newext"));
        Assert.True(ChromiumSettingsHas(alice, "chrome", "Default", "newext"));

        var currentApproval = Policy(true, Entry(
            "chrome", "newext", "one_observation", "alice", "Default",
            "2026-07-13T00:00:00Z"));
        Assert.Single(Run(currentApproval, alice, "alice"));
        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "newext"));
        // PAT-1316: one_observation is the same removal as one_profile, just
        // narrowed to one already-observed target by the server — once the
        // approved_before boundary clears, the Preferences/Secure Preferences
        // settings entry is pruned exactly like every other scope, not left behind.
        Assert.False(ChromiumSettingsHas(alice, "chrome", "Default", "newext"));
    }

    [Fact]
    public void ObservationBoundFirefoxRemoval_RejectsNewerReinstall_AndAcceptsApprovedInstall()
    {
        var alice = UserRoot("alice");
        SeedFirefoxExtension(alice, "abc.default", "new@x");
        var xpi = Path.Combine(FirefoxProfileDir(alice, "abc.default"), "extensions", "new@x.xpi");
        File.SetLastWriteTimeUtc(xpi, new DateTime(2026, 7, 12, 0, 0, 0, DateTimeKind.Utc));

        var staleApproval = Policy(true, Entry(
            "firefox", "new@x", "one_observation", "alice", "abc.default",
            "2026-07-11T00:00:00Z"));
        Assert.Empty(Run(staleApproval, alice, "alice"));
        Assert.True(FirefoxXpiExists(alice, "abc.default", "new@x"));
        Assert.True(FirefoxAddonPresent(alice, "abc.default", "new@x"));

        var currentApproval = Policy(true, Entry(
            "firefox", "new@x", "one_observation", "alice", "abc.default",
            "2026-07-13T00:00:00Z"));
        Assert.Single(Run(currentApproval, alice, "alice"));
        Assert.False(FirefoxXpiExists(alice, "abc.default", "new@x"));
        // PAT-1316: see the matching comment in the Chromium test above.
        Assert.False(FirefoxAddonPresent(alice, "abc.default", "new@x"));
    }

    [Fact]
    public void ObservationRemoval_AtomicQuarantineLeavesConcurrentReplacementsUntouched()
    {
        var boundary = DateTimeOffset.Parse("2026-07-13T00:00:00Z");
        var dir = Path.Combine(_work, "observed-dir");
        Directory.CreateDirectory(dir);
        Directory.SetLastWriteTimeUtc(dir, boundary.UtcDateTime.AddDays(-1));
        Assert.True(ExtensionRemovalLogic.RemoveObservedDirectory(
            dir, boundary, dryRun: false,
            _ => { Directory.CreateDirectory(dir); File.WriteAllText(Path.Combine(dir, "new"), "new"); }));
        Assert.True(File.Exists(Path.Combine(dir, "new")));

        var file = Path.Combine(_work, "observed.xpi");
        File.WriteAllText(file, "old");
        File.SetLastWriteTimeUtc(file, boundary.UtcDateTime.AddDays(-1));
        Assert.True(ExtensionRemovalLogic.RemoveObservedFile(
            file, boundary, dryRun: false,
            _ => File.WriteAllText(file, "new")));
        Assert.Equal("new", File.ReadAllText(file));
    }

    [Fact]
    public void Chromium_SettingsOnlyNoDir_StillRemovesAndAudits()
    {
        var alice = UserRoot("alice");
        // Extension folder already gone, but a stale settings entry remains.
        var profileDir = Path.Combine(ChromiumUserData(alice, "chrome"), "Default");
        Directory.CreateDirectory(profileDir);
        File.WriteAllText(Path.Combine(profileDir, "Secure Preferences"),
            """{"extensions":{"settings":{"badext":{"state":1}}}}""");

        var events = Run(Policy(true, Entry("chrome", "badext", "all_devices")), alice, "alice");

        Assert.False(ChromiumSettingsHas(alice, "chrome", "Default", "badext"));
        Assert.Single(events);
    }

    // -------------------------------------------------------------------------
    // Firefox removal — addon entry + XPI
    // -------------------------------------------------------------------------

    [Fact]
    public void Firefox_RemovesAddonEntryAndXpi_KeepsOthers()
    {
        var alice = UserRoot("alice");
        SeedFirefoxExtension(alice, "abc.default", "blk@x");

        var events = Run(Policy(true, Entry("firefox", "blk@x", "all_profiles")), alice, "alice");

        Assert.False(FirefoxAddonPresent(alice, "abc.default", "blk@x"));
        Assert.False(FirefoxXpiExists(alice, "abc.default", "blk@x"));
        Assert.True(FirefoxAddonPresent(alice, "abc.default", "keep@x"));  // untouched
        var evt = Assert.Single(events);
        Assert.Equal("firefox", Detail(evt, "browser"));
    }

    // -------------------------------------------------------------------------
    // Scope semantics — multi-user / multi-profile
    // -------------------------------------------------------------------------

    private (string alice, string bob) TwoUsersTwoProfiles(string id)
    {
        var alice = UserRoot("alice");
        var bob = UserRoot("bob");
        SeedChromiumExtension(alice, "chrome", "Default", id);
        SeedChromiumExtension(alice, "chrome", "Profile 1", id);
        SeedChromiumExtension(bob, "chrome", "Default", id);
        return (alice, bob);
    }

    [Fact]
    public void Scope_OneProfile_RemovesOnlyThatProfile()
    {
        var (alice, _) = TwoUsersTwoProfiles("badext");

        var events = Run(
            Policy(true, Entry("chrome", "badext", "one_profile", user: "alice", profile: "Default")),
            alice, "alice");

        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "badext"));   // removed
        Assert.True(ChromiumExtensionDirExists(alice, "chrome", "Profile 1", "badext"));  // untouched
        var evt = Assert.Single(events);
        Assert.Equal("Default", DetailProfile(evt));
    }

    [Fact]
    public void Scope_OneUser_RemovesAllProfilesForThatUserOnly()
    {
        var (alice, bob) = TwoUsersTwoProfiles("badext");

        var directive = Policy(true, Entry("chrome", "badext", "one_user", user: "alice"));
        var aliceEvents = Run(directive, alice, "alice");
        var bobEvents = Run(directive, bob, "bob");   // bob not in scope

        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "badext"));
        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Profile 1", "badext"));
        Assert.True(ChromiumExtensionDirExists(bob, "chrome", "Default", "badext"));  // bob untouched
        Assert.Equal(2, aliceEvents.Count);   // Default + Profile 1
        Assert.Empty(bobEvents);
    }

    [Fact]
    public void Scope_AllProfiles_RemovesAcrossEveryUserAndProfile()
    {
        var (alice, bob) = TwoUsersTwoProfiles("badext");

        var directive = Policy(true, Entry("chrome", "badext", "all_profiles"));
        var aliceEvents = Run(directive, alice, "alice");
        var bobEvents = Run(directive, bob, "bob");

        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "badext"));
        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Profile 1", "badext"));
        Assert.False(ChromiumExtensionDirExists(bob, "chrome", "Default", "badext"));
        Assert.Equal(2, aliceEvents.Count);
        Assert.Single(bobEvents);
    }

    [Fact]
    public void Scope_AllDevices_ActsDeviceWide_AuditedAsAllDevices()
    {
        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "badext");

        var events = Run(Policy(true, Entry("chrome", "badext", "all_devices")), alice, "alice");

        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "badext"));
        Assert.Equal("all_devices", DetailScope(Assert.Single(events)));
    }

    [Fact]
    public void UserInScope_TargetedScopes_MatchUserCaseInsensitively()
    {
        var d = ExtensionRemovalLogic.NormalizeDirectives(
            Policy(true, Entry("chrome", "x", "one_user", user: "MACHINE\\Alice")))[0];
        Assert.True(ExtensionRemovalLogic.UserInScope(d, "machine\\alice"));
        Assert.False(ExtensionRemovalLogic.UserInScope(d, "MACHINE\\bob"));
    }

    // -------------------------------------------------------------------------
    // Dry-run, idempotency, audit shape
    // -------------------------------------------------------------------------

    [Fact]
    public void DryRun_DeletesNothingButStillEmitsEvents()
    {
        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "badext");

        var events = Run(Policy(true, Entry("chrome", "badext", "all_devices")), alice, "alice", dryRun: true);

        Assert.True(ChromiumExtensionDirExists(alice, "chrome", "Default", "badext"));  // still there
        Assert.True(ChromiumSettingsHas(alice, "chrome", "Default", "badext"));
        var evt = Assert.Single(events);
        Assert.True(DetailDryRun(evt));
    }

    [Fact]
    public void Idempotent_SecondRunRemovesNothing_NoEvents()
    {
        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "badext");
        var directive = Policy(true, Entry("chrome", "badext", "all_devices"));

        Assert.Single(Run(directive, alice, "alice"));   // first run removes + audits
        Assert.Empty(Run(directive, alice, "alice"));    // nothing left → no event
    }

    [Fact]
    public void AuditEvent_HasFullPat829DetailsShape()
    {
        var alice = UserRoot("alice");
        SeedFirefoxExtension(alice, "abc.default", "blk@x");

        var evt = Assert.Single(Run(
            Policy(true, Entry("firefox", "blk@x", "one_profile", user: "alice", profile: "abc.default")),
            alice, "alice"));

        Assert.Equal(EnforcementAuditEventTypes.ExtensionRemoved, evt.EventType);
        Assert.Equal("blk@x", evt.Subject);
        Assert.Equal("2026-07-11T00:00:00Z", evt.OccurredAt);

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(evt.Details));
        var root = doc.RootElement;
        Assert.Equal("firefox", root.GetProperty("browser").GetString());
        Assert.Equal("abc.default", root.GetProperty("profile").GetString());
        Assert.Equal("alice", root.GetProperty("user_account").GetString());
        Assert.Equal("DEVICE-1", root.GetProperty("device_id").GetString());
        Assert.Equal("one_profile", root.GetProperty("scope").GetString());
        Assert.False(root.GetProperty("dry_run").GetBoolean());
    }

    [Fact]
    public void ExtensionRemovals_DeserializeFromWireJson()
    {
        const string json = """
        {"enabled":true,"extension_removals":[
           {"browser":"chrome","extension_id":"aaaa","scope":"one_profile",
            "user_account":"MACHINE\\alice","profile":"Default"},
           {"browser":"firefox","extension_id":"blk@x","scope":"all_devices"}]}
        """;
        var policy = JsonSerializer.Deserialize<AppControlPolicy>(json)!;
        Assert.Equal(2, policy.ExtensionRemovals.Count);
        Assert.Equal("one_profile", policy.ExtensionRemovals[0].Scope);
        Assert.Equal("MACHINE\\alice", policy.ExtensionRemovals[0].UserAccount);
        Assert.Equal("Default", policy.ExtensionRemovals[0].Profile);
        Assert.Null(policy.ExtensionRemovals[1].UserAccount);
    }

    // -------------------------------------------------------------------------
    // PAT-1329 Defect B — belt-and-braces containment + reparse-point defence
    // -------------------------------------------------------------------------

    /// <summary>
    /// Bypasses NormalizeDirectives on purpose — the internal
    /// ExtensionRemovalDirective record is visible to this test assembly via
    /// InternalsVisibleTo, so this constructs a directive that Defect A would
    /// never let through, to prove the second, independent gate (GuardTarget's
    /// containment check) also refuses it. Uses '/' rather than '\' so the
    /// traversal actually escapes on macOS CI too — a Windows-native '\'
    /// traversal string is not interpreted as a separator by Unix's Path
    /// class, so it wouldn't exercise this check when this suite runs here.
    /// </summary>
    [Fact]
    public void ContainmentRefusal_EmitsAuditEvent_AndDoesNotAbortRun()
    {
        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "goodext");

        var escaping = new ExtensionRemovalDirective
        {
            Browser = "chrome",
            ExtensionId = "../../../escaped",
            Scope = ExtensionRemovalLogic.Scopes.AllDevices,
        };
        var benign = new ExtensionRemovalDirective
        {
            Browser = "chrome",
            ExtensionId = "goodext",
            Scope = ExtensionRemovalLogic.Scopes.AllDevices,
        };

        var events = ExtensionRemovalLogic.RemoveForUser(
            alice, "alice", new[] { escaping, benign }, "DEVICE-1", dryRun: false, "2026-07-11T00:00:00Z");

        // The escaping directive is refused (visible), but the benign one in
        // the same run still completed — a refusal must not abort the run.
        Assert.False(ChromiumExtensionDirExists(alice, "chrome", "Default", "goodext"));
        var refusal = Assert.Single(events, e => e.EventType == EnforcementAuditEventTypes.ExtensionRemovalRefused);
        Assert.Equal("../../../escaped", refusal.Subject);
    }

    /// <summary>
    /// PAT-1329, Windows-only: NTFS junctions are a real Windows construct
    /// (mklink /J) requiring no elevated privilege to create, unlike a
    /// symlink — the exact attack Defect B exists to close. No-ops on
    /// non-Windows so this suite still compiles and passes on macOS CI; only
    /// a real Windows run (see AGENTS.md / the PAT-1329 verification notes)
    /// exercises the assertions below.
    /// </summary>
    [Fact]
    public void RealJunctionAtExtensionDir_IsRefused_AndLeftIntact()
    {
        if (!OperatingSystem.IsWindows()) return;

        var alice = UserRoot("alice");
        SeedChromiumExtension(alice, "chrome", "Default", "badext");
        var extDir = Path.Combine(ChromiumUserData(alice, "chrome"), "Default", "Extensions", "badext");

        var junctionTarget = Path.Combine(_work, "junction-target");
        Directory.CreateDirectory(junctionTarget);
        File.WriteAllText(Path.Combine(junctionTarget, "canary.txt"), "should never be touched");

        // Simulate the pre-plant: an unprivileged local user replaces the
        // extension directory with a junction before the SYSTEM pass ever runs.
        Directory.Delete(extDir, recursive: true);
        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe",
            $"/c mklink /J \"{extDir}\" \"{junctionTarget}\"")
        { UseShellExecute = false, CreateNoWindow = true };
        using (var p = System.Diagnostics.Process.Start(psi)!) p.WaitForExit();
        Assert.True((File.GetAttributes(extDir) & FileAttributes.ReparsePoint) != 0); // sanity: junction really created

        var events = Run(Policy(true, Entry("chrome", "badext", "all_devices")), alice, "alice");

        // Refused: the junction itself and whatever it points at both survive.
        Assert.True((File.GetAttributes(extDir) & FileAttributes.ReparsePoint) != 0);
        Assert.True(File.Exists(Path.Combine(junctionTarget, "canary.txt")));
        var refusal = Assert.Single(events, e => e.EventType == EnforcementAuditEventTypes.ExtensionRemovalRefused);
        Assert.Equal("badext", refusal.Subject);
    }

    // -------------------------------------------------------------------------
    // Detail extractors
    // -------------------------------------------------------------------------

    private static string DetailProfile(EnforcementAuditEvent evt) => Detail(evt, "profile");
    private static string DetailScope(EnforcementAuditEvent evt) => Detail(evt, "scope");
    private static bool DetailDryRun(EnforcementAuditEvent evt)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(evt.Details));
        return doc.RootElement.GetProperty("dry_run").GetBoolean();
    }

    private static string Detail(EnforcementAuditEvent evt, string prop)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(evt.Details));
        return doc.RootElement.GetProperty(prop).GetString()!;
    }
}
