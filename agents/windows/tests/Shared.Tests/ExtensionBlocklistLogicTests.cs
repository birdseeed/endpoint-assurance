using System.Text.Json;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-828: platform-neutral tests for <see cref="ExtensionBlocklistLogic"/> — the
/// grouping/reconcile/audit decision logic behind Chrome/Edge/Firefox managed-policy
/// blocklist enforcement. No registry dependency, so these run on macOS CI; the
/// Windows-only registry glue lives in BrowserExtensionBlocklistEnforcer (Service).
///
/// Because the policy is device-global (HKLM, one push per browser covers every
/// user + profile), these reconcile-level tests are the multi-user/multi-profile
/// coverage: there is no per-user/per-profile branching to diverge.
/// </summary>
public sealed class ExtensionBlocklistLogicTests
{
    private static AppControlPolicy Policy(bool enabled, params (string browser, string id)[] entries) =>
        new()
        {
            Enabled = enabled,
            ExtensionBlocklist = entries
                .Select(e => new ExtensionBlocklistEntry { Browser = e.browser, ExtensionId = e.id })
                .ToList(),
        };

    private static ExtensionBlocklistState State(params (string browser, string[] ids)[] browsers)
    {
        var s = new ExtensionBlocklistState();
        foreach (var (browser, ids) in browsers)
            s.Browsers[browser] = ids.ToList();
        return s;
    }

    // -------------------------------------------------------------------------
    // NormalizeDesired
    // -------------------------------------------------------------------------

    [Fact]
    public void NormalizeDesired_Disabled_ReturnsEmpty()
    {
        var d = ExtensionBlocklistLogic.NormalizeDesired(Policy(false, ("chrome", "aaaa")));
        Assert.Empty(d);
    }

    [Fact]
    public void NormalizeDesired_EnabledButEmptyList_ReturnsEmpty()
    {
        Assert.Empty(ExtensionBlocklistLogic.NormalizeDesired(Policy(true)));
    }

    [Fact]
    public void NormalizeDesired_GroupsDedupesSortsAndLowercasesBrowser()
    {
        var d = ExtensionBlocklistLogic.NormalizeDesired(Policy(true,
            ("Chrome", "bbbb"), ("chrome", "aaaa"), ("chrome", "aaaa"), ("EDGE", "cccc")));

        Assert.Equal(new[] { "aaaa", "bbbb" }, d["chrome"]);   // sorted + deduped
        Assert.Equal(new[] { "cccc" }, d["edge"]);
    }

    [Fact]
    public void NormalizeDesired_SkipsBlankBrowserOrId()
    {
        var d = ExtensionBlocklistLogic.NormalizeDesired(Policy(true,
            ("", "aaaa"), ("chrome", "  "), ("chrome", " dddd ")));
        Assert.False(d.ContainsKey(""));
        Assert.Equal(new[] { "dddd" }, d["chrome"]);   // trimmed
    }

    // -------------------------------------------------------------------------
    // Reconcile
    // -------------------------------------------------------------------------

    [Fact]
    public void Reconcile_FreshSet_AddsAllAndRecordsState()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true,
            ("chrome", "aaaa"), ("chrome", "bbbb"), ("firefox", "blk@x")));
        var r = ExtensionBlocklistLogic.Reconcile(desired, new ExtensionBlocklistState());

        var chrome = Assert.Single(r.Changes, c => c.Browser == "chrome");
        Assert.Equal(new[] { "aaaa", "bbbb" }, chrome.ToAdd);
        Assert.Empty(chrome.ToRemove);
        Assert.False(chrome.IsClear);
        Assert.Equal(new[] { "aaaa", "bbbb" }, r.NextState.Browsers["chrome"]);
        Assert.Contains(r.Changes, c => c.Browser == "firefox");
        Assert.Empty(r.UnsupportedBrowsers);
    }

    [Fact]
    public void Reconcile_Shrink_RemovesDroppedIdsOnly()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true, ("chrome", "aaaa")));
        var r = ExtensionBlocklistLogic.Reconcile(desired, State(("chrome", new[] { "aaaa", "bbbb" })));

        var chrome = Assert.Single(r.Changes);
        Assert.Empty(chrome.ToAdd);
        Assert.Equal(new[] { "bbbb" }, chrome.ToRemove);
        Assert.False(chrome.IsClear);
        Assert.Equal(new[] { "aaaa" }, r.NextState.Browsers["chrome"]);
    }

    [Fact]
    public void Reconcile_BrowserDroppedFromConfig_ClearsAndForgets()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true, ("chrome", "aaaa")));
        var r = ExtensionBlocklistLogic.Reconcile(desired,
            State(("chrome", new[] { "aaaa" }), ("edge", new[] { "cccc" })));

        var edge = Assert.Single(r.Changes, c => c.Browser == "edge");
        Assert.True(edge.IsClear);
        Assert.Equal(new[] { "cccc" }, edge.ToRemove);
        Assert.Empty(edge.DesiredIds);
        Assert.DoesNotContain("edge", r.NextState.Browsers.Keys);      // forgotten
        Assert.Equal(new[] { "aaaa" }, r.NextState.Browsers["chrome"]); // untouched
        Assert.DoesNotContain(r.Changes, c => c.Browser == "chrome");   // chrome unchanged
    }

    [Fact]
    public void Reconcile_DisabledPolicy_WithdrawsAllManagedBlocks()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(false, ("chrome", "aaaa")));
        var r = ExtensionBlocklistLogic.Reconcile(desired, State(("chrome", new[] { "aaaa" })));

        var chrome = Assert.Single(r.Changes);
        Assert.True(chrome.IsClear);
        Assert.Equal(new[] { "aaaa" }, chrome.ToRemove);
        Assert.Empty(r.NextState.Browsers);
    }

    [Fact]
    public void Reconcile_NoChange_ProducesNoChanges()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true, ("chrome", "aaaa")));
        var r = ExtensionBlocklistLogic.Reconcile(desired, State(("chrome", new[] { "aaaa" })));

        Assert.Empty(r.Changes);
        Assert.Equal(new[] { "aaaa" }, r.NextState.Browsers["chrome"]);  // carried forward
    }

    [Fact]
    public void Reconcile_UnsupportedBrowser_IsReportedNotEnforced()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true, ("brave", "aaaa")));
        var r = ExtensionBlocklistLogic.Reconcile(desired, new ExtensionBlocklistState());

        Assert.Empty(r.Changes);
        Assert.DoesNotContain("brave", r.NextState.Browsers.Keys);
        Assert.Equal(new[] { "brave" }, r.UnsupportedBrowsers);
    }

    [Fact]
    public void Reconcile_RegistryPathsAndMechanismsAreCorrect()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true,
            ("chrome", "a"), ("edge", "b"), ("firefox", "c@x")));
        var r = ExtensionBlocklistLogic.Reconcile(desired, new ExtensionBlocklistState());

        var chrome = r.Changes.Single(c => c.Browser == "chrome");
        var edge = r.Changes.Single(c => c.Browser == "edge");
        var firefox = r.Changes.Single(c => c.Browser == "firefox");

        Assert.Equal(@"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist", chrome.AuditPath);
        Assert.Equal(@"HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist", edge.AuditPath);
        Assert.Equal(@"HKLM\SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings", firefox.AuditPath);
        Assert.Equal("chromium_registry_blocklist", chrome.Mechanism);
        Assert.Equal("firefox_registry_extensionsettings", firefox.Mechanism);
    }

    // -------------------------------------------------------------------------
    // BuildEvent
    // -------------------------------------------------------------------------

    [Fact]
    public void BuildEvent_SetAction_HasExpectedShape()
    {
        var desired = ExtensionBlocklistLogic.NormalizeDesired(Policy(true, ("chrome", "aaaa"), ("chrome", "bbbb")));
        var change = ExtensionBlocklistLogic.Reconcile(desired, new ExtensionBlocklistState()).Changes.Single();

        var evt = ExtensionBlocklistLogic.BuildEvent(change, "2026-07-11T00:00:00Z", dryRun: false);
        Assert.Equal(EnforcementAuditEventTypes.ExtensionBlocklistPushed, evt.EventType);
        Assert.Equal("chrome", evt.Subject);
        Assert.Equal("2026-07-11T00:00:00Z", evt.OccurredAt);

        // Details serialize with the wire field names the endpoint expects.
        var json = JsonSerializer.Serialize(evt.Details);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("chrome", root.GetProperty("browser").GetString());
        Assert.Equal("set", root.GetProperty("action").GetString());
        Assert.Equal(2, root.GetProperty("blocked_count").GetInt32());
        Assert.False(root.GetProperty("dry_run").GetBoolean());
        Assert.Equal(2, root.GetProperty("extension_ids").GetArrayLength());
    }

    [Fact]
    public void BuildEvent_ClearAction_MarkedCleared()
    {
        var change = ExtensionBlocklistLogic
            .Reconcile(new Dictionary<string, IReadOnlyList<string>>(), State(("edge", new[] { "cccc" })))
            .Changes.Single();

        var evt = ExtensionBlocklistLogic.BuildEvent(change, "t", dryRun: true);
        var json = JsonSerializer.Serialize(evt.Details);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("cleared", doc.RootElement.GetProperty("action").GetString());
        Assert.Equal(0, doc.RootElement.GetProperty("blocked_count").GetInt32());
        Assert.True(doc.RootElement.GetProperty("dry_run").GetBoolean());
    }

    // -------------------------------------------------------------------------
    // State round-trip
    // -------------------------------------------------------------------------

    [Fact]
    public void State_RoundTrips()
    {
        var s = State(("chrome", new[] { "aaaa", "bbbb" }), ("firefox", new[] { "c@x" }));
        var parsed = ExtensionBlocklistState.Parse(s.Serialize());
        Assert.Equal(new[] { "aaaa", "bbbb" }, parsed.Browsers["chrome"]);
        Assert.Equal(new[] { "c@x" }, parsed.Browsers["firefox"]);
    }

    [Fact]
    public void State_ParseGarbage_ReturnsEmpty()
    {
        Assert.Empty(ExtensionBlocklistState.Parse("not json{{").Browsers);
        Assert.Empty(ExtensionBlocklistState.Parse("").Browsers);
    }

    // -------------------------------------------------------------------------
    // Wire binding: extension_blocklist parses from the agent-config app_control block
    // -------------------------------------------------------------------------

    [Fact]
    public void ExtensionBlocklist_DeserializesFromWireJson()
    {
        const string json = """
        {"enabled":true,"extension_blocklist":[
           {"browser":"chrome","extension_id":"aaaa"},
           {"browser":"firefox","extension_id":"blk@x"}]}
        """;
        var policy = JsonSerializer.Deserialize<AppControlPolicy>(json)!;
        Assert.True(policy.Enabled);
        Assert.Equal(2, policy.ExtensionBlocklist.Count);
        Assert.Equal("chrome", policy.ExtensionBlocklist[0].Browser);
        Assert.Equal("blk@x", policy.ExtensionBlocklist[1].ExtensionId);
    }

    [Fact]
    public void ExtensionBlocklist_DefaultsToEmpty_WhenAbsent()
    {
        var policy = JsonSerializer.Deserialize<AppControlPolicy>("""{"enabled":true}""")!;
        Assert.Empty(policy.ExtensionBlocklist);
        Assert.Empty(ExtensionBlocklistLogic.NormalizeDesired(policy));
    }
}
