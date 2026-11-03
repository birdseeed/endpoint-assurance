using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-552: Unit tests for AppAllowlistEnforcer.
///
/// Strategy:
///   - AppAllowlistEnforcer.GetInstalledApps() is internal virtual, so
///     FakeAppAllowlistEnforcer overrides it to return a controllable list
///     without touching the Windows registry.
///   - Enforce() returns the audit event list; tests assert on it directly.
/// </summary>
// PAT-1129: AppAllowlistEnforcer still reads PATCHED_DRY_RUN inline rather than
// through an overridable seam, so these tests must not run alongside the one class
// that sets that variable for real. Joining the collection serialises them.
// Give this enforcer the same IsDryRun() seam and this attribute can come off.
[Collection(DryRunEnvCollection.Name)]
public sealed class AppAllowlistEnforcerTests
{
    // -------------------------------------------------------------------------
    // Test double
    // -------------------------------------------------------------------------

    private sealed class FakeAppAllowlistEnforcer : AppAllowlistEnforcer
    {
        private readonly IReadOnlyList<InventoryApp> _apps;

        public FakeAppAllowlistEnforcer(IReadOnlyList<InventoryApp> apps)
            : base(NullLogger<AppAllowlistEnforcer>.Instance, null!)   // scanner unused (overridden)
        {
            _apps = apps;
        }

        internal override IReadOnlyList<InventoryApp> GetInstalledApps() => _apps;
    }

    private static InventoryApp App(string name, string? publisher = null) =>
        new InventoryApp
        {
            Name       = name,
            Version    = "1.0.0",
            Identifier = $"{{{Guid.NewGuid()}}}",
            Publisher  = publisher,
        };

    // -------------------------------------------------------------------------
    // Tests: feature gate
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_WhenDisabled_ReturnsEmpty()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("Slack", "Slack Technologies")]);
        var policy   = new AppControlPolicy { Enabled = false, AppAllowlist = ["Slack"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_WhenAllowlistEmpty_ReturnsEmpty()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("Slack", "Slack Technologies")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = [] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    // -------------------------------------------------------------------------
    // Tests: matching
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_AllowlistedApp_NotReported()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("Google Chrome", "Google LLC")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["Google Chrome"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_AllowlistedByPublisher_NotReported()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("Google Chrome", "Google LLC")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["Google LLC"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_UnlistedApp_ReportedAsAppBlockSkipped()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("SuperGames", "AcmeCorp")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["Google Chrome", "Slack"] };

        var events = enforcer.Enforce(policy);

        var ev = Assert.Single(events);
        Assert.Equal(EnforcementAuditEventTypes.AppBlockSkipped, ev.EventType);
        Assert.Equal("SuperGames", ev.Subject);
    }

    [Fact]
    public void Enforce_MixedApps_OnlyUnlistedReported()
    {
        var apps = new List<InventoryApp>
        {
            App("Slack", "Slack Technologies"),
            App("SuperGames", "AcmeCorp"),
            App("Zoom", "Zoom Video Communications"),
        };
        var policy = new AppControlPolicy
        {
            Enabled      = true,
            AppAllowlist = ["Slack", "Zoom"],
        };
        var enforcer = new FakeAppAllowlistEnforcer(apps);

        var events = enforcer.Enforce(policy);

        var ev = Assert.Single(events);
        Assert.Equal("SuperGames", ev.Subject);
        Assert.Equal(EnforcementAuditEventTypes.AppBlockSkipped, ev.EventType);
    }

    [Fact]
    public void Enforce_CaseInsensitiveMatch_AllowedCorrectly()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("Google Chrome", "Google LLC")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["google chrome"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_PartialNameMatch_AllowedCorrectly()
    {
        // "Chrome" as allowlist entry contains-matches "Google Chrome".
        var enforcer = new FakeAppAllowlistEnforcer([App("Google Chrome", "Google LLC")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["Chrome"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_AllAppsUnlisted_AllReported()
    {
        var apps     = new List<InventoryApp> { App("App1"), App("App2"), App("App3") };
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["AllowedApp"] };
        var enforcer = new FakeAppAllowlistEnforcer(apps);

        var events = enforcer.Enforce(policy);

        Assert.Equal(3, events.Count);
        Assert.All(events, e => Assert.Equal(EnforcementAuditEventTypes.AppBlockSkipped, e.EventType));
    }

    [Fact]
    public void Enforce_EmptyInstalledList_ReturnsEmpty()
    {
        var enforcer = new FakeAppAllowlistEnforcer([]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["Slack"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_EventHasCorrectOccurredAtFormat()
    {
        var enforcer = new FakeAppAllowlistEnforcer([App("Rogue", "BadCorp")]);
        var policy   = new AppControlPolicy { Enabled = true, AppAllowlist = ["Slack"] };

        var events = enforcer.Enforce(policy);

        var ev = Assert.Single(events);
        // occurred_at must be parseable as DateTimeOffset.
        Assert.True(DateTimeOffset.TryParse(ev.OccurredAt, out _),
            $"occurred_at '{ev.OccurredAt}' is not a valid DateTimeOffset");
    }
}
