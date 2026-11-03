using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-858: BrowserExtensionBlocklistEnforcer.Enforce's actuationAllowed parameter.
///
/// Non-author security review on PR #296 found that gating the ENTIRE Enforce() call
/// on Tier (like AdminEnforcer/BrowserExtensionRemover) leaves stale blocklist policy
/// in place once a tenant drops below the actuating tier (formerly "patch", now
/// "managed" — PAT-1599 collapsed the vocabulary): Enforce() also reconciles
/// (clears) previously-pushed policy when the desired set shrinks, and that
/// reconciliation never runs if the call itself is skipped. actuationAllowed=false
/// instead forces the desired set to empty — still running the full reconcile+apply,
/// so previously-pushed policy is torn down rather than left in place.
///
/// Forces dry-run mode for every test via TestEnforcer.IsDryRun's override, so
/// Enforce never calls the real registry-writing Apply() (not virtual/overridable —
/// this class has no seam for that). PAT-1110 verification (2026-08): this used to
/// mutate the process-wide PATCHED_DRY_RUN environment variable via a WithDryRun
/// helper; this class's own doc comment had explicitly accepted "the same small
/// cross-class race this repo already tolerates" against AdminEnforcerTests.cs's
/// identical pattern as a known, deliberate trade-off. PAT-1110's additional test
/// classes changed xUnit's thread-pool interleaving enough to turn that "small,
/// tolerated" race into reproducible AdminEnforcerTests failures on unrelated
/// assertions, so both classes were moved off the shared environment variable
/// entirely (AdminEnforcer.IsDryRun() / BrowserExtensionBlocklistEnforcer.IsDryRun()
/// are now virtual, matching the existing LoadState/SaveState/StateFilePath seam
/// this class already used) rather than re-tolerated.
/// </summary>
public sealed class BrowserExtensionBlocklistEnforcerTests
{
    private sealed class TestEnforcer(ExtensionBlocklistState initialState)
        : BrowserExtensionBlocklistEnforcer(NullLogger<BrowserExtensionBlocklistEnforcer>.Instance)
    {
        internal override ExtensionBlocklistState LoadState() => initialState;
        internal override void SaveState(ExtensionBlocklistState state) { /* dry-run never calls this */ }

        // Every test in this file needs dry-run behaviour (see class doc comment),
        // so this defaults to true — unlike AdminEnforcerTests' FakeAdminEnforcer,
        // where most tests want real (non-dry-run) removal and only one test opts in.
        internal override bool IsDryRun() => true;
    }

    [Fact]
    public void Enforce_ActuationDisallowed_ReconcilesToEmpty_EvenWhenPolicyWantsNewEntries()
    {
        var previous = new ExtensionBlocklistState();
        previous.Browsers["chrome"] = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"];
        var enforcer = new TestEnforcer(previous);

        var policy = new AppControlPolicy
        {
            Enabled = true,
            ExtensionBlocklist =
            [
                new ExtensionBlocklistEntry { Browser = "chrome", ExtensionId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
            ],
        };

        var events = enforcer.Enforce(policy, actuationAllowed: false);

        Assert.Single(events);
        var json = JsonSerializer.Serialize(events[0].Details);

        // Rolled back to empty ("cleared"), not set to the policy's desired id —
        // proves the Tier gate forces reconcile-to-empty rather than adding the new
        // entry the policy asked for.
        Assert.Contains("\"action\":\"cleared\"", json);
        Assert.DoesNotContain("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", json);
    }

    [Fact]
    public void Enforce_ActuationDisallowedAndNothingPreviouslyManaged_NoChangesNoEvents()
    {
        var enforcer = new TestEnforcer(new ExtensionBlocklistState());
        var policy = new AppControlPolicy
        {
            Enabled = true,
            ExtensionBlocklist =
            [
                new ExtensionBlocklistEntry { Browser = "chrome", ExtensionId = "cccccccccccccccccccccccccccccccc" },
            ],
        };

        var events = enforcer.Enforce(policy, actuationAllowed: false);
        Assert.Empty(events); // nothing to roll back, nothing new applied
    }

    [Fact]
    public void Enforce_ActuationAllowed_DefaultParameter_AppliesDesiredPolicy()
    {
        var enforcer = new TestEnforcer(new ExtensionBlocklistState());
        var policy = new AppControlPolicy
        {
            Enabled = true,
            ExtensionBlocklist =
            [
                new ExtensionBlocklistEntry { Browser = "chrome", ExtensionId = "dddddddddddddddddddddddddddddddd" },
            ],
        };

        // actuationAllowed defaults to true — existing callers/behavior unaffected.
        var events = enforcer.Enforce(policy);

        Assert.Single(events);
        var json = JsonSerializer.Serialize(events[0].Details);
        Assert.Contains("\"action\":\"set\"", json);
        Assert.Contains("dddddddddddddddddddddddddddddddd", json);
    }
}
