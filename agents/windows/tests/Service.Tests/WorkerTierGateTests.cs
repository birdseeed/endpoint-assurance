using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-858 / PAT-1263: local Tier gate for BrowserExtensionBlocklistEnforcer's
/// actuationAllowed flag, the Deploy-downgrade gate, the uninstall trigger, and the
/// catalogue install/removal engines — defence-in-depth so the client never
/// actuates config enforcement while assurance-only even if the server mis-issues
/// app_control.enabled=true.
///
/// PAT-1599: the signed agent-config's tier vocabulary collapsed from three values
/// (report_deploy/patch/managed) to two (assurance/managed) — "assurance observes,
/// managed acts", one bit, not a ladder. There is no more "patch" rung, so these
/// tests are rewritten rather than patched (the old 3-value cases below no longer
/// describe a value the signed config can emit). ActuatingTierAllows and
/// DestructiveActuatingTierAllows (WorkerDestructiveTierGateTests below) now share
/// the same body — only the exact literal "managed" actuates either gate; both
/// still fail closed on null, empty, unknown and any other string.
///
/// PatchedWorker.RunCycleAsync is a large, DI-heavy private method (17 constructor
/// dependencies) with no existing test harness in this repo, so the gating decision
/// itself is exercised here directly via the extracted, internal
/// PatchedWorker.ActuatingTierAllows predicate (visible to this assembly via
/// Service.csproj's InternalsVisibleTo).
/// </summary>
public sealed class WorkerTierGateTests
{
    [Fact]
    public void ActuatingTierAllows_ManagedTier_ReturnsTrue()
    {
        Assert.True(PatchedWorker.ActuatingTierAllows("managed"));
    }

    [Theory]
    [InlineData("assurance")] // PAT-1599: the new report-only rung — must stay gated.
    [InlineData("report")]
    [InlineData("report_deploy")] // PAT-1599: retired tier value — must stay gated.
    [InlineData("patch")] // PAT-1599: retired tier value — must stay gated.
    [InlineData("app_management")] // never a valid agent-config Tier value (belongs
                                    // to the separate enforcement_tier vocabulary).
    [InlineData("bogus")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("MANAGED")] // case-sensitive on purpose — mirrors the existing
                             // config.Tier == "managed" literal comparisons
                             // elsewhere in Worker.cs (RemovalRunner/InstallRunner
                             // gates).
    public void ActuatingTierAllows_AnyOtherTier_ReturnsFalse(string? tier)
    {
        Assert.False(PatchedWorker.ActuatingTierAllows(tier));
    }
}

/// <summary>
/// PAT-1263: local Tier gate for the two destructive, one-way endpoint-actuating
/// enforcement paths — AdminEnforcer.Enforce (local-admin removal via
/// RemoveFromAdministrators) and BrowserExtensionRemover.Remove (extension-artifact
/// deletion). Both are wired through PatchedWorker.RunTierGatedEnforcementAsync,
/// which gates on DestructiveActuatingTierAllows.
///
/// PAT-1599: under the collapsed 2-value tier vocabulary (assurance/managed),
/// DestructiveActuatingTierAllows and ActuatingTierAllows (WorkerTierGateTests
/// above) are now the same check — there is no longer a "patch" rung sitting
/// between them. Both predicates are retained as distinct names because they still
/// express different intent at their call sites (general actuation vs. the
/// destructive-only paths), but their behaviour is now identical: only "managed"
/// actuates either gate.
///
/// This is the Windows counterpart of macos/patched-upload.sh's ac_tier_gate_check
/// and its PATCHED_ACTUATING_TIER="managed" constant — same tenant tier, same
/// signed agent-config, same decision on both platforms: only "managed" actuates
/// these two paths.
///
/// Exercised directly against the extracted, internal
/// PatchedWorker.DestructiveActuatingTierAllows predicate (InternalsVisibleTo, same
/// rationale as WorkerTierGateTests above — PatchedWorker itself is not
/// constructible in a unit test) rather than by driving the whole worker.
/// </summary>
public sealed class WorkerDestructiveTierGateTests
{
    [Fact]
    public void DestructiveActuatingTierAllows_ManagedTier_ReturnsTrue()
    {
        // Acceptance criterion: at tier 'managed', behaviour is unchanged from today —
        // AdminEnforcer / BrowserExtensionRemover still actuate.
        Assert.True(PatchedWorker.DestructiveActuatingTierAllows("managed"));
    }

    [Theory]
    [InlineData("assurance")] // PAT-1599: the new report-only rung — must refuse.
    [InlineData("report")]
    [InlineData("report_deploy")] // PAT-1599: retired tier value — must refuse.
    [InlineData("patch")] // PAT-1599: retired tier value — must refuse; before this
                           // ticket "patch" was already sub-managed for the
                           // destructive paths (PAT-1263), and it stays refused now
                           // that it is not a valid tier value at all.
    [InlineData("app_management")] // never a valid agent-config Tier value; belongs to
                                    // the separate per-app enforcement_tier vocabulary.
    [InlineData("bogus")]
    [InlineData(null)]   // missing tier: fails closed, never defaults to permissive.
    [InlineData("")]     // empty tier: fails closed.
    [InlineData("  ")]   // whitespace-only tier: fails closed.
    [InlineData("MANAGED")] // case-sensitive on purpose, same convention as the literal
                             // config.Tier comparisons elsewhere in Worker.cs.
    [InlineData("managed ")] // trailing whitespace: not an exact match, fails closed —
                              // mirrors macOS's ac_tier_gate_check, which also requires
                              // an exact string match against PATCHED_ACTUATING_TIER.
    public void DestructiveActuatingTierAllows_AnyOtherTier_ReturnsFalse(string? tier)
    {
        // Acceptance criterion: sub-managed, missing, and malformed tier values all
        // refuse — there is no permissive branch.
        Assert.False(PatchedWorker.DestructiveActuatingTierAllows(tier));
    }
}
