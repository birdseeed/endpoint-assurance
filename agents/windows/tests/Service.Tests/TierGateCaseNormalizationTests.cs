using System.Text.Json;
using Patched.Service;
using Patched.Shared.Config;
using Patched.Shared.Posture;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1418. The daemon's own actuating-tier gates (PatchedWorker.ActuatingTierAllows
/// / DestructiveActuatingTierAllows, Worker.cs — both ordinal, since C# pattern
/// matching and == on string constants are ordinal) must agree with the UI gating
/// seam (PostureGating.GrantsPatchDeploy, PostureModels.cs — case-insensitive) for
/// every tier string the server can plausibly emit, INCLUDING non-canonical case.
/// Before PAT-1418 they diverged at tier "MANAGED": PostureGating (case-insensitive)
/// told Self Service to offer Install / Get / Uninstall, while PatchedWorker (ordinal)
/// refused to actuate the resulting trigger — a dead button, which
/// <see cref="PostureGating"/>'s own doc comment says the UI must never show.
///
/// PAT-1599 rewrite: the tier vocabulary collapsed from three values
/// (report_deploy/patch/managed) to two (assurance/managed) — "assurance observes,
/// managed acts", one bit, not a ladder. Both PatchedWorker's gates and
/// PostureGating's gates were collapsed together in the same change specifically so
/// this file's core invariant — daemon and UI seam always agree — keeps holding.
/// Before that collapse, leaving PatchedWorker gated to "managed" only while
/// PostureGating still granted on "patch" would have reintroduced exactly the dead
/// button this class exists to catch, just flipped (UI offers, daemon refuses). The
/// vocabulary table below is rewritten, not patched, because "patch" is no longer a
/// value the signed config can canonically carry — it is now one of several retired
/// strings that must keep refusing on both sides alongside "assurance", the new
/// canonical observe-only value.
///
/// The fix canonicalizes the tier string once, at the two points it enters the
/// process — AgentConfig.Deserialize (AgentConfig.cs) and Posture.Deserialize
/// (PostureModels.cs) — so every downstream comparison, including the ordinal daemon
/// predicates, agrees without needing its own case-insensitive guard. These tests
/// deliberately go through the real Deserialize entry points (not the predicates
/// called directly with pre-lowercased strings) so they actually exercise that
/// boundary: a test that only called the predicates with "managed" would pass
/// whether or not the boundary normalization exists, and would therefore prove
/// nothing about this ticket.
/// </summary>
public sealed class TierGateCaseNormalizationTests
{
    /// <summary>
    /// Shared vocabulary table driving both sides of the comparison below, so the
    /// daemon-side and UI-side expectations cannot independently drift out of sync
    /// with each other the way the two live gates themselves did.
    /// </summary>
    public static IEnumerable<object?[]> TierVocabulary()
    {
        // Canonical values, already lowercase.
        yield return new object?[] { "assurance" };
        yield return new object?[] { "managed" };
        // Case variants — the PAT-1418 defect. A non-canonical-case server payload
        // must not make the UI seam and the daemon gate disagree.
        yield return new object?[] { "MANAGED" };
        yield return new object?[] { "Managed" };
        yield return new object?[] { "ASSURANCE" };
        yield return new object?[] { "Assurance" };
        // Retired values (PAT-1599) — must keep refusing on both sides, same as any
        // other unrecognised string.
        yield return new object?[] { "report" };
        yield return new object?[] { "report_deploy" };
        yield return new object?[] { "patch" };
        yield return new object?[] { "PATCH" };
        yield return new object?[] { "app_management" };
        // Edge values that must fail closed on both sides.
        yield return new object?[] { "" };
        yield return new object?[] { "   " };
        yield return new object?[] { null };
        yield return new object?[] { "bogus" };
    }

    [Theory]
    [MemberData(nameof(TierVocabulary))]
    public void DaemonGateAndUiSeam_AgreeAfterRealDeserialization_AgentConfigTier(string? rawTier)
    {
        AgentConfig? config = AgentConfig.Deserialize(BuildAgentConfigJson(rawTier));
        Assert.NotNull(config);

        bool daemonActuates = PatchedWorker.ActuatingTierAllows(config!.Tier);
        bool uiActuates     = PostureGating.GrantsPatchDeploy(config.Tier);

        Assert.Equal(uiActuates, daemonActuates);
    }

    [Theory]
    [MemberData(nameof(TierVocabulary))]
    public void DaemonGateAndUiSeam_AgreeAfterRealDeserialization_PostureTier(string? rawTier)
    {
        Posture? posture = Posture.Deserialize(BuildPostureJson(rawTier));
        Assert.NotNull(posture);

        bool daemonActuates = PatchedWorker.ActuatingTierAllows(posture!.Tier);
        bool uiActuates     = PostureGating.GrantsPatchDeploy(posture.Tier);

        Assert.Equal(uiActuates, daemonActuates);
    }

    /// <summary>
    /// PAT-1418: this is the exact case that was broken before the fix — deserializing
    /// a non-canonical-case "MANAGED" tier from the wire must leave the daemon gate and
    /// the UI seam agreeing (both true), never the dead-button split (UI true, daemon
    /// false). Still the sole actuating value after PAT-1599's collapse.
    /// </summary>
    [Fact]
    public void UppercaseManagedTier_ActuatesOnBothSidesAfterDeserialization()
    {
        var config  = AgentConfig.Deserialize(BuildAgentConfigJson("MANAGED"));
        var posture = Posture.Deserialize(BuildPostureJson("MANAGED"));
        Assert.NotNull(config);
        Assert.NotNull(posture);

        Assert.True(PatchedWorker.ActuatingTierAllows(config!.Tier));
        Assert.True(PostureGating.GrantsPatchDeploy(posture!.Tier));
    }

    /// <summary>
    /// The missing-tier path (no "tier" key at all) must keep falling back to the
    /// "assurance" default (PAT-1599; formerly "report_deploy") — PAT-1418's
    /// normalization must not change that fallback, only fold the case of a present
    /// value.
    /// </summary>
    [Fact]
    public void MissingTier_KeepsAssuranceDefault_OnBothSides()
    {
        var config  = AgentConfig.Deserialize("{}");
        var posture = Posture.Deserialize("""{"device":{"id":"d","os":"Windows"}}""");
        Assert.NotNull(config);
        Assert.NotNull(posture);

        Assert.Equal("assurance", config!.Tier);
        Assert.Equal("assurance", posture!.Tier);
        Assert.False(PatchedWorker.ActuatingTierAllows(config.Tier));
        Assert.False(PostureGating.GrantsPatchDeploy(posture.Tier));
    }

    /// <summary>
    /// PAT-1263's destructive gate (AdminEnforcer / BrowserExtensionRemover) must stay
    /// strictly "managed"-only across case variants once the boundary normalizes the
    /// wire value — "assurance" and every retired value (any case) must still refuse,
    /// only "managed" (any case) actuates. Under PAT-1599's collapse this is now the
    /// same check as ActuatingTierAllows above, but the destructive gate is exercised
    /// separately so a future re-divergence between the two is still caught here.
    /// </summary>
    [Theory]
    [InlineData("managed", true)]
    [InlineData("MANAGED", true)]
    [InlineData("Managed", true)]
    [InlineData("mAnAgEd", true)]
    [InlineData("assurance", false)]
    [InlineData("ASSURANCE", false)]
    [InlineData("patch", false)]
    [InlineData("PATCH", false)]
    [InlineData("Patch", false)]
    [InlineData("report", false)]
    [InlineData("report_deploy", false)]
    [InlineData("app_management", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void DestructiveActuatingTierAllows_StaysManagedOnlyAfterRealDeserialization(string? rawTier, bool expected)
    {
        var config = AgentConfig.Deserialize(BuildAgentConfigJson(rawTier));
        Assert.NotNull(config);

        Assert.Equal(expected, PatchedWorker.DestructiveActuatingTierAllows(config!.Tier));
    }

    private static string BuildAgentConfigJson(string? tier) =>
        JsonSerializer.Serialize(new Dictionary<string, string?> { ["tier"] = tier });

    private static string BuildPostureJson(string? tier)
    {
        // Posture requires no fields beyond what its record defaults already supply;
        // "device"/"compliance"/"evidence" all have working defaults, so a minimal
        // payload carrying only "tier" deserializes cleanly and exercises the real
        // Posture.Deserialize boundary rather than constructing the record directly.
        var payload = new Dictionary<string, object?>
        {
            ["tier"] = tier,
            ["device"] = new Dictionary<string, string?> { ["id"] = "test-device", ["os"] = "Windows" },
        };
        return JsonSerializer.Serialize(payload);
    }
}
