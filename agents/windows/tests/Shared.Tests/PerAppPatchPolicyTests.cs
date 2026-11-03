using Patched.Shared.Config;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-381: the Windows per-app update-policy resolver and its tolerant wire
/// reader. Mirrors the macOS patched-update.sh policy_allows / load_policy
/// semantics: override wins, then estate default, then fail-open on absence.
/// </summary>
public class PerAppPatchPolicyTests
{
    private static PerAppPatchPolicy? Parse(string perAppPatchJson)
    {
        string cfg = $$"""{ "tenant_id": "t", "per_app_patch": {{perAppPatchJson}} }""";
        return AgentConfig.Deserialize(cfg)!.PerAppPatch;
    }

    [Fact]
    public void Override_Enabled_Wins_Over_FleetDefaultOff()
    {
        var p = Parse("""
            { "fleet_default_enabled": false,
              "overrides": [ { "platform": "windows", "identifier": "Google.Chrome", "enabled": true } ] }
            """);

        Assert.True(p!.Allows("windows", "Google.Chrome"));
        Assert.Equal(PerAppPatchPolicy.SourceOverride, p.SourceFor("windows", "Google.Chrome"));
    }

    [Fact]
    public void Override_Disabled_Wins_Over_FleetDefaultOn()
    {
        var p = Parse("""
            { "fleet_default_enabled": true,
              "overrides": [ { "platform": "windows", "identifier": "Mozilla.Firefox", "enabled": false } ] }
            """);

        Assert.False(p!.Allows("windows", "Mozilla.Firefox"));
        Assert.Equal(PerAppPatchPolicy.SourceOverride, p.SourceFor("windows", "Mozilla.Firefox"));
    }

    [Fact]
    public void NoOverride_FallsBackToFleetDefault()
    {
        var on  = Parse("""{ "fleet_default_enabled": true, "overrides": [] }""");
        var off = Parse("""{ "fleet_default_enabled": false, "overrides": [] }""");

        Assert.True(on!.Allows("windows", "Some.App"));
        Assert.False(off!.Allows("windows", "Some.App"));
        Assert.Equal(PerAppPatchPolicy.SourceFleetDefault, on.SourceFor("windows", "Some.App"));
    }

    [Fact]
    public void Override_ForOtherPlatform_IsIgnored()
    {
        // A macOS override must not affect the Windows resolution.
        var p = Parse("""
            { "fleet_default_enabled": true,
              "overrides": [ { "platform": "macos", "identifier": "Google.Chrome", "enabled": false } ] }
            """);

        Assert.True(p!.Allows("windows", "Google.Chrome"));   // falls through to estate default
        Assert.Equal(PerAppPatchPolicy.SourceFleetDefault, p.SourceFor("windows", "Google.Chrome"));
    }

    [Fact]
    public void Identifier_And_Platform_MatchCaseInsensitively()
    {
        var p = Parse("""
            { "fleet_default_enabled": false,
              "overrides": [ { "platform": "Windows", "identifier": "google.chrome", "enabled": true } ] }
            """);

        Assert.True(p!.Allows("windows", "GOOGLE.CHROME"));
    }

    [Fact]
    public void Allows_MatchesAnyCandidateIdentifier_IncludingLabel()
    {
        // Overrides may be keyed by the shared label rather than the winget id.
        var p = Parse("""
            { "fleet_default_enabled": false,
              "overrides": [ { "platform": "windows", "identifier": "googlechrome", "enabled": true } ] }
            """);

        // candidates: (winget id, label) — the label matches.
        Assert.True(p!.Allows("windows", "Google.Chrome", "googlechrome"));
    }

    [Fact]
    public void Enabled_DefaultsTrue_WhenOmitted()
    {
        var p = Parse("""
            { "fleet_default_enabled": false,
              "overrides": [ { "platform": "windows", "identifier": "Google.Chrome" } ] }
            """);

        Assert.True(p!.Allows("windows", "Google.Chrome"));
    }

    [Fact]
    public void NullPolicy_DeserializesToNull_AndAllowsOrDefaultIsTrue()
    {
        var cfg = AgentConfig.Deserialize("""{ "tenant_id": "t", "per_app_patch": null }""");

        Assert.Null(cfg!.PerAppPatch);
        Assert.True(PerAppPatchPolicy.AllowsOrDefault(cfg.PerAppPatch, "windows", "Anything"));
    }

    [Fact]
    public void AbsentPolicy_IsNull_AndFailsOpen()
    {
        var cfg = AgentConfig.Deserialize("""{ "tenant_id": "t" }""");

        Assert.Null(cfg!.PerAppPatch);
        Assert.True(PerAppPatchPolicy.AllowsOrDefault(cfg.PerAppPatch, "windows", "Anything"));
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    public void BareBool_IsToleratedDefensively(string boolJson, bool fleetEnabled)
    {
        var p = Parse(boolJson);

        Assert.NotNull(p);
        Assert.Equal(fleetEnabled, p!.FleetDefaultEnabled);
        Assert.Equal(fleetEnabled, p.Allows("windows", "Anything"));
    }

    [Fact]
    public void MalformedPolicy_FailsOpen_WithoutBrickingConfig()
    {
        // A wrong-typed per_app_patch must not discard the rest of the signed config.
        var cfg = AgentConfig.Deserialize(
            """{ "tenant_id": "t", "tier": "managed", "per_app_patch": "garbage" }""");

        Assert.NotNull(cfg);
        Assert.Equal("managed", cfg!.Tier);                // sibling fields survive
        Assert.True(PerAppPatchPolicy.AllowsOrDefault(cfg.PerAppPatch, "windows", "Anything"));
    }

    [Fact]
    public void MalformedOverrideRows_AreSkipped_NotFatal()
    {
        var p = Parse("""
            { "fleet_default_enabled": true,
              "overrides": [
                  "not-an-object",
                  { "platform": "windows", "enabled": false },
                  { "platform": "windows", "identifier": "Mozilla.Firefox", "enabled": false }
              ] }
            """);

        Assert.NotNull(p);
        Assert.Single(p!.Overrides);                       // only the well-formed keyed row
        Assert.False(p.Allows("windows", "Mozilla.Firefox"));
    }
}
