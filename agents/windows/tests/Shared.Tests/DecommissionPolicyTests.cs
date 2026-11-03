using Patched.Shared.Config;
using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1110. Proves the decommission block's parsing degrades to a safe/never-due
/// reading for every malformed or absent shape, and never throws out of
/// AgentConfig.Deserialize the way the PAT-737 proxy-port regression did for a
/// differently-typed field. Combined with DecommissionEvaluatorTests, this is the
/// "prove it with a test" evidence for the ticket's safety contract: an unverifiable
/// or locally-tampered decommission block can only ever resolve to NotDue or Fault,
/// never Due.
/// </summary>
public class DecommissionPolicyTests
{
    private static DateTimeOffset BuildFloor => AgentBuildInfo.BuildFloor;

    [Fact]
    public void AgentConfig_DecommissionAbsent_IsNull_NotDefaults()
    {
        // Distinguishing "absent from the document" from "explicit mode=none" is the
        // whole point of AgentConfig.Decommission having no object-initializer
        // default — see the property's doc comment.
        const string json = """{ "tenant_id": "t", "config_version": 1 }""";
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Null(cfg!.Decommission);
    }

    [Fact]
    public void Defaults_DecommissionIsNull()
    {
        // AgentConfig.Defaults is what the worker uses before any config has ever
        // been verified. It must never resolve to "due".
        Assert.Null(AgentConfig.Defaults.Decommission);
    }

    [Fact]
    public void Deserialize_ExplicitModeNone_IsRecognisedAndInert()
    {
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": "none", "expires_at": null, "purge": false, "reason": null }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg!.Decommission);
        Assert.True(cfg.Decommission!.IsRecognisedMode);
        Assert.Equal(DecommissionMode.None, cfg.Decommission.ResolvedMode);
    }

    [Fact]
    public void Deserialize_ModeImmediate_ResolvesToImmediate()
    {
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": "immediate", "expires_at": null, "purge": true, "reason": "offboarding" }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.Equal(DecommissionMode.Immediate, cfg!.Decommission!.ResolvedMode);
        Assert.True(cfg.Decommission.Purge);
        Assert.Equal("offboarding", cfg.Decommission.Reason);
    }

    [Fact]
    public void Deserialize_ModeExpiry_ParsesExpiresAt()
    {
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": "expiry", "expires_at": "2026-12-01T00:00:00Z", "purge": false, "reason": null }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.Equal(DecommissionMode.Expiry, cfg!.Decommission!.ResolvedMode);
        Assert.Equal(DateTimeOffset.Parse("2026-12-01T00:00:00Z"), cfg.Decommission.ExpiresAt);
    }

    [Theory]
    [InlineData("banana")]
    [InlineData("")]
    [InlineData("Immediate")] // case-sensitive per the contract; not a recognised value
    public void Deserialize_UnrecognisedMode_IsNotRecognised(string mode)
    {
        string json = $$"""
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": "{{mode}}", "expires_at": null, "purge": false, "reason": null }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg!.Decommission);
        Assert.False(cfg.Decommission!.IsRecognisedMode);
    }

    [Fact]
    public void Deserialize_ModeAsNonString_DegradesToUnrecognised_NeverThrows()
    {
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": 123, "expires_at": null, "purge": false, "reason": null }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.NotNull(cfg!.Decommission);
        Assert.False(cfg.Decommission!.IsRecognisedMode);
    }

    [Fact]
    public void Deserialize_PurgeAsWrongType_DegradesToFalse_NeverThrows()
    {
        // A malformed "purge" must degrade to the SAFER (less destructive) default.
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": "none", "expires_at": null, "purge": "true", "reason": null }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg!.Decommission);
        Assert.False(cfg.Decommission!.Purge);
    }

    [Fact]
    public void Deserialize_DecommissionAsWrongShape_DegradesToUnrecognised_NeverThrows()
    {
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": "not-an-object"
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.NotNull(cfg!.Decommission);
        Assert.False(cfg.Decommission!.IsRecognisedMode);
    }

    [Fact]
    public void Deserialize_ExpiresAtUnparseable_ExpiresAtIsNullButRawIsPresent()
    {
        const string json = """
        {
          "tenant_id": "t",
          "config_version": 1,
          "decommission": { "mode": "expiry", "expires_at": "not-a-date", "purge": false, "reason": null }
        }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.True(cfg!.Decommission!.ExpiresAtPresent);
        Assert.Null(cfg.Decommission.ExpiresAt);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (item 1): DateTimeOffset.TryParse is PERMISSIVE —
    // it accepts a timezone-less, locale-style value and silently resolves it
    // using the ENDPOINT'S LOCAL timezone rather than failing. ExpiresAt must
    // reject anything that is not an explicit, offset-qualified RFC3339 instant —
    // the THE regression proof this test class exists to add.
    // -------------------------------------------------------------------------
    [Theory]
    [InlineData("2026-12-01T00:00:00")]        // no offset at all — the exact permissive-parse trap
    [InlineData("2026-12-01 00:00:00")]        // locale-style separator, still no offset
    [InlineData("2026-12-01T00:00:00.123")]    // fractional seconds, still no offset
    [InlineData("06/01/2026 00:00:00")]        // a locale date format DateTimeOffset.TryParse would also accept
    public void ExpiresAt_TimezoneLessValue_IsRejected_NeverResolvedViaLocalTimezone(string raw)
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = raw };

        Assert.True(policy.ExpiresAtPresent);
        Assert.Null(policy.ExpiresAt);
    }

    [Theory]
    [InlineData("2026-12-01T00:00:00Z")]
    [InlineData("2026-12-01T00:00:00.123Z")]
    [InlineData("2026-12-01T00:00:00.123456Z")]
    [InlineData("2026-12-01T00:00:00.1234567Z")]
    public void ExpiresAt_ExplicitZSuffix_IsAccepted_ResolvesToUtc(string raw)
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = raw };

        Assert.NotNull(policy.ExpiresAt);
        Assert.Equal(TimeSpan.Zero, policy.ExpiresAt!.Value.Offset);
    }

    [Theory]
    [InlineData("2026-12-01T02:00:00+02:00")]       // +02:00, same instant as 00:00Z
    [InlineData("2026-11-30T19:00:00-05:00")]       // -05:00, same instant as 00:00Z the next day
    [InlineData("2026-12-01T00:00:00.000000+00:00")]
    public void ExpiresAt_ExplicitNumericOffset_IsAccepted_OffsetHonoured(string raw)
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = raw };

        Assert.NotNull(policy.ExpiresAt);
        // Every case above denotes the same UTC instant —
        // proves the offset was actually applied, not just accepted as text.
        Assert.Equal(DateTimeOffset.Parse("2026-12-01T00:00:00Z"), policy.ExpiresAt!.Value);
    }

    [Fact]
    public void ExpiresAt_RoundTripFormat_SevenFractionalDigitsPlusNumericOffset_IsAccepted()
    {
        // DateTimeOffset.ToString("O") — used by both DecommissionEvaluatorTests
        // (Now.ToString("O") / BuildFloor.ToString("O")) and plausibly by whatever
        // authors the signed config — always emits exactly 7 fractional digits and
        // a numeric (never "Z") offset. Must parse.
        var original = DateTimeOffset.Parse("2026-08-01T12:00:00Z");
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = original.ToString("O") };

        Assert.Equal(original, policy.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_GenuinelyUnparseableValue_IsStillRejected()
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = "not-a-timestamp-at-all" };
        Assert.Null(policy.ExpiresAt);
    }

    [Fact]
    public void Deserialize_IsCaseInsensitiveLikeRestOfAgentConfig()
    {
        const string json = """
        { "Tenant_Id": "t", "Config_Version": 1, "Decommission": { "Mode": "immediate" } }
        """;
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg!.Decommission);
        Assert.Equal(DecommissionMode.Immediate, cfg.Decommission!.ResolvedMode);
    }

    // -------------------------------------------------------------------------
    // End-to-end safety proof: every shape above, run through the real evaluator,
    // never resolves to Due unless mode is genuinely "immediate" or a past
    // "expiry" — see DecommissionEvaluatorTests for the exhaustive pure-logic
    // coverage of Evaluate itself.
    // -------------------------------------------------------------------------

    [Fact]
    public void EndToEnd_AbsentDecommission_NeverDue()
    {
        var cfg = AgentConfig.Deserialize("""{ "tenant_id": "t", "config_version": 1 }""");
        var decision = DecommissionEvaluator.Evaluate(cfg!.Decommission, DateTimeOffset.UtcNow, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, decision.Outcome);
    }

    [Fact]
    public void EndToEnd_UnrecognisedMode_NeverDue()
    {
        var cfg = AgentConfig.Deserialize("""
        { "tenant_id": "t", "config_version": 1, "decommission": { "mode": "delete_everything" } }
        """);
        var decision = DecommissionEvaluator.Evaluate(cfg!.Decommission, DateTimeOffset.UtcNow, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, decision.Outcome);
    }
}
