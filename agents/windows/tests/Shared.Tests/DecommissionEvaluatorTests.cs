using Patched.Shared.Config;
using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1110. Exhaustive pure-logic coverage of the safety contract: every condition
/// enumerated in the ticket brief that must leave the agent running (invalid/absent
/// directive, unparseable or absurd expiry, unrecognised mode) resolves to
/// <see cref="DecommissionOutcome.Fault"/>, never <see cref="DecommissionOutcome.Due"/>.
/// </summary>
public class DecommissionEvaluatorTests
{
    private static readonly DateTimeOffset Now        = DateTimeOffset.Parse("2026-08-01T12:00:00Z");
    private static readonly DateTimeOffset BuildFloor  = DateTimeOffset.Parse("2026-07-01T00:00:00Z");

    [Fact]
    public void NullPolicy_ObjectAbsent_IsFault()
    {
        var d = DecommissionEvaluator.Evaluate(null, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, d.Outcome);
        Assert.Contains("absent", d.FaultReason);
    }

    [Fact]
    public void ModeNone_IsNotDue_NoFault()
    {
        var policy = new DecommissionPolicy { ModeRaw = "none" };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.NotDue, d.Outcome);
        Assert.Null(d.FaultReason);
    }

    [Fact]
    public void ModeImmediate_IsDue()
    {
        var policy = new DecommissionPolicy { ModeRaw = "immediate" };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Due, d.Outcome);
    }

    [Theory]
    [InlineData("")]
    [InlineData("delete")]
    [InlineData("Immediate")]
    [InlineData(null)]
    public void UnrecognisedOrNullMode_IsFault_NeverDue(string? mode)
    {
        var policy = new DecommissionPolicy { ModeRaw = mode };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, d.Outcome);
    }

    [Fact]
    public void ModeExpiry_FutureExpiry_IsNotDue()
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = "2026-09-01T00:00:00Z" };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.NotDue, d.Outcome);
    }

    [Fact]
    public void ModeExpiry_PastExpiry_IsDue()
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = "2026-07-01T00:00:00Z" };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Due, d.Outcome);
    }

    [Fact]
    public void ModeExpiry_ExactlyNow_IsDue()
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = Now.ToString("O") };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Due, d.Outcome);
    }

    [Fact]
    public void ModeExpiry_MissingExpiresAt_IsFault()
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = null };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, d.Outcome);
        Assert.Contains("missing", d.FaultReason);
    }

    [Fact]
    public void ModeExpiry_UnparseableExpiresAt_IsFault()
    {
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = "not-a-timestamp" };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, d.Outcome);
        Assert.Contains("not a parseable", d.FaultReason);
    }

    [Fact]
    public void ModeExpiry_ExpiresAtBeforeBuildFloor_IsFault_EvenThoughItsBeforeNow()
    {
        // A timestamp earlier than the agent's own build floor is either a malformed
        // value or evidence the local clock is badly wrong — it must NOT be treated
        // as "obviously already due" just because expires_at < now.
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = "2000-01-01T00:00:00Z" };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Fault, d.Outcome);
        Assert.Contains("predates", d.FaultReason);
    }

    [Fact]
    public void ModeExpiry_ExpiresAtExactlyBuildFloor_IsNotAFault()
    {
        // Boundary: equal to the floor is acceptable (only strictly-earlier is a fault).
        var policy = new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = BuildFloor.ToString("O") };
        var d = DecommissionEvaluator.Evaluate(policy, Now, BuildFloor);
        Assert.Equal(DecommissionOutcome.Due, d.Outcome); // BuildFloor is also < Now here
    }

    [Fact]
    public void PurgeAndReason_DoNotAffectOutcome()
    {
        // Reason must never be evaluated in control flow — vary it and purge and
        // confirm the outcome is unaffected.
        var a = DecommissionEvaluator.Evaluate(
            new DecommissionPolicy { ModeRaw = "none", Reason = "anything, even garbage", Purge = true },
            Now, BuildFloor);
        var b = DecommissionEvaluator.Evaluate(
            new DecommissionPolicy { ModeRaw = "none", Reason = null, Purge = false },
            Now, BuildFloor);

        Assert.Equal(DecommissionOutcome.NotDue, a.Outcome);
        Assert.Equal(DecommissionOutcome.NotDue, b.Outcome);
    }
}
