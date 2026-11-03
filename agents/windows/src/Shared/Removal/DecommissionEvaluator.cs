using Patched.Shared.Config;

namespace Patched.Shared.Removal;

/// <summary>
/// PAT-1110. Pure evaluation of an already-verified <see cref="DecommissionPolicy"/>
/// into one of three outcomes — never due, due, or a fault. This is the single choke
/// point for the safety contract: every condition that must leave the agent running
/// (invalid/absent directive, unparseable or absurd expiry, unrecognised mode) is
/// handled here as <see cref="DecommissionOutcome.Fault"/>, not silently folded into
/// "not due" — callers (<c>DecommissionRunner</c>) record faults for operator
/// visibility even though the ACTION taken (do nothing) is identical to "not due".
///
/// Takes an already-verified <see cref="DecommissionPolicy"/> — this type performs no
/// signature/tenant/version checking itself. That verification is
/// <c>AgentConfigFetcher</c>'s job; a config that fails ANY of those checks is
/// rejected wholesale (see <c>AgentConfigFetcher.Reject</c>) and this evaluator never
/// even sees it, so signature-invalid / tenant-mismatch / version-regression configs
/// already can't reach "due" without any code here. This evaluator only covers the
/// decommission-specific structural checks the schema requires beyond that: absent
/// object, unrecognised mode, and a malformed/absurd expiry.
/// </summary>
public static class DecommissionEvaluator
{
    /// <param name="policy">
    /// The verified config's decommission block, or null if the "decommission"
    /// property was absent from the document entirely.
    /// </param>
    /// <param name="now">Current UTC time (injected for deterministic tests).</param>
    /// <param name="buildFloor">
    /// <see cref="AgentBuildInfo.BuildFloor"/> in production — an expiry earlier than
    /// this is treated as malformed/clock-skewed, never as "already due".
    /// </param>
    public static DecommissionDecision Evaluate(
        DecommissionPolicy? policy, DateTimeOffset now, DateTimeOffset buildFloor)
    {
        if (policy is null)
            return DecommissionDecision.Fault("decommission object absent from verified config");

        if (!policy.IsRecognisedMode)
            return DecommissionDecision.Fault($"unrecognised decommission mode '{policy.ModeRaw ?? "(null)"}'");

        return policy.ResolvedMode switch
        {
            DecommissionMode.None      => DecommissionDecision.NotDue(),
            DecommissionMode.Immediate => DecommissionDecision.Due(),
            DecommissionMode.Expiry    => EvaluateExpiry(policy, now, buildFloor),
            _ => DecommissionDecision.Fault($"unrecognised decommission mode '{policy.ModeRaw}'"),
        };
    }

    private static DecommissionDecision EvaluateExpiry(
        DecommissionPolicy policy, DateTimeOffset now, DateTimeOffset buildFloor)
    {
        if (!policy.ExpiresAtPresent)
            return DecommissionDecision.Fault("mode=expiry but expires_at is missing");

        if (policy.ExpiresAt is not { } expiresAt)
            return DecommissionDecision.Fault(
                $"mode=expiry but expires_at '{policy.ExpiresAtRaw}' is not a parseable RFC3339 timestamp");

        if (expiresAt < buildFloor)
            return DecommissionDecision.Fault(
                $"expires_at {expiresAt:O} predates the agent build floor {buildFloor:O} " +
                "(malformed value or the local clock is badly wrong)");

        return expiresAt <= now ? DecommissionDecision.Due() : DecommissionDecision.NotDue();
    }
}

public enum DecommissionOutcome
{
    NotDue,
    Due,
    Fault,
}

/// <summary>Result of <see cref="DecommissionEvaluator.Evaluate"/>.</summary>
public sealed record DecommissionDecision
{
    public required DecommissionOutcome Outcome { get; init; }

    /// <summary>Non-null only when <see cref="Outcome"/> is <see cref="DecommissionOutcome.Fault"/>.</summary>
    public string? FaultReason { get; init; }

    public static DecommissionDecision NotDue() => new() { Outcome = DecommissionOutcome.NotDue };
    public static DecommissionDecision Due() => new() { Outcome = DecommissionOutcome.Due };
    public static DecommissionDecision Fault(string reason) =>
        new() { Outcome = DecommissionOutcome.Fault, FaultReason = reason };
}
