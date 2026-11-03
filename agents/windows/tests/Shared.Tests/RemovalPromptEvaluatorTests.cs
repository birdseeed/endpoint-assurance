using Patched.Shared.Interruption;
using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1623: the removal notify/defer surface's presentation-decision logic,
/// mirroring menubar/PatchedUpdaterTests/RemovalPromptTests.swift for content
/// equivalence between the two platforms.
///
/// Load-bearing assertions: tier gate is fail-closed; a running removal
/// target presents; re-reading the same unchanged status does not re-request
/// an attempt; Defer never touches the daemon's own state; the prompt never
/// has a terminal state at any budget; the OS-update and removal surfaces
/// never both present in the same tick.
/// </summary>
public sealed class RemovalPromptEvaluatorTests
{
    private static readonly TimeSpan Retry = TimeSpan.FromHours(2);

    private sealed class StubSignals : IInterruptionSignalSource
    {
        public SignalReading Camera { get; set; } = SignalReading.Idle;
        public SignalReading Microphone { get; set; } = SignalReading.Idle;
        public SignalReading Presenting { get; set; } = SignalReading.Idle;
        public SignalReading Focus { get; set; } = SignalReading.Idle;

        public SignalReading CameraReading() => Camera;
        public SignalReading MicrophoneReading() => Microphone;
        public SignalReading PresentingReading() => Presenting;
        public SignalReading FocusReading() => Focus;
    }

    private readonly StubSignals _signals = new();

    private RemovalPromptEvaluator MakeEvaluator(RemovalPromptPolicy? policy = null)
    {
        var governor = new PromptPresentationGovernor(
            RemovalPromptEvaluator.Surface,
            new InterruptionGate(_signals),
            Retry);
        return new RemovalPromptEvaluator(governor, policy);
    }

    private static UninstallStatus StatusWith(params (long EntryId, string Name, RemovalOutcome Outcome)[] entries)
    {
        return new UninstallStatus
        {
            SchemaVersion = 1,
            GeneratedAt = DateTimeOffset.UtcNow,
            Removals = entries.Select(e => new RemovalResult
            {
                EntryId = e.EntryId,
                Name = e.Name,
                Outcome = e.Outcome,
                VerifyResult = null,
                Method = RemovalMethod.None,
                RecordedAt = DateTimeOffset.UtcNow,
            }).ToList(),
        };
    }

    // MARK: - Tier gate

    [Fact]
    public void InertWhenTierNeverApplied()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
        Assert.Null(evaluator.Pending);
        Assert.Equal(PromptOutcomeKind.Absent,
            evaluator.Evaluate(DateTimeOffset.UtcNow, sessionActive: true, shouldShowOsUpdatePrompt: false).Kind);
    }

    [Theory]
    // Only "managed" ever applied — this gate never accepted "patch" even before
    // PAT-1599 retired it. "report"/"report_deploy"/"patch" are retired values
    // that must keep refusing alongside the current canonical "assurance".
    [InlineData("report")]
    [InlineData("report_deploy")]
    [InlineData("patch")]
    [InlineData("assurance")]
    [InlineData("")]
    [InlineData("weird")]
    public void InertForEveryNonManagedTier(string tier)
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier(tier);
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
        Assert.Null(evaluator.Pending);
    }

    [Fact]
    public void ManagedTierIsCaseInsensitive()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("MANAGED");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
        Assert.NotNull(evaluator.Pending);
    }

    // MARK: - Presentation

    [Fact]
    public void ARunningRemovalTargetPresents()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));

        var outcome = evaluator.Evaluate(DateTimeOffset.UtcNow, sessionActive: true, shouldShowOsUpdatePrompt: false);
        Assert.Equal(PromptOutcomeKind.Present, outcome.Kind);
    }

    [Fact]
    public void OnlyDeferredAppRunningOutcomesSurface()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith(
            (1, "Zoom", RemovalOutcome.Removed),
            (2, "Docker", RemovalOutcome.FailedHard)));
        Assert.Null(evaluator.Pending);
    }

    [Fact]
    public void SuppressionDelaysNotCancels()
    {
        _signals.Camera = SignalReading.Busy;
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));

        var outcome = evaluator.Evaluate(DateTimeOffset.UtcNow, sessionActive: true, shouldShowOsUpdatePrompt: false);
        Assert.Equal(PromptOutcomeKind.Suppressed, outcome.Kind);
        Assert.NotNull(evaluator.Pending);
    }

    // MARK: - Re-notification restraint

    [Fact]
    public void UnchangedStatusIsNotAFreshAttempt()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        var first = evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
        Assert.True(first, "the first sighting is itself an attempt opportunity");

        var second = evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
        Assert.False(second, "an unchanged pending app must not re-request an attempt every cycle");
    }

    [Fact]
    public void ADifferentAppEnteringTheSetIsAFreshAttempt()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));

        var fresh = evaluator.ApplyStatus(StatusWith(
            (1, "Slack", RemovalOutcome.DeferredAppRunning),
            (2, "Docker Desktop", RemovalOutcome.DeferredAppRunning)));
        Assert.True(fresh, "a different app newly needing removal is a state change, not a repeat");
    }

    // MARK: - Defer

    [Fact]
    public void DeferDismissesLocallyWithoutGating()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
        Assert.NotNull(evaluator.Pending);

        evaluator.RecordDefer();
        Assert.Null(evaluator.Pending);
    }

    [Fact]
    public void RepeatedDefersNeverExhaustTheAbilityToDeferAgain()
    {
        // Budget of 1 is the most adversarial case for a would-be "count < budget" gate.
        var evaluator = MakeEvaluator(new RemovalPromptPolicy { DeferralBudget = 1 });
        evaluator.ApplyTier("managed");

        for (var i = 0; i < 5; i++)
        {
            evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));
            Assert.NotNull(evaluator.Pending);
            evaluator.RecordDefer();
        }
    }

    // MARK: - No terminal state, ever

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(5, 5)]
    [InlineData(1, 100)]
    [InlineData(0, 1)]
    public void NeverRendersATerminalStateAtAnyBudget(int budget, long deferralCount)
    {
        var policy = new RemovalPromptPolicy { DeferralBudget = budget };
        Assert.True(policy.CanAlwaysDefer(deferralCount));
    }

    // MARK: - "Queue, do not stack"

    [Fact]
    public void OsUpdateAndRemovalNeverPresentInTheSameTick()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));

        var outcome = evaluator.Evaluate(DateTimeOffset.UtcNow, sessionActive: true, shouldShowOsUpdatePrompt: true);
        Assert.Equal(PromptOutcomeKind.Absent, outcome.Kind);
    }

    [Fact]
    public void RemovalPresentsOnceTheOsUpdatePromptIsNotDue()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));

        var outcome = evaluator.Evaluate(DateTimeOffset.UtcNow, sessionActive: true, shouldShowOsUpdatePrompt: false);
        Assert.Equal(PromptOutcomeKind.Present, outcome.Kind);
    }

    [Fact]
    public void ALockedSessionIsAbsentNotSuppressed()
    {
        var evaluator = MakeEvaluator();
        evaluator.ApplyTier("managed");
        evaluator.ApplyStatus(StatusWith((1, "Slack", RemovalOutcome.DeferredAppRunning)));

        var outcome = evaluator.Evaluate(DateTimeOffset.UtcNow, sessionActive: false, shouldShowOsUpdatePrompt: false);
        Assert.Equal(PromptOutcomeKind.Absent, outcome.Kind);
    }
}
