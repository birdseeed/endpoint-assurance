using System.Text.Json;
using Patched.Shared.Config;
using Patched.Shared.Interruption;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1624: the bounds, proven with a synthetic permanently-busy state rather
/// than a click-through. Mirrors
/// menubar/PatchedUpdaterTests/PromptPresentationGovernorTests.swift.
/// </summary>
public sealed class PromptPresentationGovernorTests
{
    private const string Surface = "os_update_blocking_prompt";
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

        public void Clear()
        {
            Camera = Microphone = Presenting = Focus = SignalReading.Idle;
        }
    }

    private sealed class RecordingEvents : IInterruptionEventSink
    {
        public List<(string Level, string Message, IReadOnlyDictionary<string, object> Fields)> Entries { get; } = new();
        public void Record(string level, string message, IReadOnlyDictionary<string, object> fields) =>
            Entries.Add((level, message, fields));
    }

    private sealed class RecordingOperatorSignal : IOperatorSignalSink
    {
        public List<(string Surface, InterruptionReason Reason, DateTimeOffset Since, int Days)> Raised { get; } = new();
        public List<string> Cleared { get; } = new();

        public void SignalPromptUnreachable(string surface, InterruptionReason reason, DateTimeOffset since, int suppressedDays) =>
            Raised.Add((surface, reason, since, suppressedDays));

        public void ClearPromptUnreachable(string surface) => Cleared.Add(surface);
    }

    private readonly StubSignals _signals = new();
    private readonly RecordingEvents _events = new();
    private readonly RecordingOperatorSignal _operator = new();

    private PromptPresentationGovernor Governor(InterruptionPolicy? policy = null, TimeSpan? retry = null) =>
        new(Surface, new InterruptionGate(_signals), retry ?? Retry, policy, _events, _operator);

    /// <summary>A fixed local start so day boundaries are unambiguous.</summary>
    private static DateTimeOffset Day(int index, int hour = 9) =>
        new DateTimeOffset(new DateTime(2026, 9, 14 + index, hour, 0, 0, DateTimeKind.Local));

    // ---- Happy path -------------------------------------------------------

    [Fact]
    public void ClearSignalsPresent()
    {
        var governor = Governor();
        Assert.Equal(PromptOutcomeKind.Present, governor.Evaluate(Day(0), sessionActive: true).Kind);
        Assert.Equal(0, governor.ConsecutiveSuppressedAttempts);
    }

    // ---- Bound 1: stop presenting after the suppression window -------------

    [Fact]
    public void DefaultAttemptCapIsFourAtTheTwoHourRetry()
    {
        Assert.Equal(4, Governor().AttemptCap);
    }

    [Fact]
    public void FirstThreeSuppressedAttemptsJustDelay()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var outcome = governor.Evaluate(Day(0, 9 + attempt * 2), sessionActive: true);
            Assert.Equal(PromptOutcomeKind.Suppressed, outcome.Kind);
            Assert.Equal(InterruptionReason.CameraInUse, outcome.Reason);
        }
    }

    [Fact]
    public void FourthConsecutiveSuppressedAttemptFallsBackToANotification()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        PromptOutcome outcome = PromptOutcome.Absent;
        for (var attempt = 1; attempt <= 4; attempt++)
            outcome = governor.Evaluate(Day(0, 9 + attempt * 2), sessionActive: true);

        Assert.Equal(PromptOutcomeKind.NotificationFallback, outcome.Kind);
        Assert.Equal(InterruptionReason.CameraInUse, outcome.Reason);
    }

    [Fact]
    public void ChangingTheRetryIntervalDoesNotChangeTheEightHourPolicy()
    {
        Assert.Equal(8, Governor(retry: TimeSpan.FromHours(1)).AttemptCap);
        Assert.Equal(4, Governor(retry: TimeSpan.FromHours(2)).AttemptCap);
        Assert.Equal(2, Governor(retry: TimeSpan.FromHours(4)).AttemptCap);
    }

    // ---- Bound 2: notification at most once per day ------------------------

    [Fact]
    public void SecondFallbackInsideTheSameDayIsSilent()
    {
        _signals.Microphone = SignalReading.Busy;
        var governor = Governor();
        for (var attempt = 1; attempt <= 4; attempt++)
            governor.Evaluate(Day(0, 8 + attempt), sessionActive: true);

        Assert.Equal(PromptOutcomeKind.Silent, governor.Evaluate(Day(0, 14), sessionActive: true).Kind);
    }

    [Fact]
    public void AFurtherFallbackFiresOnceTheDailyGapHasElapsed()
    {
        _signals.Microphone = SignalReading.Busy;
        var governor = Governor();
        for (var attempt = 1; attempt <= 4; attempt++)
            governor.Evaluate(Day(0, 8 + attempt), sessionActive: true);

        Assert.Equal(PromptOutcomeKind.NotificationFallback,
            governor.Evaluate(Day(1, 14), sessionActive: true).Kind);
    }

    // ---- Bound 3: operator signal after three days -------------------------

    [Fact]
    public void OperatorIsNotSignalledAfterOneBusyDay()
    {
        _signals.Presenting = SignalReading.Busy;
        var governor = Governor();
        for (var attempt = 1; attempt <= 6; attempt++)
            governor.Evaluate(Day(0, 8 + attempt), sessionActive: true);

        Assert.Empty(_operator.Raised);
    }

    [Fact]
    public void OperatorIsSignalledOnceOnTheThirdConsecutiveBusyDay()
    {
        _signals.Presenting = SignalReading.Busy;
        var governor = Governor();
        for (var index = 0; index < 6; index++)
            for (var attempt = 1; attempt <= 4; attempt++)
                governor.Evaluate(Day(index, 8 + attempt), sessionActive: true);

        Assert.Single(_operator.Raised);
        Assert.Equal(Surface, _operator.Raised[0].Surface);
        Assert.Equal(InterruptionReason.Presenting, _operator.Raised[0].Reason);
        Assert.Equal(3, _operator.Raised[0].Days);
    }

    // ---- Bound 4: absence is not suppression -------------------------------

    [Fact]
    public void ALockedSessionMovesNoCounters()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        for (var index = 0; index < 10; index++)
            Assert.Equal(PromptOutcomeKind.Absent, governor.Evaluate(Day(index), sessionActive: false).Kind);

        Assert.Equal(0, governor.ConsecutiveSuppressedAttempts);
        Assert.Equal(0, governor.SuppressedDayCount);
        Assert.Empty(_operator.Raised);
        Assert.Empty(_events.Entries);
    }

    [Fact]
    public void ALaptopInABagForThreeDaysThenAvailableStillPresents()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        for (var index = 0; index < 3; index++)
            governor.Evaluate(Day(index), sessionActive: false);

        _signals.Clear();
        Assert.Equal(PromptOutcomeKind.Present, governor.Evaluate(Day(3), sessionActive: true).Kind);
    }

    // ---- Counters reset on a successful presentation -----------------------

    [Fact]
    public void ASuccessfulPresentationResetsEveryCounter()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        for (var attempt = 1; attempt <= 3; attempt++)
            governor.Evaluate(Day(0, 8 + attempt), sessionActive: true);
        Assert.Equal(3, governor.ConsecutiveSuppressedAttempts);

        _signals.Clear();
        Assert.Equal(PromptOutcomeKind.Present, governor.Evaluate(Day(0, 13), sessionActive: true).Kind);
        Assert.Equal(0, governor.ConsecutiveSuppressedAttempts);
        Assert.Equal(0, governor.SuppressedDayCount);
        Assert.Null(governor.SuppressionRunStartedAt);

        _signals.Camera = SignalReading.Busy;
        Assert.Equal(PromptOutcomeKind.Suppressed, governor.Evaluate(Day(0, 15), sessionActive: true).Kind);
    }

    [Fact]
    public void ASuccessfulPresentationWithdrawsAStandingOperatorSignal()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        for (var index = 0; index < 3; index++)
            for (var attempt = 1; attempt <= 4; attempt++)
                governor.Evaluate(Day(index, 8 + attempt), sessionActive: true);
        Assert.Single(_operator.Raised);

        _signals.Clear();
        governor.Evaluate(Day(3), sessionActive: true);
        Assert.Equal(new[] { Surface }, _operator.Cleared);
        Assert.False(governor.OperatorSignalled);
    }

    // ---- Suppression delays, it never cancels ------------------------------

    [Fact]
    public void EveryOutcomeLeavesTheNextAttemptPossible()
    {
        _signals.Focus = SignalReading.Busy;
        var governor = Governor();
        for (var attempt = 1; attempt <= 20; attempt++)
            Assert.NotEqual(PromptOutcomeKind.Present,
                governor.Evaluate(Day(attempt / 4, 8 + attempt % 4), sessionActive: true).Kind);

        _signals.Clear();
        Assert.Equal(PromptOutcomeKind.Present, governor.Evaluate(Day(9), sessionActive: true).Kind);
    }

    // ---- Privacy -----------------------------------------------------------

    [Fact]
    public void SuppressionEventsCarryOnlyTheReasonCode()
    {
        _signals.Camera = SignalReading.Busy;
        Governor().Evaluate(Day(0), sessionActive: true);

        var suppression = Assert.Single(_events.Entries, e => e.Message == "prompt suppressed");
        Assert.Equal(
            new[] { "attempt", "attempt_cap", "reason", "suppressed_days", "surface" },
            suppression.Fields.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.Equal("camera_in_use", suppression.Fields["reason"]);
    }

    [Fact]
    public void NoEventEverRecordsADurationOrAnApplication()
    {
        _signals.Camera = SignalReading.Busy;
        var governor = Governor();
        for (var index = 0; index < 4; index++)
            for (var attempt = 1; attempt <= 4; attempt++)
                governor.Evaluate(Day(index, 8 + attempt), sessionActive: true);

        string[] forbidden = { "app", "application", "bundle", "process", "duration", "started_at", "ended_at", "held_by" };
        foreach (var entry in _events.Entries)
            foreach (var key in entry.Fields.Keys)
                Assert.DoesNotContain(key, forbidden);
    }

    // ---- Policy resolution / tier placement --------------------------------

    [Fact]
    public void ShippedDefaultsMatchTheAgreedBounds()
    {
        var policy = InterruptionPolicy.Defaults;
        Assert.Equal(8, policy.SuppressionWindowHours);
        Assert.Null(policy.MaxSuppressedAttempts);
        Assert.Equal(24, policy.NotificationFallbackIntervalHours);
        Assert.Equal(3, policy.OperatorSignalAfterDays);
        Assert.Equal(4, policy.EffectiveAttemptCap(TimeSpan.FromHours(2)));
    }

    private static readonly InterruptionPolicyOverrides Overrides = new()
    {
        SuppressionWindowHours = 2,
        MaxSuppressedAttempts = 1,
        NotificationFallbackIntervalHours = 4,
        OperatorSignalAfterDays = 1,
    };

    [Fact]
    public void ManagedTierAppliesOverrides()
    {
        var policy = InterruptionPolicy.Resolve(Overrides, "managed");
        Assert.Equal(2, policy.SuppressionWindowHours);
        Assert.Equal(1, policy.MaxSuppressedAttempts);
        Assert.Equal(4, policy.NotificationFallbackIntervalHours);
        Assert.Equal(1, policy.OperatorSignalAfterDays);
    }

    [Theory]
    // Only "managed" ever applied — this gate never accepted "patch" even before
    // PAT-1599 retired it. "assurance" is the current canonical observe-only tier;
    // "report_deploy"/"patch"/"report" are retired values that must keep refusing.
    [InlineData("report_deploy")]
    [InlineData("patch")]
    [InlineData("assurance")]
    [InlineData("report")]
    [InlineData(null)]
    [InlineData("")]
    public void EveryOtherTierIgnoresOverridesEntirely(string? tier)
    {
        Assert.Equal(InterruptionPolicy.Defaults, InterruptionPolicy.Resolve(Overrides, tier));
    }

    [Fact]
    public void TierMatchIsCaseInsensitiveLikeTheRestOfTheTierSeam()
    {
        Assert.Equal(2, InterruptionPolicy.Resolve(Overrides, "MANAGED").SuppressionWindowHours);
    }

    [Fact]
    public void OutOfRangeValuesLeaveTheDefaultsInPlace()
    {
        var bad = new InterruptionPolicyOverrides
        {
            SuppressionWindowHours = 0,
            MaxSuppressedAttempts = -1,
            NotificationFallbackIntervalHours = 100_000,
            OperatorSignalAfterDays = 0,
        };
        Assert.Equal(InterruptionPolicy.Defaults, InterruptionPolicy.Resolve(bad, "managed"));
    }

    [Fact]
    public void AnExplicitCapOnlyEverTightensTheDerivedOne()
    {
        var tight = InterruptionPolicy.Defaults with { MaxSuppressedAttempts = 2 };
        Assert.Equal(2, tight.EffectiveAttemptCap(TimeSpan.FromHours(2)));

        var loose = InterruptionPolicy.Defaults with { MaxSuppressedAttempts = 99 };
        Assert.Equal(4, loose.EffectiveAttemptCap(TimeSpan.FromHours(2)));
    }

    // ---- Contract binding ---------------------------------------------------

    [Fact]
    public void TheInterruptionBlockBindsFromASignedAgentConfig()
    {
        const string json = """
        {
          "tenant_id": "00000000-0000-0000-0000-000000000000",
          "config_version": 4,
          "tier": "managed",
          "interruption_policy": {
            "suppression_window_hours": 12,
            "notification_fallback_interval_hours": 6,
            "operator_signal_after_days": 2
          }
        }
        """;
        var config = JsonSerializer.Deserialize<AgentConfig>(json)!;
        var policy = InterruptionPolicy.Resolve(config.InterruptionPolicy, config.Tier);
        Assert.Equal(12, policy.SuppressionWindowHours);
        Assert.Equal(6, policy.NotificationFallbackIntervalHours);
        Assert.Equal(2, policy.OperatorSignalAfterDays);
    }

    [Fact]
    public void AConfigWithNoInterruptionBlockUsesTheDefaults()
    {
        const string json = """
        {"tenant_id":"00000000-0000-0000-0000-000000000000","config_version":1,"tier":"managed"}
        """;
        var config = JsonSerializer.Deserialize<AgentConfig>(json)!;
        Assert.Null(config.InterruptionPolicy);
        Assert.Equal(InterruptionPolicy.Defaults, InterruptionPolicy.Resolve(config.InterruptionPolicy, config.Tier));
    }
}
