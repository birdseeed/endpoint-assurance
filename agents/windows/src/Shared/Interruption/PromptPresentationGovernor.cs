namespace Patched.Shared.Interruption;

/// <summary>
/// PAT-1624: what happens when the never-interrupt gate keeps saying no.
/// Content-equivalent with the macOS <c>PromptPresentationGovernor</c>.
///
/// THE THREE PROPERTIES THAT MATTER MORE THAN THE NUMBERS:
///
/// 1. Suppression DELAYS, it never cancels. Every suppressed attempt is retried
///    on the caller's existing retry cadence.
/// 2. Suppression NEVER touches a deferral budget. Nothing in this file reads,
///    writes, decrements or resets deferrals_remaining, and it writes no
///    os_defer trigger. Only a human pressing Defer spends a deferral.
/// 3. Counters accrue only while a user session is active and unlocked, and
///    reset on any successful presentation. Locked or logged out is ABSENCE,
///    not suppression: a laptop shut in a bag for a day must not arrive at
///    "cannot be prompted" having never been near a camera.
///
/// PRIVACY. Everything that leaves this class is a reason code and a counter.
/// It never records or uploads which application held the camera, when, or for
/// how long.
/// </summary>
public enum PromptOutcomeKind
{
    /// Show the window.
    Present,
    /// No user session, or the screen is locked. Not suppression: no counter moves.
    Absent,
    /// Gated, still inside the suppression window. Try again next tick.
    Suppressed,
    /// Past the suppression window: hand off to a notification, which Windows
    /// already delivers correctly under Focus Assist and during a call.
    NotificationFallback,
    /// Past the suppression window and already notified inside the daily gap.
    Silent,
}

public sealed record PromptOutcome(PromptOutcomeKind Kind, InterruptionReason? Reason)
{
    public static readonly PromptOutcome Present = new(PromptOutcomeKind.Present, null);
    public static readonly PromptOutcome Absent  = new(PromptOutcomeKind.Absent, null);
}

/// <summary>Where suppression events go. The reason code is the whole payload.</summary>
public interface IInterruptionEventSink
{
    void Record(string level, string message, IReadOnlyDictionary<string, object> fields);
}

/// <summary>How the agent tells the platform it has a user it cannot reach.</summary>
public interface IOperatorSignalSink
{
    void SignalPromptUnreachable(string surface, InterruptionReason reason, DateTimeOffset since, int suppressedDays);
    void ClearPromptUnreachable(string surface);
}

public sealed class NullInterruptionEventSink : IInterruptionEventSink
{
    public static readonly NullInterruptionEventSink Instance = new();
    public void Record(string level, string message, IReadOnlyDictionary<string, object> fields) { }
}

public sealed class NullOperatorSignalSink : IOperatorSignalSink
{
    public static readonly NullOperatorSignalSink Instance = new();
    public void SignalPromptUnreachable(string surface, InterruptionReason reason, DateTimeOffset since, int suppressedDays) { }
    public void ClearPromptUnreachable(string surface) { }
}

public sealed class PromptPresentationGovernor
{
    private readonly InterruptionGate _gate;
    private readonly IInterruptionEventSink _events;
    private readonly IOperatorSignalSink _operatorSignal;
    private readonly TimeSpan _retryInterval;

    /// <summary>
    /// Which prompt this governor guards. One instance per user-facing surface,
    /// so a quiet OS-update prompt does not silence a removal prompt.
    /// </summary>
    public string Surface { get; }

    public InterruptionPolicy Policy { get; private set; }

    public int ConsecutiveSuppressedAttempts { get; private set; }
    /// <summary>
    /// Distinct local calendar days on which a suppressed attempt happened while
    /// the session was active. Wall-clock days are the wrong unit: a machine
    /// that was asleep contributed no days.
    /// </summary>
    public int SuppressedDayCount { get; private set; }
    public DateTimeOffset? SuppressionRunStartedAt { get; private set; }
    public bool OperatorSignalled { get; private set; }

    private DateOnly? _lastSuppressedDay;
    private DateTimeOffset? _lastFallbackNotificationAt;

    public PromptPresentationGovernor(
        string surface,
        InterruptionGate gate,
        TimeSpan retryInterval,
        InterruptionPolicy? policy = null,
        IInterruptionEventSink? events = null,
        IOperatorSignalSink? operatorSignal = null)
    {
        Surface         = surface;
        _gate           = gate;
        _retryInterval  = retryInterval;
        Policy          = policy ?? InterruptionPolicy.Defaults;
        _events         = events ?? NullInterruptionEventSink.Instance;
        _operatorSignal = operatorSignal ?? NullOperatorSignalSink.Instance;
    }

    /// <summary>
    /// Live policy updates from the signed config. Counters are left alone: a
    /// config refresh mid-suppression must not hand the user a fresh 8 hours.
    /// </summary>
    public void UpdatePolicy(InterruptionPolicy policy) => Policy = policy;

    public int AttemptCap => Policy.EffectiveAttemptCap(_retryInterval);

    public PromptOutcome Evaluate(DateTimeOffset now, bool sessionActive)
    {
        // Absence, not suppression. No counter moves and nothing is recorded.
        if (!sessionActive) return PromptOutcome.Absent;

        var decision = _gate.CanInterruptNow();
        if (decision.IsAllowed)
        {
            RecordSuccessfulPresentation();
            return PromptOutcome.Present;
        }

        var reason = decision.Reason!.Value;
        ConsecutiveSuppressedAttempts++;
        SuppressionRunStartedAt ??= now;
        CountDay(now);

        var cap = AttemptCap;
        _events.Record("info", "prompt suppressed", new Dictionary<string, object>
        {
            ["surface"]         = Surface,
            ["reason"]          = reason.Code(),
            ["attempt"]         = ConsecutiveSuppressedAttempts,
            ["attempt_cap"]     = cap,
            ["suppressed_days"] = SuppressedDayCount,
        });

        MaybeSignalOperator(reason);

        if (ConsecutiveSuppressedAttempts < cap)
            return new PromptOutcome(PromptOutcomeKind.Suppressed, reason);

        return FallbackOutcome(now, reason);
    }

    /// <summary>
    /// Called when the window actually went up, and on the allow path. Resets
    /// every counter and withdraws any standing operator signal: the agent got
    /// through, so there is nothing left for an admin to act on.
    /// </summary>
    public void RecordSuccessfulPresentation()
    {
        var wasSuppressing = ConsecutiveSuppressedAttempts > 0;
        ConsecutiveSuppressedAttempts = 0;
        SuppressedDayCount = 0;
        _lastSuppressedDay = null;
        SuppressionRunStartedAt = null;
        _lastFallbackNotificationAt = null;
        if (OperatorSignalled)
        {
            _operatorSignal.ClearPromptUnreachable(Surface);
            OperatorSignalled = false;
        }
        if (wasSuppressing)
        {
            _events.Record("info", "prompt presented after suppression",
                new Dictionary<string, object> { ["surface"] = Surface });
        }
    }

    private void CountDay(DateTimeOffset now)
    {
        var day = DateOnly.FromDateTime(now.LocalDateTime);
        if (_lastSuppressedDay == day) return;
        _lastSuppressedDay = day;
        SuppressedDayCount++;
    }

    private PromptOutcome FallbackOutcome(DateTimeOffset now, InterruptionReason reason)
    {
        if (_lastFallbackNotificationAt is DateTimeOffset last &&
            now - last < Policy.NotificationFallbackInterval)
        {
            return new PromptOutcome(PromptOutcomeKind.Silent, reason);
        }

        _lastFallbackNotificationAt = now;
        _events.Record("info", "prompt fell back to notification", new Dictionary<string, object>
        {
            ["surface"]         = Surface,
            ["reason"]          = reason.Code(),
            ["suppressed_days"] = SuppressedDayCount,
        });
        return new PromptOutcome(PromptOutcomeKind.NotificationFallback, reason);
    }

    private void MaybeSignalOperator(InterruptionReason reason)
    {
        if (OperatorSignalled) return;
        if (SuppressedDayCount < Policy.OperatorSignalAfterDays) return;
        if (SuppressionRunStartedAt is not DateTimeOffset since) return;

        OperatorSignalled = true;
        _operatorSignal.SignalPromptUnreachable(Surface, reason, since, SuppressedDayCount);
        _events.Record("error", "prompt unreachable", new Dictionary<string, object>
        {
            ["surface"]         = Surface,
            ["reason"]          = reason.Code(),
            ["suppressed_days"] = SuppressedDayCount,
        });
    }
}
