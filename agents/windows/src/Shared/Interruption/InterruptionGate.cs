namespace Patched.Shared.Interruption;

/// <summary>
/// PAT-1624: the one gate every user-facing prompt the Windows agent raises
/// must pass through. Content-equivalent with the macOS
/// <c>InterruptionGate.canInterruptNow()</c>.
///
/// The rule is not "camera". Special-casing the camera produces a second gap
/// the first time somebody dials into a call with video off, so the gate reads
/// four signals and any one of them is enough to stay quiet.
/// </summary>
public sealed record InterruptionDecision(bool IsAllowed, InterruptionReason? Reason)
{
    public static readonly InterruptionDecision Allow = new(true, null);
    public static InterruptionDecision Suppress(InterruptionReason reason) => new(false, reason);
}

public sealed class InterruptionGate
{
    private readonly IInterruptionSignalSource _source;

    public InterruptionGate(IInterruptionSignalSource source) => _source = source;

    /// <summary>
    /// The one question every user-facing prompt asks before it appears.
    ///
    /// Two passes on purpose. The first looks for a signal that is definitely
    /// busy, in a fixed order, so an admin looking at a device that is not
    /// progressing gets the most informative reason available. Only if nothing
    /// is definitely busy does the second pass fall back to
    /// <see cref="InterruptionReason.SignalUnreadable"/>, which still
    /// suppresses. Both passes end in silence, so the ordering only ever
    /// changes the reason code, never the decision.
    /// </summary>
    public InterruptionDecision CanInterruptNow()
    {
        var readings = new (InterruptionReason Reason, SignalReading Reading)[]
        {
            (InterruptionReason.CameraInUse,         _source.CameraReading()),
            (InterruptionReason.MicrophoneInUse,     _source.MicrophoneReading()),
            (InterruptionReason.Presenting,          _source.PresentingReading()),
            (InterruptionReason.FocusOrDoNotDisturb, _source.FocusReading()),
        };

        foreach (var (reason, reading) in readings)
            if (reading == SignalReading.Busy) return InterruptionDecision.Suppress(reason);

        foreach (var (_, reading) in readings)
            if (reading == SignalReading.Unreadable)
                return InterruptionDecision.Suppress(InterruptionReason.SignalUnreadable);

        return InterruptionDecision.Allow;
    }
}
