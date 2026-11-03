using System.Runtime.Versioning;
using Patched.Shared.Interruption;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1624: the Windows gate's decision logic, one signal at a time.
/// Mirrors menubar/PatchedUpdaterTests/InterruptionGateTests.swift case for
/// case so the two platforms cannot drift on what suppresses.
/// </summary>
public sealed class InterruptionGateTests
{
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

    private static InterruptionGate Gate(StubSignals signals) => new(signals);

    [Fact]
    public void AllClearAllowsTheInterruption()
    {
        Assert.True(Gate(new StubSignals()).CanInterruptNow().IsAllowed);
    }

    [Fact]
    public void CameraInUseSuppresses()
    {
        var decision = Gate(new StubSignals { Camera = SignalReading.Busy }).CanInterruptNow();
        Assert.False(decision.IsAllowed);
        Assert.Equal(InterruptionReason.CameraInUse, decision.Reason);
    }

    [Fact]
    public void MicrophoneInUseSuppresses()
    {
        // A windowed Teams call does not reliably set a busy notification state,
        // which is exactly why the ConsentStore read exists.
        var decision = Gate(new StubSignals { Microphone = SignalReading.Busy }).CanInterruptNow();
        Assert.Equal(InterruptionReason.MicrophoneInUse, decision.Reason);
    }

    [Fact]
    public void PresentingSuppresses()
    {
        var decision = Gate(new StubSignals { Presenting = SignalReading.Busy }).CanInterruptNow();
        Assert.Equal(InterruptionReason.Presenting, decision.Reason);
    }

    [Fact]
    public void FocusAssistSuppresses()
    {
        var decision = Gate(new StubSignals { Focus = SignalReading.Busy }).CanInterruptNow();
        Assert.Equal(InterruptionReason.FocusOrDoNotDisturb, decision.Reason);
    }

    [Theory]
    [InlineData("camera")]
    [InlineData("microphone")]
    [InlineData("presenting")]
    [InlineData("focus")]
    public void AnyUnreadableSignalSuppresses(string which)
    {
        var signals = new StubSignals();
        switch (which)
        {
            case "camera":     signals.Camera = SignalReading.Unreadable; break;
            case "microphone": signals.Microphone = SignalReading.Unreadable; break;
            case "presenting": signals.Presenting = SignalReading.Unreadable; break;
            default:           signals.Focus = SignalReading.Unreadable; break;
        }
        var decision = Gate(signals).CanInterruptNow();
        Assert.False(decision.IsAllowed);
        Assert.Equal(InterruptionReason.SignalUnreadable, decision.Reason);
    }

    [Fact]
    public void DefinitelyBusyBeatsUnreadableInTheReasonCode()
    {
        var signals = new StubSignals
        {
            Camera = SignalReading.Unreadable,
            Microphone = SignalReading.Busy,
        };
        Assert.Equal(InterruptionReason.MicrophoneInUse, Gate(signals).CanInterruptNow().Reason);
    }

    [Fact]
    public void FirstBusySignalInFixedOrderWins()
    {
        var signals = new StubSignals
        {
            Camera = SignalReading.Busy,
            Microphone = SignalReading.Busy,
            Presenting = SignalReading.Busy,
            Focus = SignalReading.Busy,
        };
        Assert.Equal(InterruptionReason.CameraInUse, Gate(signals).CanInterruptNow().Reason);
    }

    [Fact]
    public void ReasonCodesMatchTheMacosVocabularyExactly()
    {
        // Platform parity: an operator reading a suppression event should not
        // have to know which platform produced it.
        Assert.Equal("camera_in_use", InterruptionReason.CameraInUse.Code());
        Assert.Equal("microphone_in_use", InterruptionReason.MicrophoneInUse.Code());
        Assert.Equal("presenting", InterruptionReason.Presenting.Code());
        Assert.Equal("focus_or_do_not_disturb", InterruptionReason.FocusOrDoNotDisturb.Code());
        Assert.Equal("signal_unreadable", InterruptionReason.SignalUnreadable.Code());
    }
}

/// <summary>
/// PAT-1624: the SHQueryUserNotificationState mapping. Only
/// QUNS_ACCEPTS_NOTIFICATIONS permits a window.
///
/// [SupportedOSPlatform] is an analyser annotation, not a runtime gate: these
/// cases inject a fake shell state, so no P/Invoke into shell32 ever happens and
/// they run identically on the macOS cross-target build.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsShellNotificationStateTests
{
    private static WindowsInterruptionSignals WithState(ShellNotificationState state) =>
        new(() => state);

    [Theory]
    [InlineData(ShellNotificationState.Busy)]
    [InlineData(ShellNotificationState.RunningD3DFullScreen)]
    [InlineData(ShellNotificationState.PresentationMode)]
    [InlineData(ShellNotificationState.RunningWindowsStoreApp)]
    public void BusyStatesReadAsPresenting(ShellNotificationState state)
    {
        Assert.Equal(SignalReading.Busy, WithState(state).PresentingReading());
    }

    [Fact]
    public void QuietTimeReadsAsFocus()
    {
        Assert.Equal(SignalReading.Busy, WithState(ShellNotificationState.QuietTime).FocusReading());
        Assert.Equal(SignalReading.Idle, WithState(ShellNotificationState.QuietTime).PresentingReading());
    }

    [Fact]
    public void AcceptsNotificationsIsTheOnlyStateThatPermitsAWindow()
    {
        var signals = WithState(ShellNotificationState.AcceptsNotifications);
        Assert.Equal(SignalReading.Idle, signals.PresentingReading());
        Assert.Equal(SignalReading.Idle, signals.FocusReading());
    }

    [Fact]
    public void AFailedShellCallFailsClosed()
    {
        var signals = WithState(ShellNotificationState.Unknown);
        Assert.Equal(SignalReading.Unreadable, signals.PresentingReading());
        Assert.Equal(SignalReading.Unreadable, signals.FocusReading());
    }

    [Fact]
    public void NotPresentIsAbsenceNotSuppression()
    {
        // QUNS_NOT_PRESENT is a locked or screensavered workstation. It must not
        // read as "presenting", or a laptop left alone would burn the bounds.
        var signals = WithState(ShellNotificationState.NotPresent);
        Assert.Equal(SignalReading.Idle, signals.PresentingReading());
        Assert.Equal(SignalReading.Idle, signals.FocusReading());
        Assert.False(new WindowsUserSessionState(() => ShellNotificationState.NotPresent).IsActiveAndUnlocked);
    }

    [Fact]
    public void AFailedShellCallDoesNotDeclareTheUserAbsent()
    {
        // Failing closed on the session check would silence the agent forever on
        // any machine where the shell call fails. The interruption signals
        // already fail closed; this one must not.
        Assert.True(new WindowsUserSessionState(() => ShellNotificationState.Unknown).IsActiveAndUnlocked);
    }
}
