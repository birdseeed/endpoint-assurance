using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Patched.Shared.Interruption;

/// <summary>
/// PAT-1624: the Windows half of the never-interrupt gate's signal readers.
/// Content-equivalent with the macOS <c>SystemInterruptionSignals</c>: the same
/// four signals, the same tri-state, the same reason vocabulary, so the
/// findings contract stays platform-neutral even though the collection differs.
///
/// PRIVACY, NOT OPTIONAL. Everything here is evaluated as a boolean at decision
/// time and thrown away. Reading the ConsentStore means walking subkeys whose
/// names ARE application identities, and not one of them ever leaves this file:
/// no caller can ask which application held the camera, when, or for how long.
/// "Camera in use 14:02 to 15:30" is attendance monitoring and Patched does not
/// collect it.
///
/// FAIL CLOSED TOWARD SILENCE. A signal that cannot be read is treated as busy.
/// A delayed prompt costs a day. A window over a customer demo costs the account.
/// </summary>
public enum SignalReading
{
    Idle,
    Busy,
    Unreadable,
}

/// <summary>
/// Why the agent stayed quiet. Identical vocabulary to the macOS
/// <c>InterruptionReason</c>: an operator reading a suppression event should not
/// have to know which platform produced it.
/// </summary>
public enum InterruptionReason
{
    CameraInUse,
    MicrophoneInUse,
    Presenting,
    FocusOrDoNotDisturb,
    SignalUnreadable,
}

public static class InterruptionReasonCodes
{
    public static string Code(this InterruptionReason reason) => reason switch
    {
        InterruptionReason.CameraInUse         => "camera_in_use",
        InterruptionReason.MicrophoneInUse     => "microphone_in_use",
        InterruptionReason.Presenting          => "presenting",
        InterruptionReason.FocusOrDoNotDisturb => "focus_or_do_not_disturb",
        _                                      => "signal_unreadable",
    };
}

/// <summary>Injectable so the bounds can be tested without a real call.</summary>
public interface IInterruptionSignalSource
{
    SignalReading CameraReading();
    SignalReading MicrophoneReading();
    SignalReading PresentingReading();
    SignalReading FocusReading();
}

/// <summary>Is there actually somebody there? Locked or logged out is absence, not suppression.</summary>
public interface IUserSessionState
{
    bool IsActiveAndUnlocked { get; }
}

/// <summary>
/// The operating system's own shell notification state. Windows already answers
/// most of this question for us, which is why the gate leans on it rather than
/// enumerating windows the way the macOS side has to.
/// </summary>
public enum ShellNotificationState
{
    /// QUNS_NOT_PRESENT: screen saver, locked, or fast-user-switched away.
    NotPresent = 1,
    /// QUNS_BUSY: a full-screen application is running, or Presentation Settings are on.
    Busy = 2,
    /// QUNS_RUNNING_D3D_FULL_SCREEN: a full-screen Direct3D application.
    RunningD3DFullScreen = 3,
    /// QUNS_PRESENTATION_MODE: the user explicitly asked not to be disturbed.
    PresentationMode = 4,
    /// QUNS_ACCEPTS_NOTIFICATIONS: the only value that permits a window.
    AcceptsNotifications = 5,
    /// QUNS_QUIET_TIME: Focus Assist / Quiet Hours.
    QuietTime = 6,
    /// QUNS_APP: a Windows Store app is running full screen.
    RunningWindowsStoreApp = 7,
    /// Not a real QUNS value: the call failed and the answer is unknown.
    Unknown = 0,
}

[SupportedOSPlatform("windows")]
public sealed class WindowsInterruptionSignals : IInterruptionSignalSource
{
    private const string ConsentStoreBase =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\";

    /// <summary>Overridable so the shell state can be faked in a test.</summary>
    private readonly Func<ShellNotificationState> _shellState;

    public WindowsInterruptionSignals() : this(QueryShellNotificationState) { }

    internal WindowsInterruptionSignals(Func<ShellNotificationState> shellState) => _shellState = shellState;

    // ---- Camera and microphone -------------------------------------------
    //
    // An application holds the device when LastUsedTimeStart is non-zero and
    // LastUsedTimeStop is zero. Needed on top of the shell state because a
    // windowed Teams call does not reliably set a busy notification state.

    public SignalReading CameraReading()    => ConsentStoreReading("webcam");
    public SignalReading MicrophoneReading() => ConsentStoreReading("microphone");

    private static SignalReading ConsentStoreReading(string capability)
    {
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(ConsentStoreBase + capability);
            // The capability has never been used on this device. That is a
            // clear answer, not an unreadable one.
            if (root is null) return SignalReading.Idle;

            if (AnyHolder(root, skipNonPackaged: true)) return SignalReading.Busy;

            using var nonPackaged = root.OpenSubKey("NonPackaged");
            if (nonPackaged is not null && AnyHolder(nonPackaged, skipNonPackaged: false))
                return SignalReading.Busy;

            return SignalReading.Idle;
        }
        catch
        {
            // Access denied, a hive that will not open, anything at all: assume busy.
            return SignalReading.Unreadable;
        }
    }

    /// <summary>
    /// True when any child of <paramref name="parent"/> currently holds the
    /// device. The subkey names are application monikers; this method reads
    /// them to open the key and discards them. Nothing is returned but a bool.
    /// </summary>
    private static bool AnyHolder(RegistryKey parent, bool skipNonPackaged)
    {
        foreach (var name in parent.GetSubKeyNames())
        {
            if (skipNonPackaged && string.Equals(name, "NonPackaged", StringComparison.OrdinalIgnoreCase))
                continue;

            using var child = parent.OpenSubKey(name);
            if (child is null) continue;

            var start = ReadQuadWord(child, "LastUsedTimeStart");
            var stop  = ReadQuadWord(child, "LastUsedTimeStop");
            if (start is > 0 && stop == 0) return true;
        }
        return false;
    }

    private static long? ReadQuadWord(RegistryKey key, string name) => key.GetValue(name) switch
    {
        long l  => l,
        int i   => i,
        _       => null,
    };

    // ---- Presenting and Focus --------------------------------------------

    /// <summary>
    /// Full-screen Direct3D, Presentation Settings, or any full-screen
    /// application. Keynote's Windows equivalents all land here.
    /// </summary>
    public SignalReading PresentingReading() => _shellState() switch
    {
        ShellNotificationState.Busy                   => SignalReading.Busy,
        ShellNotificationState.RunningD3DFullScreen   => SignalReading.Busy,
        ShellNotificationState.PresentationMode       => SignalReading.Busy,
        ShellNotificationState.RunningWindowsStoreApp => SignalReading.Busy,
        ShellNotificationState.Unknown                => SignalReading.Unreadable,
        _                                             => SignalReading.Idle,
    };

    /// <summary>Focus Assist / Quiet Hours. Treat as do not interrupt.</summary>
    public SignalReading FocusReading() => _shellState() switch
    {
        ShellNotificationState.QuietTime => SignalReading.Busy,
        ShellNotificationState.Unknown   => SignalReading.Unreadable,
        _                                => SignalReading.Idle,
    };

    // ---- SHQueryUserNotificationState ------------------------------------

    internal static ShellNotificationState QueryShellNotificationState()
    {
        try
        {
            var hr = SHQueryUserNotificationState(out var state);
            if (hr != 0) return ShellNotificationState.Unknown;
            return Enum.IsDefined(typeof(ShellNotificationState), state) && state != 0
                ? (ShellNotificationState)state
                : ShellNotificationState.Unknown;
        }
        catch (DllNotFoundException)   { return ShellNotificationState.Unknown; }
        catch (EntryPointNotFoundException) { return ShellNotificationState.Unknown; }
    }

    [DllImport("shell32.dll", ExactSpelling = true)]
    private static extern int SHQueryUserNotificationState(out int state);
}

/// <summary>
/// QUNS_NOT_PRESENT is Windows' own answer to "is the user actually here":
/// screen saver, locked workstation, or switched away. Absence, not suppression.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsUserSessionState : IUserSessionState
{
    private readonly Func<ShellNotificationState> _shellState;

    public WindowsUserSessionState() : this(WindowsInterruptionSignals.QueryShellNotificationState) { }

    internal WindowsUserSessionState(Func<ShellNotificationState> shellState) => _shellState = shellState;

    public bool IsActiveAndUnlocked
    {
        get
        {
            var state = _shellState();
            // Unknown means the call failed, not that nobody is here. Treating
            // it as absent would silence the agent permanently on any machine
            // where the shell call fails; the interruption signals themselves
            // already fail closed, and this one must not.
            return state != ShellNotificationState.NotPresent;
        }
    }
}
