namespace Patched.Shared.Compliance;

/// <summary>How a single registry key read ended.</summary>
public enum DesktopKeyState
{
    /// <summary>The key does not exist.</summary>
    Absent,
    /// <summary>The key was opened and its values read.</summary>
    Present,
    /// <summary>Opening or reading the key threw.</summary>
    Failed,
}

/// <summary>
/// One <c>Control Panel\Desktop</c> key (policy or preference), reduced to the raw
/// values the screen saver signals read. A null value means the value was absent.
/// REG_SZ arrives as string, REG_DWORD as int; both are accepted, and a value of
/// any other type reads as "Unknown".
/// </summary>
public sealed record DesktopKey(
    DesktopKeyState State,
    object? ScreenSaveActive = null,
    object? ScreenSaverIsSecure = null,
    object? ScreenSaveTimeOut = null,
    object? ScreenSaverExecutable = null)
{
    public static DesktopKey Absent { get; } = new(DesktopKeyState.Absent);
    public static DesktopKey Failed { get; } = new(DesktopKeyState.Failed);
}

/// <summary>Whether the interactive console user's registry hive could be reached.</summary>
public enum ConsoleUserHive
{
    /// <summary>A console user was resolved and their hive is loaded under HKEY_USERS.</summary>
    Available,
    /// <summary>Nobody is logged on at the physical console.</summary>
    NoConsoleUser,
    /// <summary>A console user was resolved but their hive is not loaded under HKEY_USERS.</summary>
    NotLoaded,
    /// <summary>Resolving the console user or opening their hive threw or returned an error.</summary>
    ReadFailed,
}

/// <summary>
/// Everything the screen saver decision reads. The user keys are only meaningful
/// when <see cref="UserHive"/> is <see cref="ConsoleUserHive.Available"/>.
/// </summary>
public sealed record ScreensaverSnapshot(
    ConsoleUserHive UserHive,
    DesktopKey UserPolicy,
    DesktopKey UserPreference);

/// <summary>
/// Reads one registry key by its full path, for example
/// <c>HKEY_USERS\S-1-5-21-...\Control Panel\Desktop</c>.
/// </summary>
public delegate DesktopKey DesktopKeyReader(string fullPath);

/// <summary>
/// PAT-1747: pure decision for the Windows screen saver compliance signals
/// (server rules <c>cis_win_19_1_3_2_screensaver_enabled</c>,
/// <c>cis_win_19_1_3_3_screensaver_password</c> and
/// <c>cis_win_19_1_3_4_screensaver_timeout</c>). The Service reads the registry
/// (Windows-only) and passes a snapshot here; this class is API-free and
/// unit-testable off-box.
///
/// Group Policy and Intune deliver these settings as User Configuration
/// (Control Panel &gt; Personalization), which lands in the user's own
/// <c>HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop</c>. The
/// Service runs as LocalSystem, so it reads that key through
/// <c>HKEY_USERS\&lt;console user SID&gt;</c>. The user's own setting lives in
/// <c>HKCU\Control Panel\Desktop</c>.
///
/// Precedence, resolved per value, highest first:
/// <list type="number">
///   <item><c>user_policy</c>: HKU\&lt;SID&gt;\Software\Policies\...\Control Panel\Desktop.
///         The screen saver ADMX settings are User Configuration policies, so this
///         is where Group Policy and Intune put the value that applies to this user.</item>
///   <item><c>user_preference</c>: HKU\&lt;SID&gt;\Control Panel\Desktop, what the user
///         chose in Settings.</item>
/// </list>
/// Nothing else decides the value. Each value is resolved on its own because a policy
/// may set some values and leave the rest to the user (for example only
/// ScreenSaveTimeOut).
///
/// HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop is deliberately not
/// read. These settings exist only under User Configuration in the ADMX, Windows reads
/// them from the user's Policies hive, and nothing is known to apply an HKLM value to a
/// user session. A value Windows does not enforce is not evidence: ranked above the
/// preference, a stray HKLM 1 would pass a device whose user has 0. Agents before
/// PAT-1747 read only that key. Recording it can come back with device evidence that
/// Windows honours it.
///
/// Absence requires authority. With no console user, a hive that is not loaded, or
/// a failed read, every signal is "Unknown" and no timeout is sent. A failed read at a
/// tier the resolution reaches is also "Unknown"; it never falls through to a lower
/// tier. PAT-1767: when both tiers were read and neither carries the value
/// (<c>not_set</c>), the signal is "NotConfigured", timeout included, so the server
/// rule decides what an unset screen saver means; it is never "Unknown".
///
/// Preference semantics differ from policy for ScreenSaveActive. Windows keeps
/// ScreenSaveActive=1 in the user's preference key even when the screen saver is
/// "(None)" (seen on the WIN-STAGING VM, which has no SCRNSAVE.EXE), so a preference
/// ScreenSaveActive=1 counts as enabled only when a non-empty SCRNSAVE.EXE is set at
/// either tier. Policy ScreenSaveActive keeps its existing meaning, which matches the
/// CIS 19.1.3.2 audit of the policy value.
///
/// ScreenSaveTimeOut=0 means the screen saver never starts, and a negative value cannot
/// mean it starts within any number of seconds (PAT-1761). The server rule compares
/// <c>lte 900</c>, which both would pass, so a resolved timeout of 0 or less is sent as
/// <see cref="NeverTimeoutSentinel"/> (99999) whichever tier it came from, and its
/// <c>_source</c> still names that tier. This is the estate's existing "never" value:
/// <c>machine_inactivity_limit_seconds</c> in <see cref="SecurityOptionsParser"/> (which
/// also maps 0 or less) and the macOS <c>idleTime</c> 0 use it too. Positive integers are
/// sent as read, and a value that is not an integer still sends no timeout.
/// </summary>
public static class ScreensaverPolicyResolver
{
    public const string EnabledKey = "screensaver_enabled";
    public const string PasswordRequiredKey = "screensaver_password_required";
    public const string TimeoutKey = "screensaver_timeout_seconds";

    public const string SourceSuffix = "_source";

    public const string SourceUserPolicy = "user_policy";
    public const string SourceUserPreference = "user_preference";
    /// <summary>Neither the user policy nor the user preference carries the value.</summary>
    public const string SourceNotSet = "not_set";
    public const string SourceNoConsoleUser = "no_console_user";
    public const string SourceUserHiveNotLoaded = "user_hive_not_loaded";
    public const string SourceReadFailed = "read_failed";

    /// <summary>
    /// Sent in place of a ScreenSaveTimeOut of 0 ("never") or less so <c>lte 900</c> fails. Same
    /// value as <c>NoInactivityLimitSentinel</c> in <see cref="SecurityOptionsParser"/>.
    /// </summary>
    public const int NeverTimeoutSentinel = 99999;

    private const string Unknown = ComplianceSignalValue.Unknown;
    private const string NotConfigured = ComplianceSignalValue.NotConfigured;
    private const string UnsupportedType = "\u0000unsupported-registry-type";

    public const string UsersHive = "HKEY_USERS";
    public const string PolicySubPath = @"Software\Policies\Microsoft\Windows\Control Panel\Desktop";
    public const string PreferenceSubPath = @"Control Panel\Desktop";

    /// <summary>
    /// Builds the snapshot from the console user's hive. The reader is asked only for
    /// <c>HKEY_USERS\&lt;sid&gt;\</c> policy and preference paths, and not at all unless
    /// <paramref name="userHive"/> is <see cref="ConsoleUserHive.Available"/>.
    /// </summary>
    public static ScreensaverSnapshot BuildSnapshot(ConsoleUserHive userHive, string? sid, DesktopKeyReader read)
    {
        if (userHive != ConsoleUserHive.Available)
            return new ScreensaverSnapshot(userHive, DesktopKey.Absent, DesktopKey.Absent);
        if (string.IsNullOrEmpty(sid))
            return new ScreensaverSnapshot(ConsoleUserHive.ReadFailed, DesktopKey.Absent, DesktopKey.Absent);

        return new ScreensaverSnapshot(
            ConsoleUserHive.Available,
            read($@"{UsersHive}\{sid}\{PolicySubPath}"),
            read($@"{UsersHive}\{sid}\{PreferenceSubPath}"));
    }

    /// <summary>
    /// Returns the screen saver signals plus a <c>&lt;signal&gt;_source</c> companion for
    /// each. <c>screensaver_timeout_seconds</c> is "NotConfigured" when neither tier sets
    /// it and is omitted when no integer was otherwise resolved; a resolved 0 or less is
    /// sent as <see cref="NeverTimeoutSentinel"/>.
    /// </summary>
    public static Dictionary<string, object> Evaluate(ScreensaverSnapshot? snapshot)
    {
        var s = new Dictionary<string, object>();

        var hiveFailure = snapshot is null
            ? SourceReadFailed
            : snapshot.UserHive switch
            {
                ConsoleUserHive.Available => null,
                ConsoleUserHive.NoConsoleUser => SourceNoConsoleUser,
                ConsoleUserHive.NotLoaded => SourceUserHiveNotLoaded,
                _ => SourceReadFailed,
            };

        if (hiveFailure is not null)
        {
            s[EnabledKey] = Unknown;
            s[EnabledKey + SourceSuffix] = hiveFailure;
            s[PasswordRequiredKey] = Unknown;
            s[PasswordRequiredKey + SourceSuffix] = hiveFailure;
            s[TimeoutKey + SourceSuffix] = hiveFailure;
            return s;
        }

        var snap = snapshot!;

        var (active, activeSource) = Resolve(snap, k => Normalise(k.ScreenSaveActive));
        s[EnabledKey] = EvaluateEnabled(snap, active, activeSource);
        s[EnabledKey + SourceSuffix] = activeSource;

        var (secure, secureSource) = Resolve(snap, k => Normalise(k.ScreenSaverIsSecure));
        s[PasswordRequiredKey] = secureSource == SourceNotSet
            ? NotConfigured
            : secure switch
            {
                "1" => "Yes",
                "0" => "No",
                _ => Unknown,
            };
        s[PasswordRequiredKey + SourceSuffix] = secureSource;

        var (timeout, timeoutSource) = Resolve(snap, k => Normalise(k.ScreenSaveTimeOut));
        if (timeoutSource == SourceNotSet)
            s[TimeoutKey] = NotConfigured;
        else if (int.TryParse(timeout, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var secs))
            s[TimeoutKey] = secs <= 0 ? NeverTimeoutSentinel : secs;
        s[TimeoutKey + SourceSuffix] = timeoutSource;

        return s;
    }

    private static string EvaluateEnabled(ScreensaverSnapshot snap, string? active, string source)
    {
        if (source == SourceNotSet)
            return NotConfigured;

        if (source == SourceUserPreference)
        {
            if (active == "0")
                return "No";
            if (active != "1")
                return Unknown;

            var (exe, exeSource) = Resolve(snap, k => NormaliseExecutable(k.ScreenSaverExecutable));
            if (exeSource == SourceReadFailed)
                return Unknown;
            return exe is not null ? "Yes" : "No";
        }

        return active switch
        {
            "1" => "Yes",
            "0" => "No",
            _ => Unknown,
        };
    }

    /// <summary>
    /// Walks user policy, then user preference, and returns the first
    /// value found with its source. A failed key read reached before a value is found
    /// returns (null, read_failed) rather than consulting a lower tier.
    /// </summary>
    private static (string? Value, string Source) Resolve(ScreensaverSnapshot snap, Func<DesktopKey, string?> pick)
    {
        foreach (var (key, source) in Tiers(snap))
        {
            if (key is null || key.State == DesktopKeyState.Failed)
                return (null, SourceReadFailed);
            if (key.State != DesktopKeyState.Present)
                continue;
            var value = pick(key);
            if (value is not null)
                return (value, source);
        }
        return (null, SourceNotSet);
    }

    private static IEnumerable<(DesktopKey? Key, string Source)> Tiers(ScreensaverSnapshot snap)
    {
        yield return (snap.UserPolicy, SourceUserPolicy);
        yield return (snap.UserPreference, SourceUserPreference);
    }

    /// <summary>
    /// Converts a raw registry value to trimmed text. REG_SZ and REG_DWORD are
    /// accepted. Null means the value is absent. A value of any other type is
    /// present but unusable, so it returns a marker that matches no expected value:
    /// it stops the precedence walk and reads as "Unknown" instead of letting a
    /// lower tier decide.
    /// </summary>
    internal static string? Normalise(object? value) => value switch
    {
        null => null,
        string str => str.Trim(),
        int i => i.ToString(System.Globalization.CultureInfo.InvariantCulture),
        long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
        _ => UnsupportedType,
    };

    /// <summary>
    /// SCRNSAVE.EXE is a file name; an empty or whitespace name selects no screen
    /// saver, so it counts as absent at that tier.
    /// </summary>
    private static string? NormaliseExecutable(object? value) =>
        value is string str && !string.IsNullOrWhiteSpace(str) ? str.Trim() : null;
}
