using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1747: the pure screen saver decision. User Configuration policy (Group Policy,
/// Intune) lives in the console user's hive, so a device configured that way must not
/// report Unknown, and no missing or unreadable hive may produce a value.
/// </summary>
public class ScreensaverPolicyResolverTests
{
    private const string Enabled = "screensaver_enabled";
    private const string Password = "screensaver_password_required";
    private const string Timeout = "screensaver_timeout_seconds";

    private static DesktopKey Key(object? active = null, object? secure = null, object? timeout = null, object? exe = null) =>
        new(DesktopKeyState.Present, active, secure, timeout, exe);

    private const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string UserPolicyPath = @"HKEY_USERS\" + Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop";
    private const string UserPreferencePath = @"HKEY_USERS\" + Sid + @"\Control Panel\Desktop";
    private const string MachinePolicyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop";

    private static ScreensaverSnapshot Loaded(DesktopKey? userPolicy = null, DesktopKey? userPreference = null) =>
        new(ConsoleUserHive.Available,
            userPolicy ?? DesktopKey.Absent,
            userPreference ?? DesktopKey.Absent);

    /// <summary>
    /// A whole device registry keyed by full path, HKLM included. The snapshot is
    /// built from it the way the Service builds it, so a resolver that consulted
    /// HKLM would see these values.
    /// </summary>
    private static (Dictionary<string, object> Signals, List<string> Requested) EvaluateDevice(Dictionary<string, DesktopKey> registry)
    {
        var requested = new List<string>();
        var snapshot = ScreensaverPolicyResolver.BuildSnapshot(ConsoleUserHive.Available, Sid, path =>
        {
            requested.Add(path);
            return registry.TryGetValue(path, out var key) ? key : DesktopKey.Absent;
        });
        return (ScreensaverPolicyResolver.Evaluate(snapshot), requested);
    }

    // The WIN-STAGING VM's own preference key: ScreenSaveActive=1 with no
    // SCRNSAVE.EXE, ScreenSaverIsSecure or ScreenSaveTimeOut (screen saver "(None)").
    private static DesktopKey WinStagingPreference() => Key(active: "1");

    private static void AssertSignal(Dictionary<string, object> s, string key, object? value, string source)
    {
        if (value is null)
            Assert.False(s.ContainsKey(key), $"{key} should be omitted");
        else
            Assert.Equal(value, s[key]);
        Assert.Equal(source, s[key + "_source"]);
    }

    [Fact]
    public void UserPolicy_WinStagingShape_ReportsPolicyValues()
    {
        // The exact state set on the VM: User Configuration policy values (REG_SZ)
        // over the default preference key.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(active: "1", secure: "1", timeout: "900"),
            userPreference: WinStagingPreference()));

        AssertSignal(s, Enabled, "Yes", "user_policy");
        AssertSignal(s, Password, "Yes", "user_policy");
        AssertSignal(s, Timeout, 900, "user_policy");
    }

    [Fact]
    public void UserPolicy_BeatsUserPreference()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(active: "1", secure: "1", timeout: "600"),
            userPreference: Key(active: "0", secure: "0", timeout: "3600", exe: @"C:\Windows\system32\scrnsave.scr")));

        AssertSignal(s, Enabled, "Yes", "user_policy");
        AssertSignal(s, Password, "Yes", "user_policy");
        AssertSignal(s, Timeout, 600, "user_policy");
    }

    [Fact]
    public void UserPolicy_NoValue_BeatsPreferenceYes()
    {
        // A policy that says "0" must not be overridden by a user who turned it on.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(active: "0", secure: "0"),
            userPreference: Key(active: "1", secure: "1", exe: "scrnsave.scr")));

        AssertSignal(s, Enabled, "No", "user_policy");
        AssertSignal(s, Password, "No", "user_policy");
    }

    [Fact]
    public void PreferenceUsed_WhenNoPolicy()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPreference: Key(active: "1", secure: "1", timeout: "600", exe: @"C:\Windows\system32\scrnsave.scr")));

        AssertSignal(s, Enabled, "Yes", "user_preference");
        AssertSignal(s, Password, "Yes", "user_preference");
        AssertSignal(s, Timeout, 600, "user_preference");
    }

    [Fact]
    public void PreferenceActiveWithoutExecutable_IsNotEnabled()
    {
        // Windows keeps ScreenSaveActive=1 with the screen saver set to "(None)";
        // that alone is not a running screen saver.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPreference: WinStagingPreference()));

        AssertSignal(s, Enabled, "No", "user_preference");
        AssertSignal(s, Password, "NotConfigured", "not_set");
        AssertSignal(s, Timeout, "NotConfigured", "not_set");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void PreferenceActiveWithBlankExecutable_IsNotEnabled(string exe)
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPreference: Key(active: "1", exe: exe)));

        AssertSignal(s, Enabled, "No", "user_preference");
    }

    [Fact]
    public void PreferenceActive_WithPolicyForcedExecutable_IsEnabled()
    {
        // "Force specific screen saver" sets SCRNSAVE.EXE under the user policy key only.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(exe: "scrnsave.scr"),
            userPreference: Key(active: "1")));

        AssertSignal(s, Enabled, "Yes", "user_preference");
    }

    [Fact]
    public void PerValueResolution_MixesSources()
    {
        // A GPO that sets only the timeout and the password requirement leaves
        // ScreenSaveActive to the user.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(secure: "1", timeout: "900"),
            userPreference: Key(active: "1", exe: "scrnsave.scr")));

        AssertSignal(s, Enabled, "Yes", "user_preference");
        AssertSignal(s, Password, "Yes", "user_policy");
        AssertSignal(s, Timeout, 900, "user_policy");
    }

    [Theory]
    [InlineData(ConsoleUserHive.NoConsoleUser, "no_console_user")]
    [InlineData(ConsoleUserHive.NotLoaded, "user_hive_not_loaded")]
    [InlineData(ConsoleUserHive.ReadFailed, "read_failed")]
    public void UserHiveUnavailable_IsUnknown(ConsoleUserHive hive, string source)
    {
        var s = ScreensaverPolicyResolver.Evaluate(new ScreensaverSnapshot(
            hive,
            Key(active: "1", secure: "1", timeout: "900"),
            Key(active: "1", secure: "1", timeout: "900", exe: "scrnsave.scr")));

        AssertSignal(s, Enabled, "Unknown", source);
        AssertSignal(s, Password, "Unknown", source);
        AssertSignal(s, Timeout, null, source);
    }

    [Fact]
    public void MachinePolicyValues_WithNoUserValues_AreNotSet_NotYes()
    {
        // HKLM is not read: Windows applies these settings from the user's Policies
        // hive only, so an HKLM value is not evidence of what the user gets.
        var (s, requested) = EvaluateDevice(new Dictionary<string, DesktopKey>
        {
            [MachinePolicyPath] = Key(active: "1", secure: "1", timeout: "900", exe: "scrnsave.scr"),
        });

        AssertSignal(s, Enabled, "NotConfigured", "not_set");
        AssertSignal(s, Password, "NotConfigured", "not_set");
        AssertSignal(s, Timeout, "NotConfigured", "not_set");
        Assert.Equal(new[] { UserPolicyPath, UserPreferencePath }, requested);
    }

    [Fact]
    public void StrayMachinePolicyYes_DoesNotOverrideUserPreferenceNo()
    {
        var (s, _) = EvaluateDevice(new Dictionary<string, DesktopKey>
        {
            [MachinePolicyPath] = Key(active: "1", secure: "1", timeout: "600"),
            [UserPreferencePath] = Key(active: "0", secure: "0", timeout: "3600", exe: "scrnsave.scr"),
        });

        AssertSignal(s, Enabled, "No", "user_preference");
        AssertSignal(s, Password, "No", "user_preference");
        AssertSignal(s, Timeout, 3600, "user_preference");
    }

    [Fact]
    public void BuildSnapshot_ReadsUserPolicyAndPreferencePaths()
    {
        var (s, _) = EvaluateDevice(new Dictionary<string, DesktopKey>
        {
            [UserPolicyPath] = Key(secure: "1", timeout: "900"),
            [UserPreferencePath] = Key(active: "1", exe: "scrnsave.scr"),
        });

        AssertSignal(s, Enabled, "Yes", "user_preference");
        AssertSignal(s, Password, "Yes", "user_policy");
        AssertSignal(s, Timeout, 900, "user_policy");
    }

    [Theory]
    [InlineData(ConsoleUserHive.NoConsoleUser)]
    [InlineData(ConsoleUserHive.NotLoaded)]
    [InlineData(ConsoleUserHive.ReadFailed)]
    public void BuildSnapshot_UnavailableHive_NeverCallsReader(ConsoleUserHive hive)
    {
        var snapshot = ScreensaverPolicyResolver.BuildSnapshot(hive, Sid,
            _ => throw new InvalidOperationException("reader must not be called"));

        Assert.Equal(hive, snapshot.UserHive);
        Assert.Equal("Unknown", ScreensaverPolicyResolver.Evaluate(snapshot)[Enabled]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void BuildSnapshot_AvailableWithoutSid_IsReadFailed(string? sid)
    {
        var snapshot = ScreensaverPolicyResolver.BuildSnapshot(ConsoleUserHive.Available, sid,
            _ => throw new InvalidOperationException("reader must not be called"));

        Assert.Equal(ConsoleUserHive.ReadFailed, snapshot.UserHive);
    }

    [Fact]
    public void NullSnapshot_IsUnknown()
    {
        var s = ScreensaverPolicyResolver.Evaluate(null);

        AssertSignal(s, Enabled, "Unknown", "read_failed");
        AssertSignal(s, Password, "Unknown", "read_failed");
        AssertSignal(s, Timeout, null, "read_failed");
    }

    [Fact]
    public void NothingSetAnywhere_IsNotConfigured()
    {
        // PAT-1767: both tiers were read and neither key exists. That is a successful
        // read of an unset screen saver, not a failed one.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded());

        AssertSignal(s, Enabled, "NotConfigured", "not_set");
        AssertSignal(s, Password, "NotConfigured", "not_set");
        AssertSignal(s, Timeout, "NotConfigured", "not_set");
    }

    [Fact]
    public void KeysPresentWithoutValues_AreNotConfigured()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: Key(), userPreference: Key()));

        AssertSignal(s, Enabled, "NotConfigured", "not_set");
        AssertSignal(s, Password, "NotConfigured", "not_set");
        AssertSignal(s, Timeout, "NotConfigured", "not_set");
    }

    [Fact]
    public void FailedPreferenceRead_AfterAbsentPolicy_IsUnknown_NeverNotConfigured()
    {
        // The policy tier is absent, so resolution reaches the preference tier, whose
        // read failed. Absent-then-failed must not collapse into "nothing set".
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: DesktopKey.Absent, userPreference: DesktopKey.Failed));

        foreach (var key in new[] { Enabled, Password, Timeout })
            Assert.NotEqual("NotConfigured", s.GetValueOrDefault(key));
        AssertSignal(s, Enabled, "Unknown", "read_failed");
        AssertSignal(s, Password, "Unknown", "read_failed");
        AssertSignal(s, Timeout, null, "read_failed");
    }

    [Fact]
    public void FailedUserPolicyRead_IsUnknown_NotPreference()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: DesktopKey.Failed,
            userPreference: Key(active: "1", secure: "1", timeout: "600", exe: "scrnsave.scr")));

        AssertSignal(s, Enabled, "Unknown", "read_failed");
        AssertSignal(s, Password, "Unknown", "read_failed");
        AssertSignal(s, Timeout, null, "read_failed");
    }

    [Fact]
    public void FailedPreferenceRead_IsUnknown()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPreference: DesktopKey.Failed));

        AssertSignal(s, Enabled, "Unknown", "read_failed");
        AssertSignal(s, Password, "Unknown", "read_failed");
        AssertSignal(s, Timeout, null, "read_failed");
    }

    [Fact]
    public void DwordValues_AreAccepted()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: Key(active: 1, secure: 0, timeout: 300)));

        AssertSignal(s, Enabled, "Yes", "user_policy");
        AssertSignal(s, Password, "No", "user_policy");
        AssertSignal(s, Timeout, 300, "user_policy");
    }

    [Fact]
    public void UnusablePolicyValue_IsUnknown_AndDoesNotFallThrough()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(active: new byte[] { 1 }, secure: "yes", timeout: "fifteen"),
            userPreference: Key(active: "1", secure: "1", timeout: "600", exe: "scrnsave.scr")));

        AssertSignal(s, Enabled, "Unknown", "user_policy");
        AssertSignal(s, Password, "Unknown", "user_policy");
        AssertSignal(s, Timeout, null, "user_policy");
    }

    [Fact]
    public void EmptyPolicyString_IsUnknown_AndDoesNotFallThrough()
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(active: "", secure: " "),
            userPreference: Key(active: "1", secure: "1", exe: "scrnsave.scr")));

        AssertSignal(s, Enabled, "Unknown", "user_policy");
        AssertSignal(s, Password, "Unknown", "user_policy");
    }

    // PAT-1761: ScreenSaveTimeOut=0 means the screen saver never starts, and a negative
    // value cannot mean it starts within 900 seconds. Both would pass cis_win_19_1_3_4
    // (lte 900), so they are sent as the estate's "never" value, 99999.
    [Theory]
    [InlineData("0")]
    [InlineData(0)]
    [InlineData("-1")]
    [InlineData(-1)]
    public void UserPolicyZeroOrNegativeTimeout_IsSentAsNever_WithUserPolicySource(object zero)
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(
            userPolicy: Key(timeout: zero),
            userPreference: Key(timeout: "600")));

        AssertSignal(s, Timeout, 99999, "user_policy");
    }

    [Theory]
    [InlineData("0")]
    [InlineData(0)]
    [InlineData("-1")]
    [InlineData(-1)]
    public void UserPreferenceZeroOrNegativeTimeout_IsSentAsNever_WithUserPreferenceSource(object zero)
    {
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPreference: Key(timeout: zero)));

        AssertSignal(s, Timeout, 99999, "user_preference");
    }

    [Theory]
    [InlineData("600", 600)]
    [InlineData("900", 900)]
    [InlineData(600, 600)]
    [InlineData(900, 900)]
    public void NonZeroTimeout_IsSentAsRead(object raw, int expected)
    {
        AssertSignal(ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: Key(timeout: raw))), Timeout, expected, "user_policy");
        AssertSignal(ScreensaverPolicyResolver.Evaluate(Loaded(userPreference: Key(timeout: raw))), Timeout, expected, "user_preference");
    }

    [Fact]
    public void NeverSentinel_MatchesInactivityLimitSentinel()
    {
        Assert.Equal(99999, ScreensaverPolicyResolver.NeverTimeoutSentinel);
        var inactivity = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead> { ["InactivityTimeoutSecs"] = RegistryRead.Present(0) });
        Assert.Equal(ScreensaverPolicyResolver.NeverTimeoutSentinel, inactivity["machine_inactivity_limit_seconds"]);
    }

    [Fact]
    public void ZeroOrNegativeTimeout_IsNeverEmitted_FromAnyTier()
    {
        var zeros = new object[] { "0", 0, 0L, " 0 ", "00", "-0", "+0", "-1", -1, -1L, "-900" };
        var otherTier = new DesktopKey?[] { null, DesktopKey.Absent, Key(), Key(timeout: "600"), Key(timeout: "0") };
        var cases = 0;

        foreach (var zero in zeros)
        {
            foreach (var other in otherTier)
            {
                // Zero or negative at the policy tier, anything at the preference tier.
                var policy = ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: Key(timeout: zero), userPreference: other));
                AssertSignal(policy, Timeout, 99999, "user_policy");

                // Nothing usable at the policy tier, zero or negative at the preference tier.
                if (other is null || other.ScreenSaveTimeOut is null)
                {
                    var pref = ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: other, userPreference: Key(timeout: zero)));
                    AssertSignal(pref, Timeout, 99999, "user_preference");
                }
                cases += 1;
            }
        }

        Assert.Equal(zeros.Length * otherTier.Length, cases);
    }

    [Fact]
    public void SignalKeys_MatchServerRules()
    {
        // cis_win_19_1_3_2/3/4 consume exactly these keys and value shapes.
        var s = ScreensaverPolicyResolver.Evaluate(Loaded(userPolicy: Key(active: "1", secure: "1", timeout: "900")));

        Assert.IsType<string>(s["screensaver_enabled"]);
        Assert.IsType<string>(s["screensaver_password_required"]);
        Assert.IsType<int>(s["screensaver_timeout_seconds"]);
        Assert.Equal(6, s.Count);
    }
}
