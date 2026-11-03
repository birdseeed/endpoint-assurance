using Microsoft.Win32;
using Patched.Service;
using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1747: the registry wiring behind the screen saver signals. Production passes
/// HKEY_USERS; these tests point the users root at a scratch key under the test
/// process's own HKCU so the key paths and value names are exercised against a real
/// registry without touching machine or other users' state. HKLM is never read, so
/// there is no machine root to inject. Windows-only.
/// </summary>
public sealed class ComplianceCollectorScreensaverRegistryTests : IDisposable
{
    private const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private readonly string _scratchPath = $@"Software\PatchedTests\PAT-1747\{Guid.NewGuid():N}";

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows()) return;
        Registry.CurrentUser.DeleteSubKeyTree(_scratchPath, throwOnMissingSubKey: false);
    }

    private RegistryKey CreateUsersRoot() => Registry.CurrentUser.CreateSubKey(_scratchPath + @"\users");

    private static void SetValues(RegistryKey root, string path, params (string Name, object Value, RegistryValueKind Kind)[] values)
    {
        using var key = root.CreateSubKey(path);
        foreach (var (name, value, kind) in values)
            key.SetValue(name, value, kind);
    }

    [Fact]
    public void UserPolicyInConsoleUserHive_IsRead_AndBeatsPreference()
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var users = CreateUsersRoot())
        {
            // The WIN-STAGING state: REG_SZ policy values over a "(None)" preference.
            SetValues(users, Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                ("ScreenSaveActive", "1", RegistryValueKind.String),
                ("ScreenSaverIsSecure", "1", RegistryValueKind.String),
                ("ScreenSaveTimeOut", "900", RegistryValueKind.String));
            SetValues(users, Sid + @"\Control Panel\Desktop",
                ("ScreenSaveActive", "0", RegistryValueKind.String),
                ("ScreenSaveTimeOut", "3600", RegistryValueKind.String));

            var snapshot = ComplianceCollector.ReadScreensaverSnapshot(
                users, new ConsoleUserLookup(ConsoleUserLookupStatus.Resolved, Sid));

            Assert.Equal(ConsoleUserHive.Available, snapshot.UserHive);
            Assert.Equal(DesktopKeyState.Present, snapshot.UserPolicy.State);
            Assert.Equal(DesktopKeyState.Present, snapshot.UserPreference.State);

            var s = ScreensaverPolicyResolver.Evaluate(snapshot);
            Assert.Equal("Yes", s["screensaver_enabled"]);
            Assert.Equal("user_policy", s["screensaver_enabled_source"]);
            Assert.Equal("Yes", s["screensaver_password_required"]);
            Assert.Equal(900, s["screensaver_timeout_seconds"]);
            Assert.Equal("user_policy", s["screensaver_timeout_seconds_source"]);
        }
    }

    [Fact]
    public void PreferenceIsReadFromItsPath()
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var users = CreateUsersRoot())
        {
            SetValues(users, Sid + @"\Control Panel\Desktop",
                ("ScreenSaverIsSecure", 1, RegistryValueKind.DWord),
                ("ScreenSaveActive", "1", RegistryValueKind.String),
                ("ScreenSaveTimeOut", "600", RegistryValueKind.String),
                ("SCRNSAVE.EXE", @"C:\Windows\system32\scrnsave.scr", RegistryValueKind.String));

            var s = ScreensaverPolicyResolver.Evaluate(ComplianceCollector.ReadScreensaverSnapshot(
                users, new ConsoleUserLookup(ConsoleUserLookupStatus.Resolved, Sid)));

            Assert.Equal("Yes", s["screensaver_enabled"]);
            Assert.Equal("user_preference", s["screensaver_enabled_source"]);
            Assert.Equal("Yes", s["screensaver_password_required"]);
            Assert.Equal("user_preference", s["screensaver_password_required_source"]);
            Assert.Equal(600, s["screensaver_timeout_seconds"]);
            Assert.Equal("user_preference", s["screensaver_timeout_seconds_source"]);
        }
    }

    [Fact]
    public void ConsoleUserHiveNotLoaded_IsNotLoaded()
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var users = CreateUsersRoot())
        {
            // A different user's hive is loaded; the console user's is not.
            SetValues(users, @"S-1-5-21-9-9-9-1002\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                ("ScreenSaveActive", "1", RegistryValueKind.String));

            var snapshot = ComplianceCollector.ReadScreensaverSnapshot(
                users, new ConsoleUserLookup(ConsoleUserLookupStatus.Resolved, Sid));

            Assert.Equal(ConsoleUserHive.NotLoaded, snapshot.UserHive);
            var s = ScreensaverPolicyResolver.Evaluate(snapshot);
            Assert.Equal("Unknown", s["screensaver_enabled"]);
            Assert.Equal("user_hive_not_loaded", s["screensaver_enabled_source"]);
            Assert.False(s.ContainsKey("screensaver_timeout_seconds"));
        }
    }

    [Fact]
    public void NoConsoleUser_IsUnknown()
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var users = CreateUsersRoot())
        {
            SetValues(users, Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                ("ScreenSaveActive", "1", RegistryValueKind.String));

            var snapshot = ComplianceCollector.ReadScreensaverSnapshot(
                users, new ConsoleUserLookup(ConsoleUserLookupStatus.NoConsoleUser));

            Assert.Equal(ConsoleUserHive.NoConsoleUser, snapshot.UserHive);
            Assert.Equal("Unknown", ScreensaverPolicyResolver.Evaluate(snapshot)["screensaver_enabled"]);
        }
    }

    [Theory]
    // ConsoleUserLookupStatus is internal, so the theory takes its name.
    [InlineData(nameof(ConsoleUserLookupStatus.Failed), null)]
    [InlineData(nameof(ConsoleUserLookupStatus.Resolved), null)]
    [InlineData(nameof(ConsoleUserLookupStatus.Resolved), "")]
    [InlineData(nameof(ConsoleUserLookupStatus.Resolved), @"S-1-5-21-1111111111-2222222222-3333333333-1001\Software")]
    [InlineData(nameof(ConsoleUserLookupStatus.Resolved), "not-a-sid")]
    public void FailedOrImplausibleLookup_IsReadFailed(string statusName, string? sid)
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var users = CreateUsersRoot())
        {
            SetValues(users, Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                ("ScreenSaveActive", "1", RegistryValueKind.String));

            var snapshot = ComplianceCollector.ReadScreensaverSnapshot(
                users, new ConsoleUserLookup(Enum.Parse<ConsoleUserLookupStatus>(statusName), sid));

            Assert.Equal(ConsoleUserHive.ReadFailed, snapshot.UserHive);
        }
    }

    [Theory]
    [InlineData(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop")]
    [InlineData(@"HKEY_USERS\S-1-5-21-9-9-9-1002\Software\Policies\Microsoft\Windows\Control Panel\Desktop")]
    [InlineData(@"Software\Policies\Microsoft\Windows\Control Panel\Desktop")]
    public void ReadUserDesktopKey_RefusesPathsOutsideConsoleUserHive(string fullPath)
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var users = CreateUsersRoot())
        {
            SetValues(users, Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                ("ScreenSaveActive", "1", RegistryValueKind.String));
            using var hive = users.OpenSubKey(Sid)!;

            Assert.Equal(DesktopKeyState.Failed, ComplianceCollector.ReadUserDesktopKey(hive, Sid, fullPath).State);
            Assert.Equal(DesktopKeyState.Present, ComplianceCollector.ReadUserDesktopKey(hive, Sid,
                @"HKEY_USERS\" + Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop").State);
        }
    }

    [Fact]
    public void ConsoleSessionUser_Resolve_DoesNotThrow_AndResolvedCarriesSid()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Outside LocalSystem WTSQueryUserToken is refused, so a test run usually
        // sees Failed or NoConsoleUser. The contract is only that it never throws
        // and never reports Resolved without a SID.
        var lookup = ConsoleSessionUser.Resolve();
        if (lookup.Status == ConsoleUserLookupStatus.Resolved)
            Assert.StartsWith("S-1-", lookup.Sid);
        else
            Assert.Null(lookup.Sid);
    }
}
