using System.Text.Json;
using Patched.Shared.Apps;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

// PAT-2075: apps_users[].home on Windows. Optional metadata, sent only when the
// account's profile directory is unambiguous, and never able to change a user's
// collection status or rows.
public sealed class PerUserAppHomeTests
{
    private const string AliceSid = "S-1-5-21-100-200-300-1001";
    private const string AliceOtherSid = "S-1-5-21-100-200-300-2001";
    private const string BobSid = "S-1-5-21-100-200-300-1002";
    private const string Alice = "LAB\\alice";
    private const string Bob = "LAB\\bob";

    private sealed class Key : IAppRegistryKey
    {
        internal readonly Dictionary<string, Key> Children = new(StringComparer.OrdinalIgnoreCase);
        internal readonly Dictionary<string, object> Values = new();
        internal Key Add(string name) { var key = new Key(); Children.Add(name, key); return key; }
        public IEnumerable<string> GetSubKeyNames() => Children.Keys.ToArray();
        public IAppRegistryKey? OpenSubKey(string path) => Children.GetValueOrDefault(path);
        public object? GetValue(string name) => Values.GetValueOrDefault(name);
        public void Dispose() { }
    }

    private class Reader : IAppRegistryReader
    {
        internal readonly Key Machine = new();
        internal readonly Key Users = new();
        internal readonly Dictionary<string, string?> Accounts = new()
            { [AliceSid] = Alice, [AliceOtherSid] = Alice, [BobSid] = Bob };
        internal Reader() { Machine.Add(RegistryAppCollection.NativePath); Machine.Add(RegistryAppCollection.WowPath); }
        public bool Is64BitOperatingSystem => true;
        public IAppRegistryKey OpenMachine() => Machine;
        public IAppRegistryKey OpenUsers() => Users;
        public string? ResolveAccountName(string sid) => Accounts.GetValueOrDefault(sid);
        internal void LoadedUserWithApp(string sid)
        {
            var app = Users.Add(sid).Add(RegistryAppCollection.NativePath).Add("SyntheticEditor_is1");
            app.Values["DisplayName"] = "Synthetic Editor";
            app.Values["DisplayVersion"] = "1.2.3";
        }
        internal AppCollectionResult Scan() => RegistryAppCollection.Scan(this, (_, _, version) => version);
    }

    private sealed class ProfileReader : Reader, IAppRegistryReader
    {
        internal readonly Dictionary<string, string?> Profiles = new();
        internal readonly HashSet<string> Throws = [];
        public string? ResolveProfilePath(string sid) =>
            Throws.Contains(sid) ? throw new UnauthorizedAccessException("synthetic denied ProfileList key")
                : Profiles.GetValueOrDefault(sid);
    }

    private static InventoryAppUserStatus User(AppCollectionResult scan, string account) =>
        Assert.Single(scan.Users, u => u.UserAccount == account);

    private static string[] WireKeys(InventoryAppUserStatus user) =>
        JsonSerializer.SerializeToElement(user).EnumerateObject().Select(p => p.Name).OrderBy(n => n).ToArray();

    [Fact]
    public void UnambiguousProfilePathIsSentAsHome()
    {
        var r = new ProfileReader();
        r.LoadedUserWithApp(AliceSid); r.Profiles[AliceSid] = @"C:\Users\alice.LAB";
        r.Users.Add(BobSid); r.Profiles[BobSid] = @"D:\Profiles\bob\";
        var scan = r.Scan();
        Assert.Equal(@"C:\Users\alice.LAB", User(scan, Alice).Home);
        Assert.Equal(@"D:\Profiles\bob", User(scan, Bob).Home);
        Assert.Equal("complete", User(scan, Alice).CollectionStatus);
        Assert.Equal(new[] { "collection_status", "home", "user_account" }, WireKeys(User(scan, Alice)));
        Assert.Equal(@"C:\Users\alice.LAB",
            JsonSerializer.SerializeToElement(User(scan, Alice)).GetProperty("home").GetString());
    }

    [Fact]
    public void ReaderWithoutProfileMetadataSendsNoHome()
    {
        var r = new Reader();
        r.LoadedUserWithApp(AliceSid);
        var user = User(r.Scan(), Alice);
        Assert.Null(user.Home);
        Assert.Equal("complete", user.CollectionStatus);
        Assert.Equal(new[] { "collection_status", "user_account" }, WireKeys(user));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"Users\alice")]
    [InlineData(@"\\server\profiles\alice")]
    [InlineData(@"%SystemDrive%\Users\alice")]
    [InlineData(@" C:\Users\alice")]
    [InlineData("C:\\Users\\ali\nce")]
    [InlineData("C:")]
    [InlineData(@"C:\")]
    [InlineData("/Users/alice")]
    public void UnusableProfilePathIsOmittedWithoutTouchingAuthority(string? path)
    {
        var r = new ProfileReader();
        r.LoadedUserWithApp(AliceSid); r.Profiles[AliceSid] = path;
        var scan = r.Scan();
        Assert.Null(User(scan, Alice).Home);
        Assert.Equal("complete", User(scan, Alice).CollectionStatus);
        Assert.Equal(Alice, Assert.Single(scan.Apps).UserAccount);
        Assert.Equal(new[] { "collection_status", "user_account" }, WireKeys(User(scan, Alice)));
    }

    [Fact]
    public void FailedProfileLookupIsNotAUserFailure()
    {
        var r = new ProfileReader();
        r.LoadedUserWithApp(AliceSid); r.Throws.Add(AliceSid);
        r.Users.Add(BobSid); r.Profiles[BobSid] = @"C:\Users\bob";
        var scan = r.Scan();
        Assert.Null(User(scan, Alice).Home);
        Assert.Equal("complete", User(scan, Alice).CollectionStatus);
        Assert.Equal(@"C:\Users\bob", User(scan, Bob).Home);
        Assert.Equal("complete", scan.Status);
    }

    [Fact]
    public void TwoSidsForOneAccountSendHomeOnlyWhenTheyAgree()
    {
        var r = new ProfileReader();
        r.LoadedUserWithApp(AliceSid); r.Users.Add(AliceOtherSid);
        r.Profiles[AliceSid] = @"C:\Users\alice"; r.Profiles[AliceOtherSid] = @"C:\Users\alice.LAB";
        Assert.Null(User(r.Scan(), Alice).Home);

        r.Profiles[AliceOtherSid] = null;
        Assert.Null(User(r.Scan(), Alice).Home);

        r.Profiles[AliceOtherSid] = @"C:\Users\alice";
        Assert.Equal(@"C:\Users\alice", User(r.Scan(), Alice).Home);
    }

    [Fact]
    public void ProfileLookupUsesOnlyLoadedRealUserSids()
    {
        var r = new ProfileReader();
        r.LoadedUserWithApp(AliceSid); r.Profiles[AliceSid] = @"C:\Users\alice";
        r.Profiles[BobSid] = @"C:\Users\bob"; // registered profile, hive not loaded
        foreach (var ignored in new[] { ".DEFAULT", "S-1-5-18", AliceSid + "_Classes" }) r.Users.Add(ignored);
        var scan = r.Scan();
        Assert.Equal(Alice, Assert.Single(scan.Users).UserAccount);
        Assert.DoesNotContain(scan.Users, u => u.Home == @"C:\Users\bob");
    }
}
