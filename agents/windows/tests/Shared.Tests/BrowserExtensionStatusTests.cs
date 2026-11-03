using System.Text.Json;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Contract;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2065: the browser_extensions_status block on Windows. Per-browser statuses from
/// <see cref="BrowserExtensionScanLogic.Scan"/>, the block from
/// <see cref="BrowserExtensionStatusLogic.Build"/>, and every block checked against the
/// platform's contract by <see cref="BrowserExtensionsStatusContract"/>. Runs on any OS; the
/// junction cases need <see cref="DirectoryLinkFactAttribute"/>.
/// </summary>
public sealed class BrowserExtensionStatusTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("patched-bx-status-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string Profile(string name)
    {
        var p = Path.Combine(_root, name);
        Directory.CreateDirectory(p);
        return p;
    }

    private static void Chromium(string profile, string vendor, string product, string browserProfile, string id,
        string manifest = """{ "name": "Ext", "manifest_version": 3 }""")
    {
        var dir = Path.Combine(profile, "AppData", "Local", vendor, product, "User Data", browserProfile, "Extensions", id, "1.0");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "manifest.json"), manifest);
    }

    private static void Firefox(string profile, string ffProfile, string json)
    {
        var dir = Path.Combine(profile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", ffProfile);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "extensions.json"), json);
    }

    private static string Addons(int n) =>
        JsonSerializer.Serialize(new
        {
            addons = Enumerable.Range(0, n).Select(i => new { id = $"a{i:D4}@example.com", type = "extension", version = "1" }),
        });

    /// <summary>alice: Chrome (two profiles), Edge and Firefox. bob: Chrome only. carol: nothing.</summary>
    private (string Alice, string Bob, string Carol) Estate()
    {
        var alice = Profile("alice");
        Chromium(alice, "Google", "Chrome", "Default", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        Chromium(alice, "Google", "Chrome", "Profile 2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        Chromium(alice, "Microsoft", "Edge", "Default", "cccccccccccccccccccccccccccccccc");
        Firefox(alice, "a.default-release", Addons(2));
        var bob = Profile("bob");
        Chromium(bob, "Google", "Chrome", "Default", "dddddddddddddddddddddddddddddddd");
        return (alice, bob, Profile("carol"));
    }

    /// <summary>The block the scanner would build from these scans, and the rows.</summary>
    private static (InventoryBrowserExtensionsStatus Status, List<InventoryBrowserExtension> Rows) Build(
        params (string Path, string Account, int Share)[] profiles)
    {
        var rows = new List<InventoryBrowserExtension>();
        var users = new List<BrowserExtensionUserScan>();
        var capped = false;
        foreach (var (path, account, share) in profiles)
        {
            var scan = BrowserExtensionScanLogic.Scan(path, account, share);
            rows.AddRange(scan.Extensions);
            capped |= scan.Capped;
            users.Add(new BrowserExtensionUserScan(account, "S-1-5-21-1-2-3-" + account.Length, scan.Browsers, scan.UserFailed));
        }
        return (BrowserExtensionStatusLogic.Build(users, capped, unreadableProfiles: 0), rows);
    }

    private static InventoryBrowserExtensionsStatusUser User(InventoryBrowserExtensionsStatus st, string name) =>
        Assert.Single(st.Users!, u => u.User == name);

    private static string[] Pairs(InventoryBrowserExtensionsStatusUser u) => [u.Browsers.Chrome, u.Browsers.Edge, u.Browsers.Firefox];

    // ---------------------------------------------------------------- complete / not_present

    [Fact]
    public void Complete_EveryProfileRead_PairByPair()
    {
        var (alice, bob, carol) = Estate();
        var (st, rows) = Build((alice, @"DESKTOP\alice", int.MaxValue), (bob, @"DESKTOP\bob", int.MaxValue), (carol, @"DESKTOP\carol", int.MaxValue));

        Assert.Equal("complete", st.CollectionStatus);
        Assert.False(st.CapReached);
        Assert.Equal(["complete", "complete", "complete"], Pairs(User(st, @"DESKTOP\alice")));
        Assert.Equal(["complete", "not_present", "not_present"], Pairs(User(st, @"DESKTOP\bob")));
        Assert.Equal("complete", User(st, @"DESKTOP\bob").CollectionStatus);
        Assert.Equal("not_present", User(st, @"DESKTOP\carol").CollectionStatus);
        Assert.Equal(6, rows.Count);
        // user is exactly the rows' user_account, and every row sits under a complete pair.
        Assert.All(rows, r => Assert.Contains(st.Users!, u => u.User == r.UserAccount));
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, rows));
    }

    [Fact]
    public void NotPresent_NoBrowserAnywhere()
    {
        var dave = Profile("dave");
        var erin = Profile("erin");
        var (st, rows) = Build((dave, "dave", 1000), (erin, "erin", 1000));

        Assert.Equal("not_present", st.CollectionStatus);
        Assert.All(st.Users!, u => Assert.Equal(["not_present", "not_present", "not_present"], Pairs(u)));
        Assert.Empty(rows);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, rows));

        var empty = BrowserExtensionStatusLogic.Build([], capReached: false, unreadableProfiles: 0);
        Assert.Equal("not_present", empty.CollectionStatus);
        Assert.Empty(empty.Users!);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(empty, []));
    }

    /// <summary>
    /// PAT-2065 review: a registered profile whose root is missing (an unmounted volume, a
    /// detached profile container) was never read, so it is failed, never not_present, and the
    /// block cannot claim the device's absence. It is not a health fault.
    /// </summary>
    [Fact]
    public void Failed_ARegisteredProfileWhoseRootIsMissing()
    {
        var dave = Profile("dave");
        var gone = Path.Combine(_root, "gone");
        var scan = BrowserExtensionScanLogic.Scan(gone, "gone");
        Assert.True(scan.UserFailed);
        Assert.False(scan.Partial);
        Assert.Empty(scan.Extensions);

        var (st, rows) = Build((dave, "dave", 1000), (gone, "gone", 1000));
        var u = User(st, "gone");
        Assert.Equal("failed", u.CollectionStatus);
        Assert.Equal(["failed", "failed", "failed"], Pairs(u));
        Assert.Equal("partial", st.CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, rows));
    }

    // ---------------------------------------------------------------- partial

    /// <summary>
    /// A directory the verified lister refuses (standing in for a junction swap, which is what
    /// the Windows handle check refuses) makes exactly that browser partial. This is the
    /// red/green case for refusal to partial: <see cref="BrowserExtensionScanLogic"/>'s Partial
    /// setter is what marks the browser being read.
    /// </summary>
    [Fact]
    public void Partial_ARefusedChromeProfile_MakesOnlyThatPairPartial()
    {
        var (alice, _, _) = Estate();
        var chromeProfile2 = Path.Combine(alice, "AppData", "Local", "Google", "Chrome", "User Data", "Profile 2");
        var real = UserTreeReader.DefaultLister();
        var scan = BrowserExtensionScanLogic.Scan(alice, "alice", options: new BrowserExtensionScanOptions
        {
            ListOpenedDirectory = (path, expected) =>
                string.Equals(Path.TrimEndingDirectorySeparator(path), chromeProfile2, StringComparison.Ordinal) ? null : real(path, expected),
        });

        Assert.True(scan.Partial);
        Assert.Equal(new BrowserExtensionBrowserStatuses("partial", "complete", "complete"), scan.Browsers);
        var st = BrowserExtensionStatusLogic.Build([new("alice", null, scan.Browsers, scan.UserFailed)], false, 0);
        Assert.Equal("partial", st.CollectionStatus);
        Assert.Equal("partial", User(st, "alice").CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, scan.Extensions));
    }

    [DirectoryLinkFact]
    public void Partial_ALinkedUserDataDirectory_IsPartialNeverNotPresent()
    {
        var other = Profile("other");
        Chromium(other, "Google", "Chrome", "Default", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        var alice = Profile("alice");
        var chrome = Path.Combine(alice, "AppData", "Local", "Google", "Chrome");
        Directory.CreateDirectory(chrome);
        DirectoryLinks.Plant(Path.Combine(chrome, "User Data"), Path.Combine(other, "AppData", "Local", "Google", "Chrome", "User Data"));

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Empty(scan.Extensions);
        Assert.Equal("partial", scan.Browsers.Chrome);
        Assert.Equal("not_present", scan.Browsers.Edge);
    }

    [Fact]
    public void Partial_UnparseableFiles_AndAnUnsafeLocale()
    {
        var alice = Profile("alice");
        Chromium(alice, "Google", "Chrome", "Default", "ffffffffffffffffffffffffffffffff", "{ not json");
        Chromium(alice, "Microsoft", "Edge", "Default", "12121212121212121212121212121212",
            """{ "name": "__MSG_x__", "manifest_version": 3, "default_locale": "../../other" }""");
        Firefox(alice, "broken.default", "{ not json");

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Equal(new BrowserExtensionBrowserStatuses("partial", "partial", "partial"), scan.Browsers);
        // The Edge row is still listed, under its id: the locale refusal costs only the name.
        Assert.Equal("12121212121212121212121212121212", Assert.Single(scan.Extensions).Name);
    }

    // ---------------------------------------------------------------- Firefox add-on entries (PAT-2068)

    private const string GoodAddon = """{ "id": "good@example.com", "type": "extension", "version": "1" }""";

    [Theory]
    [InlineData("\"not an object\"")]
    [InlineData("42")]
    [InlineData("""{ "type": "extension", "version": "1" }""")]
    [InlineData("""{ "id": "", "type": "extension" }""")]
    [InlineData("""{ "id": 7, "type": "extension" }""")]
    [InlineData("""{ "id": null, "type": "extension" }""")]
    public void Firefox_MalformedAddonEntry_IsPartial_OtherRowsKept(string malformed)
    {
        var alice = Profile("alice");
        Firefox(alice, "a.default", $$"""{ "addons": [ {{GoodAddon}}, {{malformed}} ] }""");

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Equal("partial", scan.Browsers.Firefox);
        Assert.True(scan.Partial); // PAT-2052's health signal, as for a corrupt manifest.
        Assert.Equal("good@example.com", Assert.Single(scan.Extensions).ExtensionId);
    }

    [Theory]
    [InlineData("""{ "addons": null }""")]
    [InlineData("""{ "addons": { "x": 1 } }""")]
    [InlineData("""{ "addons": "x" }""")]
    [InlineData("""[ ]""")]
    [InlineData("""42""")]
    public void Firefox_MalformedAddonList_IsPartial(string json)
    {
        var alice = Profile("alice");
        Firefox(alice, "a.default", json);
        Firefox(alice, "b.default", $$"""{ "addons": [ {{GoodAddon}} ] }""");

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Equal("partial", scan.Browsers.Firefox);
        Assert.True(scan.Partial);
        // The next profile is still read.
        Assert.Equal("good@example.com", Assert.Single(scan.Extensions).ExtensionId);
    }

    [Fact]
    public void Firefox_FilteredAddonTypes_StayComplete()
    {
        var alice = Profile("alice");
        Firefox(alice, "a.default", $$"""
            { "addons": [
                {{GoodAddon}},
                { "id": "default-theme@mozilla.org", "type": "theme", "location": "app-builtin" },
                { "id": "en-GB@dictionaries.addons.mozilla.org", "type": "dictionary" },
                { "id": "langpack-fr@firefox.mozilla.org", "type": "locale", "location": "app-system-defaults" },
                { "id": "odd@example.com", "type": 3 },
                { "id": "untyped@example.com" }
            ] }
            """);

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Equal("complete", scan.Browsers.Firefox);
        Assert.False(scan.Partial);
        Assert.Equal("good@example.com", Assert.Single(scan.Extensions).ExtensionId);
    }

    [Fact]
    public void Firefox_WrongTypedOptionalFields_KeepTheRow_StayComplete()
    {
        // As macOS's text(): a wrong-typed name, version or updateURL is read as empty, the row is kept.
        var alice = Profile("alice");
        Firefox(alice, "a.default", """
            { "addons": [ { "id": "odd@example.com", "type": "extension", "version": 2,
                            "updateURL": 5, "defaultLocale": { "name": 9 } } ] }
            """);

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Equal("complete", scan.Browsers.Firefox);
        var row = Assert.Single(scan.Extensions);
        Assert.Equal("odd@example.com", row.Name);
        Assert.Equal("", row.Version);
        Assert.Null(row.UpdateUrl);
    }

    [Fact]
    public void Firefox_CleanListAndMissingAddons_StayComplete()
    {
        var alice = Profile("alice");
        Firefox(alice, "a.default", Addons(3));
        Firefox(alice, "b.default", "{ }");

        var scan = BrowserExtensionScanLogic.Scan(alice, "alice");

        Assert.Equal("complete", scan.Browsers.Firefox);
        Assert.False(scan.Partial);
        Assert.Equal(3, scan.Extensions.Count);
    }

    // ---------------------------------------------------------------- cap

    [Fact]
    public void Cap_CutInsideChrome_MarksChromeAndEveryUnreadBrowserPartial()
    {
        var (alice, _, _) = Estate();
        var scan = BrowserExtensionScanLogic.Scan(alice, "alice", maxResults: 1);

        Assert.True(scan.Capped);
        Assert.Single(scan.Extensions);
        Assert.Equal(new BrowserExtensionBrowserStatuses("partial", "partial", "partial"), scan.Browsers);
    }

    [Fact]
    public void Cap_ShareExactlyFilled_IsStillComplete()
    {
        var (alice, _, _) = Estate();
        var scan = BrowserExtensionScanLogic.Scan(alice, "alice", maxResults: 5);

        Assert.False(scan.Capped);
        Assert.Equal(5, scan.Extensions.Count);
        Assert.Equal(new BrowserExtensionBrowserStatuses("complete", "complete", "complete"), scan.Browsers);
    }

    [Fact]
    public void Cap_CutInFirefox_ChromeAndEdgeStayComplete_BlockIsPartialAndCapped()
    {
        var (alice, bob, _) = Estate();
        var (st, rows) = Build((alice, "alice", 4), (bob, "bob", 1000));

        Assert.Equal(["complete", "complete", "partial"], Pairs(User(st, "alice")));
        Assert.Equal("complete", User(st, "bob").CollectionStatus);
        Assert.True(st.CapReached);
        Assert.Equal("partial", st.CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, rows));
    }

    // ---------------------------------------------------------------- failed

    [Fact]
    public void Failed_AProfileRootThatCannotBeEntered_FailsThatUser()
    {
        var (alice, _, _) = Estate();
        var notADir = Path.Combine(_root, "dan");
        File.WriteAllText(notADir, "not a directory");

        var (st, rows) = Build((alice, "alice", 1000), (notADir, "dan", 1000));

        var bob = User(st, "dan");
        Assert.Equal("failed", bob.CollectionStatus);
        Assert.Equal(["failed", "failed", "failed"], Pairs(bob));
        Assert.Equal("partial", st.CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, rows));
    }

    [Fact]
    public void Failed_TheBlockItself_CarriesOnlyTheStatus()
    {
        var json = JsonSerializer.Serialize(BrowserExtensionStatusLogic.Failed(), BrowserExtensionsStatusContract.WireOptions);
        Assert.Equal("""{"collection_status":"failed"}""", json);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(BrowserExtensionStatusLogic.Failed(), []));
    }

    // ---------------------------------------------------------------- composer rules

    private static BrowserExtensionUserScan Scan(string user, string c, string e, string f, bool failed = false) =>
        new(user, null, new BrowserExtensionBrowserStatuses(c, e, f), failed);

    [Fact]
    public void Build_UnreadableProfileEntries_KeepTheBlockPartial()
    {
        var st = BrowserExtensionStatusLogic.Build([Scan("a", "complete", "not_present", "complete")], false, unreadableProfiles: 1);
        Assert.Equal("partial", st.CollectionStatus);
    }

    [Fact]
    public void Build_TwoProfilesUnderOneAccount_AreMergedLeastAuthoritativeFirst()
    {
        var st = BrowserExtensionStatusLogic.Build(
            [Scan("a", "complete", "not_present", "complete"), Scan("a", "not_present", "partial", "failed")], false, 0);

        var u = Assert.Single(st.Users!);
        Assert.Equal(["complete", "partial", "failed"], Pairs(u));
        Assert.Equal("partial", u.CollectionStatus);
        Assert.Equal("partial", st.CollectionStatus);
    }

    [Fact]
    public void Build_OverFiveHundredUsers_ListsFiveHundredAndIsPartial()
    {
        var scans = Enumerable.Range(0, 501).Select(i => Scan("u" + i, "not_present", "not_present", "not_present")).ToList();
        var st = BrowserExtensionStatusLogic.Build(scans, false, 0);
        Assert.Equal(500, st.Users!.Count);
        Assert.Equal("partial", st.CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, []));
    }

    [Fact]
    public void Build_AnAccountWithNoName_IsLeftOutAndTheBlockIsPartial()
    {
        var st = BrowserExtensionStatusLogic.Build([Scan("", "complete", "complete", "complete")], false, 0);
        Assert.Empty(st.Users!);
        Assert.Equal("partial", st.CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(st, []));
    }

    [Fact]
    public void Serialised_UserIdNullIsWritten_AndKeysMatchTheContract()
    {
        var st = BrowserExtensionStatusLogic.Build([Scan(@"DESKTOP\alice", "complete", "not_present", "not_present")], false, 0);
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(st, BrowserExtensionsStatusContract.WireOptions));
        var root = doc.RootElement;
        Assert.Equal(["collection_status", "cap_reached", "users"], root.EnumerateObject().Select(p => p.Name).ToArray());
        var user = root.GetProperty("users")[0];
        Assert.Equal(["user", "user_id", "collection_status", "browsers"], user.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(JsonValueKind.Null, user.GetProperty("user_id").ValueKind);
        Assert.Equal(["chrome", "edge", "firefox"], user.GetProperty("browsers").EnumerateObject().Select(p => p.Name).ToArray());
    }

    // ---------------------------------------------------------------- the checker can fail

    /// <summary>
    /// The contract checker goes red on each rule it ports and on schema breaks, so a green
    /// Check above means something.
    /// </summary>
    [Theory]
    [InlineData("bob-firefox-partial", "withheld: browser_status_inconsistent")]
    [InlineData("row-under-not-present", "withheld: row_under_not_present_pair")]
    [InlineData("user-missing", "withheld: row_not_reported_complete")]
    [InlineData("user-case", "withheld: row_not_reported_complete")]
    [InlineData("capped-complete", "withheld: cap_reached_not_partial")]
    [InlineData("duplicate", "withheld: duplicate_user")]
    [InlineData("safari-key", "schema:")]
    [InlineData("unknown-status", "schema:")]
    public void Checker_GoesRedOnEachRule(string mutation, string expected)
    {
        var rows = new List<InventoryBrowserExtension>
        {
            new() { Browser = "chrome", Profile = "Default", UserAccount = "bob", ExtensionId = "x", Name = "x", Version = "1",
                    Enabled = true, Permissions = [], HostPermissions = [], FromWebstore = false },
        };
        InventoryBrowserExtensionsStatusUser Bob(string c = "complete", string f = "not_present", string user = "bob") => new()
        {
            User = user, UserId = null, CollectionStatus = "complete",
            Browsers = new() { Chrome = c, Edge = "not_present", Firefox = f },
        };
        var good = new InventoryBrowserExtensionsStatus { CollectionStatus = "complete", CapReached = false, Users = [Bob()] };
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(good, rows));

        var bad = mutation switch
        {
            "bob-firefox-partial"   => good with { Users = [Bob(f: "partial")] },
            "row-under-not-present" => good with { CollectionStatus = "partial", Users = [Bob(c: "not_present") with { CollectionStatus = "partial" }] },
            "user-missing"          => good with { Users = [] },
            "user-case"             => good with { Users = [Bob(user: "Bob")] },
            "capped-complete"       => good with { CapReached = true },
            "duplicate"             => good with { Users = [Bob(), Bob()] },
            "unknown-status"        => good with { CollectionStatus = "done" },
            _ => null,
        };
        string verdict;
        if (bad is not null)
        {
            verdict = BrowserExtensionsStatusContract.Check(bad, rows);
        }
        else
        {
            var json = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["browser_extensions_status"] = good,
                ["browser_extensions"] = rows,
            }, BrowserExtensionsStatusContract.WireOptions).Replace("\"firefox\":", "\"safari\":\"complete\",\"firefox\":");
            using var doc = JsonDocument.Parse(json);
            verdict = BrowserExtensionsStatusContract.CheckJson(doc.RootElement);
        }
        Assert.StartsWith(expected, verdict);
    }
}
