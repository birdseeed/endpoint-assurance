using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Contract;
using Patched.Shared.Tests;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2065: <see cref="BrowserExtensionScanner"/> sends browser_extensions_status beside the
/// rows it describes: the real 1,000-row cap shared fairly per profile, a failed block when the
/// profile list cannot be read, and every block checked against the platform contract.
/// Profiles are passed in, so this runs on any OS.
/// </summary>
public sealed class BrowserExtensionScannerStatusTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("patched-bx-scanner-status-").FullName;
    private readonly BrowserExtensionScanner _scanner;

    public BrowserExtensionScannerStatusTests()
    {
        var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_root, "agent-health.json"));
        _scanner = new BrowserExtensionScanner(NullLogger<BrowserExtensionScanner>.Instance, health);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string Profile(string name, int firefoxAddons = 0, bool chrome = false)
    {
        var profile = Path.Combine(_root, name);
        Directory.CreateDirectory(profile);
        if (chrome)
        {
            var version = Path.Combine(profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions",
                "abababababababababababababababab", "1.0");
            Directory.CreateDirectory(version);
            File.WriteAllText(Path.Combine(version, "manifest.json"), """{ "name": "Ext", "manifest_version": 3 }""");
        }
        if (firefoxAddons > 0)
        {
            var ff = Path.Combine(profile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "x.default-release");
            Directory.CreateDirectory(ff);
            File.WriteAllText(Path.Combine(ff, "extensions.json"), JsonSerializer.Serialize(new
            {
                addons = Enumerable.Range(0, firefoxAddons).Select(i => new { id = $"a{i:D4}@example.com", type = "extension", version = "1" }),
            }));
        }
        return profile;
    }

    private static InventoryBrowserExtensionsStatusUser User(BrowserExtensionCollection c, string name) =>
        Assert.Single(c.Status.Users!, u => u.User == name);

    [Fact]
    public void Complete_TwoReadableProfiles_WithTheirSids()
    {
        var alice = Profile("alice", firefoxAddons: 2, chrome: true);
        var carol = Profile("carol");
        var result = _scanner.Collect(() => (
            [new BrowserExtensionProfileRef(alice, @"DESKTOP\alice", "S-1-5-21-1-2-3-1001"),
             new BrowserExtensionProfileRef(carol, @"DESKTOP\carol", "S-1-5-21-1-2-3-1002")], 0));

        Assert.Equal("complete", result.Status.CollectionStatus);
        Assert.Equal("S-1-5-21-1-2-3-1001", User(result, @"DESKTOP\alice").UserId);
        Assert.Equal("not_present", User(result, @"DESKTOP\carol").CollectionStatus);
        Assert.Equal(3, result.Extensions.Count);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(result.Status, result.Extensions));
    }

    /// <summary>
    /// The real cap: alice has 1,100 Firefox add-ons. Three profiles share 1,000 rows, so alice
    /// may use 333, and bob and carol after her are still read in full: she cannot crowd them out.
    /// </summary>
    [Fact]
    public void Cap_TheRealCap_IsSharedFairly_AndMarksOnlyTheCutPairPartial()
    {
        Assert.Equal(1000, BrowserExtensionScanner.MaxExtensions);
        var alice = Profile("alice", firefoxAddons: 1100, chrome: true);
        var bob = Profile("bob", firefoxAddons: 3, chrome: true);
        var carol = Profile("carol");

        var result = _scanner.Collect(() => [(alice, "alice"), (bob, "bob"), (carol, "carol")]);

        Assert.Equal(333, result.Extensions.Count(e => e.UserAccount == "alice"));
        Assert.Equal(4, result.Extensions.Count(e => e.UserAccount == "bob"));
        Assert.True(result.Status.CapReached);
        Assert.Equal("partial", result.Status.CollectionStatus);
        var a = User(result, "alice");
        Assert.Equal(("complete", "not_present", "partial"), (a.Browsers.Chrome, a.Browsers.Edge, a.Browsers.Firefox));
        Assert.Equal("complete", User(result, "bob").CollectionStatus);
        Assert.Equal("not_present", User(result, "carol").CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(result.Status, result.Extensions));
    }

    [Fact]
    public void Cap_OneProfileOverTheWholeCap_StopsAtOneThousand()
    {
        var alice = Profile("alice", firefoxAddons: 1100);
        var result = _scanner.Collect(() => [(alice, "alice")]);

        Assert.Equal(1000, result.Extensions.Count);
        Assert.True(result.Status.CapReached);
        Assert.Equal("partial", User(result, "alice").Browsers.Firefox);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(result.Status, result.Extensions));
    }

    [Fact]
    public void Failed_AnUnreadableProfileList_IsAFailedBlockAndNoRows()
    {
        var result = _scanner.Collect(() => ((IReadOnlyList<BrowserExtensionProfileRef>, int)?)null);

        Assert.Empty(result.Extensions);
        Assert.Equal("failed", result.Status.CollectionStatus);
        Assert.Null(result.Status.Users);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(result.Status, result.Extensions));
    }

    [Fact]
    public void Partial_AProfileEntryThatCouldNotBeRead_KeepsTheBlockPartial()
    {
        var alice = Profile("alice", chrome: true);
        var result = _scanner.Collect(() => ([new BrowserExtensionProfileRef(alice, "alice", null)], 1));

        Assert.Equal("partial", result.Status.CollectionStatus);
        Assert.Equal("complete", User(result, "alice").CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(result.Status, result.Extensions));
    }

    [Fact]
    public void Partial_ARefusedProfileRoot_FailsThatUserOnly()
    {
        var alice = Profile("alice", chrome: true);
        var bob = Path.Combine(_root, "bob");
        File.WriteAllText(bob, "not a directory");

        var result = _scanner.Collect(() => [(alice, "alice"), (bob, "bob")]);

        Assert.Equal("failed", User(result, "bob").CollectionStatus);
        Assert.Equal("complete", User(result, "alice").CollectionStatus);
        Assert.Equal("partial", result.Status.CollectionStatus);
        Assert.Equal("OK", BrowserExtensionsStatusContract.Check(result.Status, result.Extensions));
    }

    /// <summary>The payload carries the block as a sibling of browser_extensions, from the same collection.</summary>
    [Fact]
    public void Payload_SerialisesTheBlockBesideTheRows()
    {
        var alice = Profile("alice", firefoxAddons: 1, chrome: true);
        var result = _scanner.Collect(() => [(alice, @"DESKTOP\alice")]);
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["browser_extensions_status"] = result.Status,
            ["browser_extensions"] = result.Extensions,
        }, BrowserExtensionsStatusContract.WireOptions);
        using var doc = JsonDocument.Parse(json);

        Assert.Equal("OK", BrowserExtensionsStatusContract.CheckJson(doc.RootElement));
        Assert.Equal(@"DESKTOP\alice",
            doc.RootElement.GetProperty("browser_extensions_status").GetProperty("users")[0].GetProperty("user").GetString());
    }
}
