using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2052 review: browser_extensions[] has no partial state on the wire, so a profile the
/// scan refused or could only partly read is recorded in agent_health under
/// (collection_partial, browser_extensions), and cleared by the next fully readable collection.
/// Profiles are passed in, so this runs on any OS.
/// </summary>
public sealed class BrowserExtensionScannerHealthTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("patched-bx-health-").FullName;
    private readonly AgentHealthStore _health;
    private readonly BrowserExtensionScanner _scanner;

    public BrowserExtensionScannerHealthTests()
    {
        _health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_root, "agent-health.json"));
        _scanner = new BrowserExtensionScanner(NullLogger<BrowserExtensionScanner>.Instance, _health);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string ReadableProfile(string name)
    {
        var profile = Path.Combine(_root, name);
        var version = Path.Combine(profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions",
            "abababababababababababababababab", "1.0");
        Directory.CreateDirectory(version);
        File.WriteAllText(Path.Combine(version, "manifest.json"), """{ "name": "Ext", "manifest_version": 3 }""");
        return profile;
    }

    /// <summary>A profile root that is not a directory: the scan refuses it, as it does a junctioned one.</summary>
    private string RefusedProfile(string name)
    {
        var profile = Path.Combine(_root, name);
        File.WriteAllText(profile, "not a directory");
        return profile;
    }

    private InventoryAgentHealthEntry? Entry() =>
        _health.BuildPayloadSection()!.Degraded.SingleOrDefault(d =>
            d.Kind == BrowserExtensionScanner.HealthKind && d.Subject == BrowserExtensionScanner.HealthSubject);

    [Fact]
    public void ARefusedProfile_RecordsTheHealthEntry_AndTheReadableOneIsStillReported()
    {
        var alice = ReadableProfile("alice");
        var bob = RefusedProfile("bob");

        var result = _scanner.Collect(() => [(alice, "alice"), (bob, "bob")]);

        Assert.Equal("alice", Assert.Single(result.Extensions).UserAccount);
        var entry = Entry();
        Assert.NotNull(entry);
        Assert.Equal("profiles_partly_unreadable:1", entry.Reason);
        Assert.Equal(1, entry.Count);
    }

    [Fact]
    public void AFullyReadableCollection_ClearsTheEntry()
    {
        var alice = ReadableProfile("alice");
        var bob = RefusedProfile("bob");
        _scanner.Collect(() => [(alice, "alice"), (bob, "bob")]);
        Assert.NotNull(Entry());

        _scanner.Collect(() => [(alice, "alice")]);

        Assert.Null(Entry());
    }

    [Fact]
    public void ACollectionThatThrows_RecordsTheEntry_AndEmitsNothing()
    {
        var result = _scanner.Collect((Func<IEnumerable<(string, string)>>)(() => throw new InvalidOperationException("profile list unreadable")));

        Assert.Empty(result.Extensions);
        Assert.Equal("failed", result.Status.CollectionStatus);
        Assert.Equal("collection_failed", Entry()?.Reason);
    }
}
