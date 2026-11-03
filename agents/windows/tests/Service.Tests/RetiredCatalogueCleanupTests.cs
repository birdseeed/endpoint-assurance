using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2245: the signed app catalogue is retired. A device upgraded from a release
/// that ran CatalogueSyncService still has its cache under %ProgramData%\Patched;
/// the service removes it at startup, best effort, and never through a reparse point.
/// </summary>
public sealed class RetiredCatalogueCleanupTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "pat2245-" + Guid.NewGuid().ToString("N"));
    private readonly string _stateDir;

    public RetiredCatalogueCleanupTests()
    {
        _stateDir = Path.Combine(_root, "Patched");
        Directory.CreateDirectory(_stateDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private RetiredCatalogueCleanup.Result Run(Action<string>? verifyTrusted = null) =>
        RetiredCatalogueCleanup.Run(
            NullLogger.Instance,
            _stateDir,
            verifyTrusted ?? (_ => { }),
            Patched.Shared.Security.PathSafety.HasReparsePointInChain);

    [Fact]
    public void Startup_RemovesEveryStaleCatalogueCacheFile()
    {
        foreach (var name in new[] { "catalogue.json", "catalogue.version", "catalogue.etag" })
            File.WriteAllText(Path.Combine(_stateDir, name), "stale");
        File.WriteAllText(Path.Combine(_stateDir, "agent-config.json"), "keep");
        File.WriteAllText(Path.Combine(_stateDir, "posture.json"), "keep");

        var result = Run();

        Assert.False(File.Exists(Path.Combine(_stateDir, "catalogue.json")));
        Assert.False(File.Exists(Path.Combine(_stateDir, "catalogue.version")));
        Assert.False(File.Exists(Path.Combine(_stateDir, "catalogue.etag")));
        Assert.True(File.Exists(Path.Combine(_stateDir, "agent-config.json")));
        Assert.True(File.Exists(Path.Combine(_stateDir, "posture.json")));
        Assert.Equal(3, result.Removed.Count);
        Assert.Empty(result.Refused);
        Assert.Empty(result.Failed);
    }

    [Fact]
    public void Startup_WithNoCache_IsANoOp_AndRepeatable()
    {
        var first = Run();
        var second = Run();

        Assert.Empty(first.Removed);
        Assert.Empty(first.Failed);
        Assert.Empty(second.Removed);
        Assert.Empty(second.Failed);
    }

    [Fact]
    public void Startup_WithMissingStateDirectory_IsANoOp()
    {
        Directory.Delete(_stateDir, recursive: true);

        var result = Run();

        Assert.Empty(result.Removed);
        Assert.Empty(result.Failed);
        Assert.False(Directory.Exists(_stateDir));
    }

    [Fact]
    public void Startup_NeverDeletesThroughALink_AndLeavesTheTargetIntact()
    {
        var outside = Path.Combine(_root, "not-ours.txt");
        File.WriteAllText(outside, "precious");
        var link = Path.Combine(_stateDir, "catalogue.json");
        File.CreateSymbolicLink(link, outside);

        var result = Run();

        Assert.True(File.Exists(outside));
        Assert.Equal("precious", File.ReadAllText(outside));
        Assert.Contains(link, result.Refused);
        Assert.DoesNotContain(link, result.Removed);
    }

    [Fact]
    public void Startup_UntrustedStateDirectory_DeletesNothing_AndDoesNotThrow()
    {
        File.WriteAllText(Path.Combine(_stateDir, "catalogue.json"), "stale");

        var result = Run(_ => throw new UnauthorizedAccessException("untrusted owner"));

        Assert.True(File.Exists(Path.Combine(_stateDir, "catalogue.json")));
        Assert.Empty(result.Removed);
        Assert.NotEmpty(result.Failed);
    }

    [Fact]
    public void Startup_ADirectoryWithACacheName_IsLeftAlone()
    {
        var dir = Path.Combine(_stateDir, "catalogue.json");
        Directory.CreateDirectory(dir);

        var result = Run();

        Assert.True(Directory.Exists(dir));
        Assert.Empty(result.Removed);
        Assert.Empty(result.Failed);
    }

    [Fact]
    public void RetiredSyncHealthEntry_IsNotReportedToThePlatform()
    {
        var store = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_root, "agent-health.json"));
        // Written by a pre-PAT-2245 release's CatalogueFetcher and persisted on disk.
        store.RecordFailure("sync_never_succeeded", "catalogue", "fetch_failed");
        store.RecordFailure("sync_never_succeeded", "posture", "fetch_failed");

        var section = store.BuildPayloadSection();

        Assert.NotNull(section);
        Assert.DoesNotContain(section!.Degraded, e => e.Subject == "catalogue");
        Assert.Contains(section.Degraded, e => e.Kind == "sync_never_succeeded" && e.Subject == "posture");
    }
}
