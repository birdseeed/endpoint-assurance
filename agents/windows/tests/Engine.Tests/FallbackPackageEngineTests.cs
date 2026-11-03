using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Patched.Engine.Tests;

/// <summary>
/// PAT-344: FallbackPackageEngine selects WingetCliEngine (primary, ARM64-safe) or
/// ChocolateyEngine (fallback for hosts without winget.exe) at construction time.
/// Uses the internal testable constructor so no real winget.exe/choco.exe lookup
/// happens in CI.
/// </summary>
public sealed class FallbackPackageEngineTests
{
    private sealed class MarkerEngine(string name) : IPackageEngine
    {
        public string Name { get; } = name;

        public Task<PackageCheckResult> CheckAsync(string packageId, CancellationToken ct) =>
            Task.FromResult(new PackageCheckResult { PackageId = packageId, IsInstalled = false });

        public Task<string?> ResolveInstallPathAsync(string packageId, CancellationToken ct) =>
            Task.FromResult<string?>(null);

        public Task<PackageInstallResult> InstallAsync(
            string packageId, CancellationToken ct,
            Patched.Shared.Config.BlockingProcessAction blockingAction = Patched.Shared.Config.BlockingProcessAction.NotifyOnly,
            string? pinnedVersion = null) =>
            Task.FromResult(new PackageInstallResult { PackageId = packageId, Success = false, ErrorMessage = Name });
    }

    [Fact]
    public async Task WingetAvailable_RoutesToWinget()
    {
        var winget = new MarkerEngine("winget");
        var choco  = new MarkerEngine("choco");
        var engine = new FallbackPackageEngine(
            NullLogger<FallbackPackageEngine>.Instance, winget, choco,
            wingetAvailable: true, chocolateyAvailable: true);

        var result = await engine.InstallAsync("Some.Package", CancellationToken.None);

        Assert.Equal("winget", result.ErrorMessage);
    }

    [Fact]
    public async Task WingetUnavailable_ChocolateyAvailable_RoutesToChocolatey()
    {
        var winget = new MarkerEngine("winget");
        var choco  = new MarkerEngine("choco");
        var engine = new FallbackPackageEngine(
            NullLogger<FallbackPackageEngine>.Instance, winget, choco,
            wingetAvailable: false, chocolateyAvailable: true);

        var result = await engine.InstallAsync("Some.Package", CancellationToken.None);

        Assert.Equal("choco", result.ErrorMessage);
    }

    [Fact]
    public async Task NeitherAvailable_FailsClosedToWinget()
    {
        // No engine can actually work here; winget is chosen so the failure mode is a
        // clear "winget.exe not found" error rather than a silent no-op.
        var winget = new MarkerEngine("winget");
        var choco  = new MarkerEngine("choco");
        var engine = new FallbackPackageEngine(
            NullLogger<FallbackPackageEngine>.Instance, winget, choco,
            wingetAvailable: false, chocolateyAvailable: false);

        var result = await engine.InstallAsync("Some.Package", CancellationToken.None);

        Assert.Equal("winget", result.ErrorMessage);
    }
}
