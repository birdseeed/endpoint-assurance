using Microsoft.Extensions.Logging;
using Patched.Shared.Config;

namespace Patched.Engine;

/// <summary>
/// Composite <see cref="IPackageEngine"/>: tries <see cref="WingetCliEngine"/> first and
/// falls back to <see cref="ChocolateyEngine"/> only when winget.exe cannot be found on
/// this host (LTSC/Server images without the App Installer package).
///
/// PAT-344: PAT-352 replaced the WinRT-based WingetComEngine with WingetCliEngine to
/// escape the unresolvable ARM64 App SDK projection, but the PAT-312 pilot cleanup left
/// ChocolateyEngine.cs excluded from Engine.csproj as collateral damage — it has no WinRT
/// dependency of its own, but was compiled out entirely (invisible to the shipped agent,
/// reachable only from test code that compiled it directly). This restores the intended
/// fallback path so ChocolateyEngine is actually referenced at runtime, not just built.
///
/// The active engine is chosen once at construction (winget presence does not change for
/// the lifetime of the service process) rather than per call.
/// </summary>
public sealed class FallbackPackageEngine : IPackageEngine
{
    private readonly IPackageEngine _active;

    public FallbackPackageEngine(
        ILogger<FallbackPackageEngine> log,
        WingetCliEngine                winget,
        ChocolateyEngine                chocolatey)
        : this(log, winget, chocolatey, WingetCliEngine.IsAvailable(), ChocolateyEngine.IsAvailable())
    {
    }

    /// <summary>Testable constructor: caller supplies availability instead of probing the filesystem.</summary>
    internal FallbackPackageEngine(
        ILogger<FallbackPackageEngine> log,
        IPackageEngine                 winget,
        IPackageEngine                 chocolatey,
        bool                           wingetAvailable,
        bool                           chocolateyAvailable)
    {
        if (wingetAvailable)
        {
            _active = winget;
        }
        else if (chocolateyAvailable)
        {
            log.LogWarning("winget.exe not found on this host — falling back to Chocolatey for all package operations.");
            _active = chocolatey;
        }
        else
        {
            log.LogError("Neither winget nor Chocolatey found on this host — package operations will fail.");
            _active = winget; // Fails closed with clear "winget.exe not found" errors rather than throwing at startup.
        }
    }

    public Task<PackageCheckResult> CheckAsync(string packageId, CancellationToken ct) =>
        _active.CheckAsync(packageId, ct);

    public Task<string?> ResolveInstallPathAsync(string packageId, CancellationToken ct) =>
        _active.ResolveInstallPathAsync(packageId, ct);

    public Task<PackageInstallResult> InstallAsync(
        string                packageId,
        CancellationToken     ct,
        BlockingProcessAction blockingAction = BlockingProcessAction.NotifyOnly,
        string?               pinnedVersion  = null) =>
        _active.InstallAsync(packageId, ct, blockingAction, pinnedVersion);
}
