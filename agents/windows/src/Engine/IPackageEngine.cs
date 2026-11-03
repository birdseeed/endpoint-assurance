using Patched.Shared.Config;

namespace Patched.Engine;

/// <summary>
/// Platform-neutral interface for package check/install operations.
/// WingetCliEngine is the primary implementation (ARM64-compatible, no WinRT). (PAT-352)
/// The service registers FallbackPackageEngine, which selects WingetCliEngine or
/// ChocolateyEngine at startup based on host availability. (PAT-344)
/// </summary>
public interface IPackageEngine
{
    /// <summary>
    /// Resolve installed and available versions for a package.
    /// Never downloads or installs anything.
    /// </summary>
    Task<PackageCheckResult> CheckAsync(string packageId, CancellationToken ct);

    /// <summary>
    /// Resolve the local path of the package installer that winget would download.
    /// Required before calling <see cref="InstallAsync"/> so the verifier can inspect it.
    /// Returns null if the path cannot be determined (blocks install).
    /// </summary>
    Task<string?> ResolveInstallPathAsync(string packageId, CancellationToken ct);

    /// <summary>
    /// Install or update a package. The caller MUST call <see cref="ResolveInstallPathAsync"/>
    /// and pass the result to the Authenticode verifier before calling this.
    ///
    /// <paramref name="blockingAction"/> controls agent behaviour when a running process
    /// must close before the update can proceed (PAT-296). The engine implementation
    /// maps this to the appropriate winget flag or interaction mode.
    /// Default: <see cref="BlockingProcessAction.NotifyOnly"/> — never force-quits.
    ///
    /// H6: <paramref name="pinnedVersion"/> MUST be the exact version that was
    /// resolved + verified by <see cref="ResolveInstallPathAsync"/>. The engine
    /// pins the install to that version so it cannot resolve/install a different
    /// (e.g. newer) artifact than the one that passed Authenticode + SHA-256
    /// verification. When null the engine installs the latest (unpinned); callers
    /// on the fail-closed deploy path always pass the verified version.
    /// </summary>
    Task<PackageInstallResult> InstallAsync(
        string               packageId,
        CancellationToken    ct,
        BlockingProcessAction blockingAction = BlockingProcessAction.NotifyOnly,
        string?              pinnedVersion  = null);
}

public sealed record PackageCheckResult
{
    public required string  PackageId        { get; init; }
    public bool             IsInstalled      { get; init; }
    public string?          InstalledVersion { get; init; }
    public string?          AvailableVersion { get; init; }
    public bool             HasUpdate        => IsInstalled
        && AvailableVersion is not null
        && InstalledVersion is not null
        && !string.Equals(InstalledVersion, AvailableVersion, StringComparison.Ordinal);
}

public sealed record PackageInstallResult
{
    public required string  PackageId        { get; init; }
    public bool             Success          { get; init; }
    public string?          InstalledVersion { get; init; }
    public string?          ErrorMessage     { get; init; }
}
