using System.Runtime.Versioning;
using Patched.Shared.Paths;

namespace Patched.Shared.Security;

/// <summary>
/// Establishes the trust boundary for %ProgramData%\Patched before the service uses
/// any path below it. This runs at process startup, before logging or hosted services,
/// so it covers every agent tier, including assurance-tier devices (PAT-1599:
/// formerly report_deploy) that never invoke a package engine before receiving a
/// decommission directive.
///
/// Existing roots are verified without repairing their DACL. Hardening a legacy
/// writable root would otherwise bless credential contents planted before startup.
/// Unsafe legacy installations require administrator investigation and reprovisioning.
/// </summary>
[SupportedOSPlatform("windows")]
public static class StateDirectoryBootstrap
{
    /// <summary>
    /// Establishes or verifies the production state-directory trust boundary.
    /// Existing unsafe roots are refused without mutation; a successful call returns false.
    /// </summary>
    public static bool EnsureHardened() => EnsureHardened(PathConstants.StateDir);

    /// <summary>Test seam for the same root-only bootstrap against an isolated path.</summary>
    internal static bool EnsureHardened(string stateDirectory) =>
        SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(
            stateDirectory, allowStandardUserRead: true, repairExisting: false);
}
