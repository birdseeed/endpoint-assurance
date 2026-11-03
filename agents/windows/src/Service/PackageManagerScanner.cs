using System.Runtime.Versioning;
using Patched.Shared.Contract;
using Patched.Shared.PackageManagers;
using Patched.Shared.UserTrees;

namespace Patched.Service;

/// <summary>
/// PAT-2018: npm global, pip user-site and pipx package inventory for every profile in HKLM
/// ProfileList, plus the machine-wide Node install, run with the daily inventory. Parity with
/// macos/lib/package_managers.sh; the file work and every hardening rule live in
/// <see cref="PackageManagerScanLogic"/> and <see cref="UserTreeReader"/>. Nothing is
/// executed: no npm, pip, pipx, node or python.
///
/// Walks every registered profile, not just loaded sessions, because the package stores are
/// plain files. An unreadable ProfileList fails the per-user half of every source rather than
/// reporting it empty (absence requires authority).
///
/// The scan checks its own 30-second budget between entries. A read that blocks inside one
/// call (a profile on an unresponsive redirected share) cannot be interrupted, so the scan
/// runs on a worker task and is abandoned as failed after <see cref="HardTimeout"/>, the same
/// outer bound the macOS collector enforces by killing its parser. Never throws.
///
/// On the wire since PAT-2225: <see cref="InventoryPoster"/> puts the block in the payload
/// within its byte budget (<see cref="ToolingBlockBudget"/>). The summary line logged here is
/// how the block is checked on real devices.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class PackageManagerScanner
{
    internal static readonly TimeSpan HardTimeout = TimeSpan.FromSeconds(45);

    private readonly ILogger<PackageManagerScanner> _log;

    public PackageManagerScanner(ILogger<PackageManagerScanner> log) => _log = log;

    public InventoryPackageManagers Collect()
    {
        InventoryPackageManagers result;
        try
        {
            // Cancelled when the hard timeout abandons the scan, so it stops at its next
            // budget check instead of running on, touching files, after its result is dropped.
            var abandon = new CancellationTokenSource();
            var scan = Task.Run(() =>
            {
                var snapshot = WindowsUserProfiles.Snapshot(_log);
                var profiles = snapshot?.Profiles
                    .Select(p => new UserProfileSource(p.UserAccount, p.Sid, p.ProfilePath))
                    .ToList();
                return PackageManagerScanLogic.Scan(profiles, new PackageManagerScanOptions { Cancellation = abandon.Token }, snapshot?.Unreadable ?? 0);
            });
            if (scan.Wait(HardTimeout))
            {
                result = scan.Result;
            }
            else
            {
                abandon.Cancel();
                _log.LogWarning("package_managers: scan still running after {Seconds}s, abandoned; block is failed",
                    HardTimeout.TotalSeconds);
                result = new InventoryPackageManagers { CollectionStatus = PackageCollectionStatus.Failed };
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "package_managers: scan failed; block is failed");
            result = new InventoryPackageManagers { CollectionStatus = PackageCollectionStatus.Failed };
        }

        string Source(string s) => result.Sources.TryGetValue(s, out var v)
            ? $"{v.CollectionStatus}/{v.PackageCount}"
            : $"{PackageCollectionStatus.Failed}/0";
        _log.LogInformation(
            "package_managers: status={Status} npm_global={Npm} pip_user={Pip} pipx={Pipx} users={Users} (collected)",
            result.CollectionStatus, Source(PackageSource.NpmGlobal), Source(PackageSource.PipUser),
            Source(PackageSource.Pipx), result.Users.Count);
        return result;
    }
}
