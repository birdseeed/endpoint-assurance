using System.Runtime.Versioning;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;

namespace Patched.Service;

/// <summary>
/// PAT-2017: IDE extension and plugin inventory (VS Code, VS Code Insiders, Cursor,
/// Windsurf, JetBrains) for every profile in HKLM ProfileList, run with the daily
/// inventory. Parity with macos/lib/ide_extensions.sh; the file work and every hardening
/// rule live in <see cref="IdeExtensionScanLogic"/>.
///
/// Like <see cref="BrowserExtensionScanner"/> this walks every registered profile, not just
/// loaded sessions, because the extension stores are plain files. Unlike it, an unreadable
/// ProfileList is a failed block rather than an empty one (absence requires authority).
///
/// The scan checks its own 30-second budget between entries. A read that blocks inside one
/// call (a profile on an unresponsive redirected share) cannot be interrupted, so the scan
/// runs on a worker task and is abandoned as failed after <see cref="HardTimeout"/>, the
/// same outer bound the macOS collector enforces by killing its parser. Never throws.
///
/// On the wire since PAT-2225: <see cref="InventoryPoster"/> puts the block in the payload
/// within its byte budget (<see cref="ToolingBlockBudget"/>). The summary line logged here is
/// how the block is checked on real devices.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class IdeExtensionScanner
{
    internal static readonly TimeSpan HardTimeout = TimeSpan.FromSeconds(45);

    private readonly ILogger<IdeExtensionScanner> _log;

    public IdeExtensionScanner(ILogger<IdeExtensionScanner> log) => _log = log;

    public InventoryIdeExtensions Collect()
    {
        InventoryIdeExtensions result;
        try
        {
            // Cancelled when the hard timeout abandons the scan, so it stops at its next
            // budget check instead of running on, touching files, after its result is dropped.
            var abandon = new CancellationTokenSource();
            var scan = Task.Run(() =>
            {
                var snapshot = WindowsUserProfiles.Snapshot(_log);
                var profiles = snapshot?.Profiles
                    .Select(p => new IdeProfileSource(p.UserAccount, p.Sid, p.ProfilePath))
                    .ToList();
                return IdeExtensionScanLogic.Scan(profiles, new IdeExtensionScanOptions { Cancellation = abandon.Token }, snapshot?.Unreadable ?? 0);
            });
            if (scan.Wait(HardTimeout))
            {
                result = scan.Result;
            }
            else
            {
                abandon.Cancel();
                _log.LogWarning("ide_extensions: scan still running after {Seconds}s, abandoned; block is failed",
                    HardTimeout.TotalSeconds);
                result = new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed };
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "ide_extensions: scan failed; block is failed");
            result = new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed };
        }

        _log.LogInformation(
            "ide_extensions: status={Status} extensions={Extensions} profiles={Profiles} users={Users} (collected)",
            result.CollectionStatus, result.Extensions?.Count ?? 0, result.Profiles.Count, result.Users.Count);
        return result;
    }
}
