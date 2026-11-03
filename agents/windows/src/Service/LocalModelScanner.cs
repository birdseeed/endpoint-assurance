using System.Runtime.Versioning;
using Patched.Shared.Contract;
using Patched.Shared.LocalModels;
using Patched.Shared.UserTrees;

namespace Patched.Service;

/// <summary>
/// PAT-2019: local model runtimes (Ollama, LM Studio, llama.cpp) and their model stores for
/// the machine and every profile in HKLM ProfileList, run with the daily inventory. Parity
/// with macos/lib/local_models.sh; the file work and every hardening rule live in
/// <see cref="LocalModelScanLogic"/>, <see cref="PeVersionReader"/> and
/// <see cref="UserTreeReader"/>. Nothing is executed and nothing touches the network: no
/// runtime is started and no local API is called. Names and sizes only.
///
/// An unreadable ProfileList fails the per-user half of every runtime rather than reporting
/// it empty (absence requires authority).
///
/// The scan checks its own 30-second budget between entries. A read that blocks inside one
/// call (a model store on a disk that has gone away) cannot be interrupted, so the scan runs
/// on a worker task and is abandoned as failed after <see cref="HardTimeout"/>, the same outer
/// bound the macOS collector enforces by killing its parser. Never throws.
///
/// On the wire since PAT-2225: <see cref="InventoryPoster"/> puts the block in the payload
/// within its byte budget (<see cref="ToolingBlockBudget"/>). The summary line logged here is
/// how the block is checked on real devices.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class LocalModelScanner
{
    internal static readonly TimeSpan HardTimeout = TimeSpan.FromSeconds(45);

    private readonly ILogger<LocalModelScanner> _log;

    public LocalModelScanner(ILogger<LocalModelScanner> log) => _log = log;

    public InventoryLocalModels Collect()
    {
        InventoryLocalModels result;
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
                return LocalModelScanLogic.Scan(profiles, new LocalModelScanOptions { Cancellation = abandon.Token }, snapshot?.Unreadable ?? 0);
            });
            if (scan.Wait(HardTimeout))
            {
                result = scan.Result;
            }
            else
            {
                abandon.Cancel();
                _log.LogWarning("local_models: scan still running after {Seconds}s, abandoned; block is failed",
                    HardTimeout.TotalSeconds);
                result = new InventoryLocalModels { CollectionStatus = PackageCollectionStatus.Failed };
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "local_models: scan failed; block is failed");
            result = new InventoryLocalModels { CollectionStatus = PackageCollectionStatus.Failed };
        }

        string Runtime(string r) => result.Runtimes.TryGetValue(r, out var v) ? v.CollectionStatus : PackageCollectionStatus.Failed;
        _log.LogInformation(
            "local_models: status={Status} ollama={Ollama} lm_studio={LmStudio} llama_cpp={LlamaCpp} installations={Installations} models={Models} bytes={Bytes} users={Users} (collected)",
            result.CollectionStatus, Runtime(LocalModelRuntime.Ollama), Runtime(LocalModelRuntime.LmStudio),
            Runtime(LocalModelRuntime.LlamaCpp), result.Installations.Count, result.Totals.ModelCount,
            result.Totals.TotalBytes, result.Users.Count);
        return result;
    }
}
