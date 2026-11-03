using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Builds and atomically writes update-status.json to %ProgramData%\Patched\.
/// Single writer invariant: only this class writes the contract file; the tray reads it.
/// Atomic write: temp file in the same directory + File.Move (same-volume rename on Windows).
/// </summary>
public sealed class StatusWriter
{
    private static readonly JsonSerializerOptions JsonOpts = ContractJsonOptions.Write;

    private readonly ILogger<StatusWriter> _log;
    private UpdateStatus?                  _current;

    public StatusWriter(ILogger<StatusWriter> log) => _log = log;

    public bool HasEverWritten => _current is not null;
    public UpdateStatus? CurrentStatus => _current;

    public UpdateStatus Build(
        DateTimeOffset             startedAt,
        DateTimeOffset             finishedAt,
        string                     trigger,
        IReadOnlyList<AppEntry>    appEntries,
        DateTimeOffset             nextRun,
        OsUpdateInfo?              osUpdate = null,
        IReadOnlyList<ComplianceFinding>? complianceFindings = null,
        IReadOnlyList<string>?     requestedDeployLabels = null)
    {
        var reconciled  = ReconcileDeployResults(appEntries, requestedDeployLabels, finishedAt);
        var upToDate    = reconciled.Count(a => a.State is AppState.UpToDate or AppState.Installed);
        var available   = reconciled.Count(a => a.State is AppState.UpdateAvailable);
        var errors      = reconciled.Count(a => a.State is AppState.Error or AppState.VerificationFailed);

        var overall = errors   > 0 ? OverallState.Error
                    : available > 0 ? OverallState.UpdatesAvailable
                    : OverallState.UpToDate;

        return new UpdateStatus
        {
            SchemaVersion = 1,
            GeneratedAt   = finishedAt,
            Device        = GetDeviceInfo(),
            LastRun       = new LastRunInfo
            {
                StartedAt        = startedAt,
                FinishedAt       = finishedAt,
                Trigger          = trigger,
                InstallomatorTag = GetWingetVersionTag(),
            },
            NextScheduledRun    = nextRun,
            OverallState        = overall,
            Counts              = new Counts
            {
                Total            = reconciled.Count,
                UpToDate         = upToDate,
                UpdatesAvailable = available,
                Errors           = errors,
            },
            Apps                = reconciled,
            OsUpdate            = osUpdate,
            ComplianceFindings  = complianceFindings,
        };
    }

    /// <summary>
    /// A consumed deploy trigger is authoritative only when every requested label
    /// produces a result. Preserve label-only matching and turn unmatched labels
    /// into explicit error rows instead of reporting an empty successful run.
    /// A null request means this was not a deploy trigger and remains unchanged.
    /// </summary>
    internal static IReadOnlyList<AppEntry> ReconcileDeployResults(
        IReadOnlyList<AppEntry> appEntries,
        IReadOnlyList<string>? requestedDeployLabels,
        DateTimeOffset finishedAt)
    {
        if (requestedDeployLabels is null) return appEntries;

        var reconciled = appEntries.ToList();
        var seen = appEntries.Select(a => a.Label).ToHashSet(StringComparer.Ordinal);
        var requested = requestedDeployLabels.Distinct(StringComparer.Ordinal).ToList();

        IEnumerable<string> missing;
        if (requested.Count == 0)
            missing = ["*"];
        else if (requested.Contains("*", StringComparer.Ordinal))
            missing = appEntries.Count == 0 ? ["*"] : [];
        else
            missing = requested.Where(label => !seen.Contains(label));

        foreach (var label in missing)
        {
            var wildcard = label == "*";
            reconciled.Add(new AppEntry
            {
                Label        = label,
                Name         = wildcard ? "Install request" : label,
                State        = AppState.Error,
                LastAction   = "error",
                LastActionAt = finishedAt,
                Message      = wildcard
                    ? (requested.Count == 0
                        ? "Install request refused: the trigger did not contain any valid labels."
                        : "Install all request refused: no allowlisted apps produced a result.")
                    : "Install request refused: requested label is not in this endpoint's allowlist.",
            });
        }

        return reconciled;
    }

    public void WriteAtomic(UpdateStatus status)
    {
        Directory.CreateDirectory(PathConstants.StateDir);

        var dest = PathConstants.UpdateStatusFile;
        var tmp  = dest + ".tmp";

        try
        {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(fs, status, JsonOpts);
            }

            // File.Move with overwrite = true is atomic within the same volume (rename syscall).
            File.Move(tmp, dest, overwrite: true);
            _current = status;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to write update-status.json");
            try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
            throw;
        }
    }

    // -------------------------------------------------------------------------
    // PAT-300/481/913: compliance detection
    // -------------------------------------------------------------------------

    /// <summary>
    /// Result of a compliance detection run (PAT-913, Option B). Carries both the
    /// violations (<see cref="Findings"/>) and the positive per-control attestation
    /// (<see cref="ControlsAssessed"/> — the finding-controls whose detection ran
    /// to a determination this run). A control that a sub-check could not evaluate
    /// (WMI unavailable, an unknown BitLocker status, an enumeration exception)
    /// appears in neither list: it is Unknown, and the server applies
    /// treat_unknown_as (fail on the critical disk-encryption rule).
    /// </summary>
    public sealed record ComplianceDetection
    {
        public required IReadOnlyList<ComplianceFinding> Findings { get; init; }
        public required IReadOnlyList<string>            ControlsAssessed { get; init; }
    }

    /// <summary>
    /// Detects BitLocker (C: drive) and unencrypted removable storage via WMI, and
    /// records which of those controls actually ran a determination this cycle.
    /// Non-fatal: WMI may not be available in all environments — a control whose
    /// probe throws or returns no definite result is simply not attested.
    /// </summary>
    public static ComplianceDetection DetectComplianceFindings()
    {
        var findings = new List<ComplianceFinding>();
        var assessed = new List<string>();

        // PAT-300: BitLocker on the OS drive.
        var (diskAssessed, diskFinding) = ClassifyDiskEncryption(ProbeOsDriveProtectionStatus());
        if (diskAssessed)          assessed.Add("disk_encryption_off");
        if (diskFinding is not null) findings.Add(diskFinding);

        // PAT-481: unencrypted removable / USB storage.
        var (removableAssessed, removableFinding) = ClassifyRemovableStorage(ProbeRemovableStorageVolumes());
        if (removableAssessed)          assessed.Add("removable_storage_unencrypted");
        if (removableFinding is not null) findings.Add(removableFinding);

        return new ComplianceDetection { Findings = findings, ControlsAssessed = assessed };
    }

    /// <summary>
    /// Pure classifier for the OS-drive BitLocker sub-check (PAT-913). Splits the
    /// "did the determination run?" and "is it a violation?" decisions from the WMI
    /// probe so both are unit-testable.
    ///
    /// <paramref name="protectionStatus"/> is the raw Win32_EncryptableVolume
    /// ProtectionStatus (0 = Unprotected, 1 = Protected, 2 = Unknown), or null when
    /// the probe threw or returned no C: volume row. The control counts as assessed
    /// only on a definite 0/1 determination; a null or a 2 (Unknown) is NOT a
    /// determination — the control is dropped rather than reported as a fabricated
    /// violation, mirroring the macOS collector's "never fire on Unknown" rule.
    /// </summary>
    internal static (bool Assessed, ComplianceFinding? Finding) ClassifyDiskEncryption(uint? protectionStatus) =>
        protectionStatus switch
        {
            1 => (true,  null),                                                                    // Protected (BitLocker on) — assessed, clean
            0 => (true,  new ComplianceFinding { Id = "disk_encryption_off", Severity = ComplianceSeverity.Critical }), // Unprotected — assessed, finding
            _ => (false, null),                                                                    // null (probe error) or 2 (Unknown) — not assessed
        };

    /// <summary>
    /// Pure classifier for the removable-storage sub-check (PAT-913).
    ///
    /// <paramref name="volumes"/> is the list of plaintext removable volumes the
    /// probe found (possibly empty), or null when the enumeration threw. A null is a
    /// sub-check error — the control is dropped from controls_assessed. A non-null
    /// result (even empty) means the enumeration ran: the control is assessed, and a
    /// finding is emitted only when at least one plaintext volume was found.
    /// </summary>
    internal static (bool Assessed, ComplianceFinding? Finding) ClassifyRemovableStorage(
        IReadOnlyList<ComplianceFindingVolume>? volumes)
    {
        if (volumes is null)
            return (false, null);       // enumeration errored — not assessed
        if (volumes.Count == 0)
            return (true, null);        // ran, no plaintext removable media — assessed, clean
        return (true, new ComplianceFinding
        {
            Id       = "removable_storage_unencrypted",
            Severity = ComplianceSeverity.Medium,
            Volumes  = volumes,
        });
    }

    /// <summary>
    /// WMI probe for the OS-drive BitLocker ProtectionStatus. Returns the raw status
    /// (0/1/2) or null when WMI is unavailable or no C: EncryptableVolume row exists.
    /// </summary>
    private static uint? ProbeOsDriveProtectionStatus()
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"\\.\root\cimv2\security\MicrosoftVolumeEncryption",
                "SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'");
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                // ProtectionStatus: 0 = Unprotected, 1 = Protected (BitLocker on), 2 = Unknown
                return Convert.ToUInt32(obj["ProtectionStatus"]);
            }
        }
        catch { /* non-fatal; WMI may not be available */ }
        return null;   // probe errored or no C: volume row — control left unassessed
    }

    /// <summary>
    /// Enumerates USB/removable logical volumes via Win32_DiskDrive associations and
    /// checks each for BitLocker To Go protection. Returns the list of plaintext
    /// removable volumes (possibly empty) on a clean run, or null when the WMI
    /// enumeration throws — the null signals the sub-check did not run so the caller
    /// can drop the control from controls_assessed rather than record a false pass.
    ///
    /// Snapshot only: reflects volumes present at run time. Third-party encryption
    /// (VeraCrypt) and hardware self-encrypting drives appear as plaintext from the
    /// WMI layer — provenance_source records the API used.
    /// </summary>
    private static IReadOnlyList<ComplianceFindingVolume>? ProbeRemovableStorageVolumes()
    {
        var volumes = new List<ComplianceFindingVolume>();
        try
        {
            using var diskSearcher = new System.Management.ManagementObjectSearcher(
                "SELECT DeviceID, MediaType, InterfaceType FROM Win32_DiskDrive " +
                "WHERE MediaType='Removable Media' OR InterfaceType='USB'");
            foreach (System.Management.ManagementObject disk in diskSearcher.Get())
            {
                foreach (System.Management.ManagementObject part in
                    disk.GetRelated("Win32_DiskPartition"))
                {
                    foreach (System.Management.ManagementObject logical in
                        part.GetRelated("Win32_LogicalDisk"))
                    {
                        var letter = logical["DeviceID"]?.ToString();
                        if (string.IsNullOrEmpty(letter)) continue;

                        // Skip BitLocker To Go-protected volumes.
                        if (IsRemovableBitLockerProtected(letter)) continue;

                        var fs = logical["FileSystem"]?.ToString() ?? "unknown";
                        volumes.Add(new ComplianceFindingVolume
                        {
                            MountPoint       = letter,
                            Filesystem       = fs,
                            EncryptionState  = "plaintext",
                            ProvenanceSource = "Win32_DiskDrive",
                        });
                    }
                }
            }
        }
        catch
        {
            // Enumeration errored — return null so the control is not attested.
            return null;
        }

        return volumes;
    }

    private static bool IsRemovableBitLockerProtected(string driveLetter)
    {
        try
        {
            var scope = new System.Management.ManagementScope(
                @"\\.\root\CIMV2\Security\MicrosoftVolumeEncryption");
            scope.Connect();
            using var bde = new System.Management.ManagementObjectSearcher(scope,
                new System.Management.ObjectQuery(
                    $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='{driveLetter}'"));
            foreach (System.Management.ManagementObject vol in bde.Get())
                return Convert.ToUInt32(vol["ProtectionStatus"]) == 1;
        }
        catch { /* BitLocker WMI namespace may not be available */ }
        return false;
    }

    private static DeviceInfo GetDeviceInfo()
    {
        string? hwUuid = null;
        try
        {
            using var mos = new System.Management.ManagementObjectSearcher(
                "SELECT UUID FROM Win32_ComputerSystemProduct");
            foreach (var obj in mos.Get())
                hwUuid = obj["UUID"]?.ToString();
        }
        catch { /* non-fatal; omit hw_uuid */ }

        return new DeviceInfo
        {
            HwUuid       = hwUuid,
            ComputerName = Environment.MachineName,
        };
    }

    private static string GetWingetVersionTag()
    {
        try
        {
            var winget = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\WindowsApps\winget.exe");
            if (File.Exists(winget))
            {
                var ver = System.Diagnostics.FileVersionInfo.GetVersionInfo(winget);
                return $"winget-{ver.ProductVersion}";
            }
        }
        catch { /* non-fatal */ }
        return "winget-unknown";
    }
}
