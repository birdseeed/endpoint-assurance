using System.Management;
using System.Runtime.Versioning;
using Patched.Shared.Contract;
using Patched.Shared.HardwareHealth;

namespace Patched.Service;

/// <summary>
/// PAT-685: collects hardware health data (battery, SMART, storage volumes) via WMI/CIM
/// for the schema v3 inventory payload.
///
/// Every WMI query is wrapped in try/catch so a single failure never aborts the wider
/// collection run — this executes on customer endpoints where WMI can be partially broken.
///
/// Battery strategy (reliability order):
///   1. root\wmi BatteryStaticData  → DesignedCapacity, CycleCount
///      root\wmi BatteryFullChargedCapacity → FullChargedCapacity
///   2. Win32_Battery (root\cimv2)  → FullChargeCapacity, DesignedCapacity (often 0 on OEM)
///   Presence: Win32_Battery rows present ↔ battery installed.
///
/// SMART source: MSFT_PhysicalDisk (root\microsoft\windows\storage):
///   HealthStatus 0=Healthy, 1=Warning, 2=Unhealthy, 5=Unknown
///   MediaType    3=HDD → solid_state=false, 4=SSD / 5=SCM → true,
///                0=Unspecified or other → undetermined, disk left out (PAT-1733)
///   BusType      7=USB → internal=false
///   device key   SerialNumber, then UniqueId; never FriendlyName, which two disks of
///                the same model share (PAT-1733, see HardwareHealthLogic.DiskDeviceKey)
///
/// PAT-1720: each section also reports collection_status (complete / partial /
/// unavailable). The collector only turns WMI and DriveInfo results into readings; the
/// rows and status are decided by <see cref="HardwareHealthLogic"/> (covered by
/// Shared.Tests). A failed query is unavailable, never "no battery / volumes / disks".
/// The former MSStorageDriver_FailurePredictStatus fallback is gone: it had no bus or
/// media type, so it sent internal=true / solid_state=false as guesses under a different
/// device key, which a partial section would have upserted over the real rows.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class HardwareHealthCollector
{
    private readonly ILogger<HardwareHealthCollector> _log;

    public HardwareHealthCollector(ILogger<HardwareHealthCollector> log) => _log = log;

    /// <summary>
    /// Returns a fully-populated <see cref="InventoryHardwareHealth"/> on every call.
    /// A section that could not be read is marked partial or unavailable in
    /// <see cref="InventoryHardwareHealth.CollectionStatus"/> rather than throwing.
    /// </summary>
    public InventoryHardwareHealth Collect()
    {
        var (battery, batteryStatus) = HardwareHealthLogic.BuildBattery(ReadBattery());

        var volumeReadings = ReadVolumes(out var volumesFailed);
        var (storage, storageStatus) = HardwareHealthLogic.BuildStorage(volumeReadings, volumesFailed);

        var diskReadings = ReadPhysicalDisks(out var disksFailed);
        var (disks, disksStatus) = HardwareHealthLogic.BuildDisks(diskReadings, disksFailed,
            (disk, reason) => _log.LogDebug(
                "HardwareHealthCollector: physical disk '{FriendlyName}' left out, disks partial: {Reason}",
                disk.FriendlyName, reason));

        return new InventoryHardwareHealth
        {
            Battery = battery,
            Storage = storage,
            Disks   = disks,
            CollectionStatus = new InventoryHardwareCollectionStatus
            {
                Battery = batteryStatus,
                Storage = storageStatus,
                Disks   = disksStatus,
            },
        };
    }

    // -------------------------------------------------------------------------
    // Battery
    // -------------------------------------------------------------------------

    private BatteryReading ReadBattery()
    {
        try
        {
            // Determine presence via Win32_Battery: rows appear only when a battery exists.
            // A failed query leaves Present null (unavailable), never false.
            bool present;
            try
            {
                present = false;
                using var mos = new ManagementObjectSearcher(
                    "SELECT BatteryStatus FROM Win32_Battery");
                foreach (ManagementObject _ in mos.Get())
                {
                    present = true;
                    break;
                }
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "HardwareHealthCollector: Win32_Battery presence check failed, battery unavailable");
                return new BatteryReading { Present = null };
            }

            if (!present)
                return new BatteryReading { Present = false };

            // Primary: root\wmi classes (more reliable on modern laptops than Win32_Battery).
            var (fullCharge, designedCapacity, cycleCount) = GetRootWmiBatteryData();

            // Fallback: Win32_Battery capacity fields when root\wmi didn't provide values.
            if (fullCharge is null || designedCapacity is null)
            {
                var (fc, dc, _) = GetWin32BatteryCapacity();
                fullCharge       ??= fc;
                designedCapacity ??= dc;
            }

            return new BatteryReading
            {
                Present          = true,
                FullCharge       = fullCharge,
                DesignedCapacity = designedCapacity,
                CycleCount       = cycleCount,
            };
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: battery collection failed, battery unavailable");
            return new BatteryReading { Present = null };
        }
    }

    /// <summary>
    /// Queries root\wmi BatteryStaticData + BatteryFullChargedCapacity.
    /// Returns (null, null, null) on any failure — caller merges with Win32_Battery fallback.
    /// </summary>
    private (long? fullCharge, long? designedCapacity, int? cycleCount) GetRootWmiBatteryData()
    {
        long? fullCharge       = null;
        long? designedCapacity = null;
        int?  cycleCount       = null;

        try
        {
            var scope = new ManagementScope(@"root\wmi");
            using var mos = new ManagementObjectSearcher(
                scope, new ObjectQuery(
                    "SELECT DesignedCapacity, CycleCount FROM BatteryStaticData"));
            foreach (ManagementObject obj in mos.Get())
            {
                var dc = obj["DesignedCapacity"];
                if (dc is not null)
                {
                    var v = Convert.ToInt64(dc);
                    if (v > 0) designedCapacity = v;
                }
                var cc = obj["CycleCount"];
                if (cc is not null)
                {
                    var v = Convert.ToInt32(cc);
                    if (v > 0) cycleCount = v;
                }
                break; // first battery instance is sufficient
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: BatteryStaticData query failed");
        }

        try
        {
            var scope = new ManagementScope(@"root\wmi");
            using var mos = new ManagementObjectSearcher(
                scope, new ObjectQuery(
                    "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity"));
            foreach (ManagementObject obj in mos.Get())
            {
                var fc = obj["FullChargedCapacity"];
                if (fc is not null)
                {
                    var v = Convert.ToInt64(fc);
                    if (v > 0) fullCharge = v;
                }
                break;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: BatteryFullChargedCapacity query failed");
        }

        return (fullCharge, designedCapacity, cycleCount);
    }

    /// <summary>
    /// Win32_Battery fallback: capacity fields are often 0 on OEM firmware but
    /// worth checking before giving up.
    /// </summary>
    private (long? fullCharge, long? designedCapacity, int? cycleCount) GetWin32BatteryCapacity()
    {
        try
        {
            using var mos = new ManagementObjectSearcher(
                "SELECT FullChargeCapacity, DesignedCapacity FROM Win32_Battery");
            foreach (ManagementObject obj in mos.Get())
            {
                var fc = obj["FullChargeCapacity"];
                var dc = obj["DesignedCapacity"];
                long? fullCharge      = fc is not null ? Convert.ToInt64(fc)  : null;
                long? designedCap     = dc is not null ? Convert.ToInt64(dc)  : null;
                if (fullCharge == 0)    fullCharge   = null;
                if (designedCap == 0)   designedCap  = null;
                return (fullCharge, designedCap, null);
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: Win32_Battery capacity query failed");
        }
        return (null, null, null);
    }

    // -------------------------------------------------------------------------
    // Storage volumes
    // -------------------------------------------------------------------------

    private List<VolumeReading> ReadVolumes(out bool enumerationFailed)
    {
        enumerationFailed = false;
        var readings = new List<VolumeReading>();
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: DriveInfo.GetDrives failed, storage unavailable");
            enumerationFailed = true;
            return readings;
        }

        foreach (var drive in drives)
        {
            try
            {
                // Storage lists mounted, ready fixed volumes, the same scope as macOS df.
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "HardwareHealthCollector: could not classify a drive, storage partial");
                readings.Add(new VolumeReading());
                continue;
            }

            string? mount = null;
            long?   total = null;
            long?   free  = null;
            try { mount = drive.RootDirectory.FullName; } catch (Exception ex) { LogVolumeRead(ex); }
            try { total = drive.TotalSize; }              catch (Exception ex) { LogVolumeRead(ex); }
            try { free  = drive.AvailableFreeSpace; }     catch (Exception ex) { LogVolumeRead(ex); }
            readings.Add(new VolumeReading { Mount = mount, TotalBytes = total, FreeBytes = free });
        }
        return readings;
    }

    private void LogVolumeRead(Exception ex) =>
        _log.LogDebug(ex, "HardwareHealthCollector: volume property read failed, storage partial");

    // -------------------------------------------------------------------------
    // Physical disks (SMART)
    // -------------------------------------------------------------------------

    private List<PhysicalDiskReading> ReadPhysicalDisks(out bool enumerationFailed)
    {
        enumerationFailed = false;
        var readings = new List<PhysicalDiskReading>();
        try
        {
            var scope = new ManagementScope(@"root\microsoft\windows\storage");
            using var mos = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT FriendlyName, SerialNumber, UniqueId, HealthStatus, MediaType, BusType FROM MSFT_PhysicalDisk"));

            // WMI can throw part way through enumeration; rows read before that are kept
            // and the section becomes partial.
            foreach (ManagementObject obj in mos.Get())
            {
                readings.Add(new PhysicalDiskReading
                {
                    FriendlyName = ReadString(obj, "FriendlyName"),
                    SerialNumber = ReadIdString(obj, "SerialNumber"),
                    UniqueId     = ReadIdString(obj, "UniqueId"),
                    HealthStatus = ReadInt(obj, "HealthStatus"),
                    MediaType    = ReadInt(obj, "MediaType"),
                    BusType      = ReadInt(obj, "BusType"),
                });
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: MSFT_PhysicalDisk query failed, disks partial or unavailable");
            enumerationFailed = true;
        }
        return readings;
    }

    /// <summary>A property value as int, or null when it is absent or cannot be read or converted.</summary>
    private int? ReadInt(ManagementBaseObject obj, string property)
    {
        try
        {
            var value = obj[property];
            return value is null ? null : Convert.ToInt32(value);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: MSFT_PhysicalDisk.{Property} unreadable", property);
            return null;
        }
    }

    /// <summary>
    /// PAT-1733: an identifier property as string. "" when the read succeeded with no value,
    /// null only when the read itself failed, so HardwareHealthLogic.DiskDeviceKey can tell
    /// a disk with no serial (fall back to UniqueId) from a failed read (leave the disk out).
    /// </summary>
    private string? ReadIdString(ManagementBaseObject obj, string property)
    {
        try
        {
            return obj[property]?.ToString() ?? "";
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: MSFT_PhysicalDisk.{Property} unreadable", property);
            return null;
        }
    }

    /// <summary>A property value as string, or null when it is absent or cannot be read.</summary>
    private string? ReadString(ManagementBaseObject obj, string property)
    {
        try
        {
            return obj[property]?.ToString();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "HardwareHealthCollector: MSFT_PhysicalDisk.{Property} unreadable", property);
            return null;
        }
    }
}
