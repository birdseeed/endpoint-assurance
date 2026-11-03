using Patched.Shared.Contract;

namespace Patched.Shared.HardwareHealth;

/// <summary>
/// PAT-685: pure, platform-neutral mapping functions for hardware health data.
/// Lives in Shared (no Windows TFM) so it can be covered by Shared.Tests running on
/// macOS CI without any WMI dependency.  HardwareHealthCollector (Service) calls these
/// helpers after obtaining the raw numbers from WMI.
/// </summary>
internal static class HardwareHealthLogic
{
    /// <summary>
    /// Derives the battery condition string from the computed health percentage.
    /// Windows has no direct "Condition" equivalent (macOS uses IOPSCopyPowerSourcesInfo),
    /// so we map from the health percentage:
    ///   health &gt;= 70 % or unknown → "Normal"
    ///   health &lt;  70 %            → "Replace Soon"
    ///
    /// The 70 % threshold is conservative: Apple flags at 80 % ("Service Recommended")
    /// but enterprise cost/reliability grounds benefit from earlier alerting.
    /// Returns null when <paramref name="maxCapacityPct"/> is null (capacity unknown).
    /// </summary>
    public static string? DeriveCondition(int? maxCapacityPct)
    {
        if (maxCapacityPct is null) return null;
        return maxCapacityPct >= 70 ? "Normal" : "Replace Soon";
    }

    /// <summary>
    /// Computes battery health as an integer percentage from the WMI capacity values.
    /// Both <paramref name="fullCharge"/> and <paramref name="designedCapacity"/> are in
    /// the same unit (mWh from BatteryStaticData / BatteryFullChargedCapacity or
    /// Win32_Battery.FullChargeCapacity / DesignedCapacity).
    ///
    /// Returns null when either input is null or <paramref name="designedCapacity"/> is 0
    /// to prevent divide-by-zero and avoid reporting meaningless zeros.
    /// Result is clamped to [0, 100] — some batteries report slightly over 100 % at full.
    /// </summary>
    public static int? ComputeHealthPct(long? fullCharge, long? designedCapacity)
    {
        if (fullCharge is null || designedCapacity is null || designedCapacity == 0)
            return null;

        var raw = (double)fullCharge.Value / designedCapacity.Value * 100.0;
        return Math.Clamp((int)Math.Round(raw), 0, 100);
    }

    /// <summary>SMART status for a disk whose health could not be read (PAT-1720).</summary>
    public const string SmartUndetermined = "Undetermined";

    /// <summary>
    /// Maps an MSFT_PhysicalDisk HealthStatus integer to a SMART status string.
    ///   0 = Healthy   → "Verified"
    ///   1 = Warning   → "Failing"
    ///   2 = Unhealthy → "Failing"
    ///   5 = Unknown, any other value, or null (property unreadable) → "Undetermined"
    ///
    /// PAT-1720: an unreadable or unknown health value is never reported as a verdict
    /// either way. The go-service extractor treats anything other than "Verified" as a
    /// flag, so "Undetermined" still never reads as healthy.
    /// </summary>
    public static string MapSmartStatus(int? healthStatus) => healthStatus switch
    {
        0    => "Verified",
        1    => "Failing",
        2    => "Failing",
        _    => SmartUndetermined,
    };

    /// <summary>
    /// Computes used-space percentage as an integer in [0, 100].
    /// Returns 0 when <paramref name="totalBytes"/> is &lt;= 0 to prevent divide-by-zero.
    /// </summary>
    public static int ComputeUsedPct(long totalBytes, long freeBytes)
    {
        if (totalBytes <= 0) return 0;
        var used = totalBytes - freeBytes;
        return Math.Clamp((int)Math.Round((double)used / totalBytes * 100.0), 0, 100);
    }
    // -------------------------------------------------------------------------
    // PAT-1720: section builders. The Service collector turns WMI / DriveInfo results
    // into the plain readings below; these decide the rows and the collection_status
    // so the rules are covered by Shared.Tests on any OS. Every failure path resolves
    // to partial or unavailable, never to complete.
    // -------------------------------------------------------------------------

    /// <summary>
    /// Builds the battery object and its status.
    ///   presence query failed (<see cref="BatteryReading.Present"/> null) → placeholder
    ///     {present:false}, unavailable (not "no battery")
    ///   presence query succeeded, no battery → {present:false}, complete (a real desktop)
    ///   battery present → per-field nulls where a detail query returned nothing, complete
    ///     (same as macOS when system_profiler succeeds without a field)
    /// </summary>
    public static (InventoryBattery Battery, string Status) BuildBattery(BatteryReading reading)
    {
        if (reading.Present is null)
            return (new InventoryBattery { Present = false }, HardwareCollectionStatus.Unavailable);

        if (reading.Present == false)
            return (new InventoryBattery { Present = false }, HardwareCollectionStatus.Complete);

        var maxCapacityPct = ComputeHealthPct(reading.FullCharge, reading.DesignedCapacity);
        return (new InventoryBattery
        {
            Present        = true,
            CycleCount     = reading.CycleCount,
            Condition      = DeriveCondition(maxCapacityPct),
            MaxCapacityPct = maxCapacityPct,
        }, HardwareCollectionStatus.Complete);
    }

    /// <summary>
    /// Builds the storage rows and status from fixed, ready volumes.
    ///   enumeration failed with nothing read → [], unavailable
    ///   enumeration failed part way, or a volume's size could not be read → rows that
    ///     were read, partial (the unreadable volume is left out, never sent as zero)
    ///   otherwise → complete
    /// </summary>
    public static (IReadOnlyList<InventoryStorageVolume> Volumes, string Status) BuildStorage(
        IReadOnlyList<VolumeReading> readings, bool enumerationFailed)
    {
        var volumes = new List<InventoryStorageVolume>();
        var partial = enumerationFailed;
        foreach (var r in readings)
        {
            if (string.IsNullOrWhiteSpace(r.Mount) || r.TotalBytes is null || r.FreeBytes is null)
            {
                partial = true;
                continue;
            }
            volumes.Add(new InventoryStorageVolume
            {
                Mount      = r.Mount,
                TotalBytes = r.TotalBytes.Value,
                FreeBytes  = r.FreeBytes.Value,
                UsedPct    = ComputeUsedPct(r.TotalBytes.Value, r.FreeBytes.Value),
            });
        }

        if (enumerationFailed && readings.Count == 0)
            return (volumes, HardwareCollectionStatus.Unavailable);
        return (volumes, partial ? HardwareCollectionStatus.Partial : HardwareCollectionStatus.Complete);
    }

    /// <summary>
    /// Builds the physical-disk rows and status.
    ///   enumeration failed with nothing read → [], unavailable
    ///   enumeration failed part way → rows that were read, partial
    ///   a disk with no usable device key (<see cref="DiskDeviceKey"/>), or whose MediaType
    ///     or BusType could not be read or is undetermined → left out, partial.
    ///     internal and solid_state are required booleans with no null in the contract, so
    ///     any value would be a claim (internal=true for a USB disk, solid_state=false for
    ///     an SSD). The server upserts every row a partial section sends, so a guessed row
    ///     would overwrite the stored, correct one; a left-out row is kept as stored, and
    ///     partial stops the server deleting it. Same rule as macOS.
    ///   two or more disks that resolve to the same device key → all of them left out,
    ///     partial (PAT-1733). The server matches partial rows on (device_hardware_id, device_node), so
    ///     a shared key would let one disk overwrite the other; neither is emitted rather
    ///     than guessing which one owns the stored row.
    ///   a disk whose HealthStatus alone could not be read → kept, smart_status
    ///     "Undetermined"; the row is otherwise fully read so it does not make the section
    ///     partial
    /// <paramref name="onLeftOut"/>, when given, is told about each disk left out and why,
    /// so the collector can log it with the FriendlyName for diagnosis.
    /// </summary>
    public static (IReadOnlyList<InventoryDisk> Disks, string Status) BuildDisks(
        IReadOnlyList<PhysicalDiskReading> readings, bool enumerationFailed,
        Action<PhysicalDiskReading, string>? onLeftOut = null)
    {
        var candidates = new List<(PhysicalDiskReading Reading, string Key, bool SolidState, bool Internal)>();
        var partial = enumerationFailed;
        foreach (var r in readings)
        {
            var key = DiskDeviceKey(r);
            var solidState = MapSolidState(r.MediaType);
            string? reason =
                key is null        ? "no stable device key (SerialNumber and UniqueId empty, unreadable or unusable)" :
                solidState is null ? "MediaType unreadable or undetermined" :
                r.BusType is null  ? "BusType unreadable" :
                null;
            if (reason is not null)
            {
                partial = true;
                onLeftOut?.Invoke(r, reason);
                continue;
            }
            // BusType 7 = USB → external; all other bus types = internal.
            candidates.Add((r, key!, solidState!.Value, r.BusType!.Value != 7));
        }

        var keyCounts = candidates
            .GroupBy(c => c.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        var disks = new List<InventoryDisk>();
        foreach (var c in candidates)
        {
            if (keyCounts[c.Key] > 1)
            {
                partial = true;
                onLeftOut?.Invoke(c.Reading, "device key shared with another disk");
                continue;
            }
            disks.Add(new InventoryDisk
            {
                Device      = c.Key,
                SmartStatus = MapSmartStatus(c.Reading.HealthStatus),
                Internal    = c.Internal,
                SolidState  = c.SolidState,
            });
        }

        if (enumerationFailed && readings.Count == 0)
            return (disks, HardwareCollectionStatus.Unavailable);
        return (disks, partial ? HardwareCollectionStatus.Partial : HardwareCollectionStatus.Complete);
    }

    /// <summary>Longest device key emitted (PAT-1733). Server column is device_disk.device_node TEXT.</summary>
    public const int MaxDiskDeviceKeyLength = 128;

    /// <summary>
    /// PAT-1733: the value sent as disks[].device for one MSFT_PhysicalDisk.
    ///
    /// The server keys disk rows by device_node, so the value must be unique per disk and
    /// stable across reboots: a value that moves causes delete/insert churn on a complete
    /// ingest and a duplicate row on a partial one. Candidates, as seen on real hardware
    /// and on the QEMU NVMe disk of the Windows staging VM:
    ///   FriendlyName  model name ("QEMU NVMe Ctrl"); identical for two disks of one model.
    ///                 The original key, and the PAT-1733 collision. Never used.
    ///   DeviceId      small integer ("0"); renumbers when disks are added or removed.
    ///   ObjectId      embeds the computer name ("{1}\\WIN-STAGING\root/...") so it moves
    ///                 on a rename; long.
    ///   SerialNumber  "77267C90-1768-4C90-8_00000001." on the VM; the drive's own serial
    ///                 (NVMe disks carry a namespace suffix), stable across reboots and
    ///                 renames, and what an operator can match against the label.
    ///   UniqueId      page 83 / EUI-64 / vendor-built id ("1B36QEMU NVMe Ctrl ... 0001
    ///                 77267C90-1768-4C90-8" on the VM); stable, and present on disks with
    ///                 no serial, such as some virtual disks.
    /// Order: trimmed SerialNumber, then trimmed UniqueId. The fallback is taken only when
    /// the serial was read and is genuinely empty or unusable, never when its read failed,
    /// so a transient WMI error cannot flip one disk between two keys. A value is unusable
    /// when it contains control characters (Postgres TEXT rejects NUL) or is longer than
    /// <see cref="MaxDiskDeviceKeyLength"/>; truncation is not used because the unique
    /// part of a long id is often its tail. Values are otherwise sent verbatim.
    /// Returns null when no usable key exists, and BuildDisks leaves the disk out.
    /// Uniqueness across disks is enforced by BuildDisks, not here.
    /// </summary>
    public static string? DiskDeviceKey(PhysicalDiskReading reading)
    {
        if (reading.SerialNumber is null) return null; // read failed: key source unknown
        var serial = NormaliseDiskId(reading.SerialNumber);
        if (serial is not null) return serial;

        if (reading.UniqueId is null) return null;
        return NormaliseDiskId(reading.UniqueId);
    }

    private static string? NormaliseDiskId(string value)
    {
        var trimmed = value.Trim().Trim('\0').Trim();
        if (trimmed.Length == 0 || trimmed.Length > MaxDiskDeviceKeyLength) return null;
        foreach (var ch in trimmed)
            if (char.IsControl(ch)) return null;
        return trimmed;
    }

    /// <summary>
    /// PAT-1733: maps MSFT_PhysicalDisk MediaType to solid_state.
    ///   3 = HDD → false
    ///   4 = SSD → true
    ///   5 = SCM (storage-class memory) → true
    ///   0 = Unspecified (common on virtual disks and some NVMe controllers), any other
    ///     value, or null (unreadable) → null, undetermined. solid_state has no null in the
    ///     contract, so BuildDisks leaves such a disk out rather than claim false.
    /// </summary>
    public static bool? MapSolidState(int? mediaType) => mediaType switch
    {
        3 => false,
        4 => true,
        5 => true,
        _ => null,
    };
}

/// <summary>
/// PAT-1720: what the battery WMI queries returned. <see cref="Present"/> is null when the
/// presence query itself failed, so a failure can never be mistaken for a desktop.
/// </summary>
internal sealed record BatteryReading
{
    public bool? Present          { get; init; }
    public long? FullCharge       { get; init; }
    public long? DesignedCapacity { get; init; }
    public int?  CycleCount       { get; init; }
}

/// <summary>PAT-1720: one fixed, ready volume. A null field means that property threw.</summary>
internal sealed record VolumeReading
{
    public string? Mount      { get; init; }
    public long?   TotalBytes { get; init; }
    public long?   FreeBytes  { get; init; }
}

/// <summary>
/// PAT-1720: one MSFT_PhysicalDisk row. A null field means the property was absent or
/// could not be read or converted, except <see cref="SerialNumber"/> and
/// <see cref="UniqueId"/> (PAT-1733): for those, null means the read failed and "" means
/// the read succeeded with no value, so a failed read never falls through to another key.
/// <see cref="FriendlyName"/> is for diagnostics only and is never sent as the device key.
/// </summary>
internal sealed record PhysicalDiskReading
{
    public string? FriendlyName { get; init; }
    public string? SerialNumber { get; init; }
    public string? UniqueId     { get; init; }
    public int?    HealthStatus { get; init; }
    public int?    MediaType    { get; init; }
    public int?    BusType      { get; init; }
}
