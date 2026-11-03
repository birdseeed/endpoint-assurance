using Patched.Shared.Contract;
using Patched.Shared.HardwareHealth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Platform-neutral tests for <see cref="HardwareHealthLogic"/>.
///
/// All tests call the static helpers directly — no WMI, no registry, no file I/O.
/// <see cref="HardwareHealthLogic"/> lives in Patched.Shared (net8.0, no Windows TFM)
/// so these run on any OS including macOS CI.
/// </summary>
public sealed class HardwareHealthLogicTests
{
    // -------------------------------------------------------------------------
    // ComputeHealthPct
    // -------------------------------------------------------------------------

    [Fact]
    public void ComputeHealthPct_NullFullCharge_ReturnsNull()
    {
        var result = HardwareHealthLogic.ComputeHealthPct(null, 5000);
        Assert.Null(result);
    }

    [Fact]
    public void ComputeHealthPct_NullDesignedCapacity_ReturnsNull()
    {
        var result = HardwareHealthLogic.ComputeHealthPct(4500, null);
        Assert.Null(result);
    }

    [Fact]
    public void ComputeHealthPct_ZeroDesignedCapacity_ReturnsNull()
    {
        // Prevents divide-by-zero when firmware reports 0 mWh designed capacity.
        var result = HardwareHealthLogic.ComputeHealthPct(4500, 0);
        Assert.Null(result);
    }

    [Fact]
    public void ComputeHealthPct_BothNull_ReturnsNull()
    {
        var result = HardwareHealthLogic.ComputeHealthPct(null, null);
        Assert.Null(result);
    }

    [Fact]
    public void ComputeHealthPct_100Percent_ReturnsHundred()
    {
        // Exactly full capacity.
        var result = HardwareHealthLogic.ComputeHealthPct(5000, 5000);
        Assert.Equal(100, result);
    }

    [Fact]
    public void ComputeHealthPct_87Percent_RoundsCorrectly()
    {
        // 4350 / 5000 = 87.0 %
        var result = HardwareHealthLogic.ComputeHealthPct(4350, 5000);
        Assert.Equal(87, result);
    }

    [Fact]
    public void ComputeHealthPct_SlightlyOver100_ClampedTo100()
    {
        // Some batteries report FullChargedCapacity > DesignedCapacity immediately after
        // calibration; the result must be clamped to 100.
        var result = HardwareHealthLogic.ComputeHealthPct(5100, 5000);
        Assert.Equal(100, result);
    }

    [Fact]
    public void ComputeHealthPct_ZeroFullCharge_ReturnsZero()
    {
        // Battery fully depleted or firmware reporting 0 mWh full charge.
        var result = HardwareHealthLogic.ComputeHealthPct(0, 5000);
        Assert.Equal(0, result);
    }

    [Fact]
    public void ComputeHealthPct_RoundsHalfUp()
    {
        // 3 / 6 = 50.0 % — exact midpoint rounds to 50.
        Assert.Equal(50, HardwareHealthLogic.ComputeHealthPct(3, 6));
    }

    // -------------------------------------------------------------------------
    // DeriveCondition
    // -------------------------------------------------------------------------

    [Fact]
    public void DeriveCondition_NullPct_ReturnsNull()
    {
        Assert.Null(HardwareHealthLogic.DeriveCondition(null));
    }

    [Fact]
    public void DeriveCondition_Exactly70_ReturnsNormal()
    {
        // Boundary: 70 % is still "Normal" per the mapping comment.
        Assert.Equal("Normal", HardwareHealthLogic.DeriveCondition(70));
    }

    [Fact]
    public void DeriveCondition_100_ReturnsNormal()
    {
        Assert.Equal("Normal", HardwareHealthLogic.DeriveCondition(100));
    }

    [Fact]
    public void DeriveCondition_85_ReturnsNormal()
    {
        Assert.Equal("Normal", HardwareHealthLogic.DeriveCondition(85));
    }

    [Fact]
    public void DeriveCondition_69_ReturnsReplaceSoon()
    {
        // One below the threshold → degraded battery.
        Assert.Equal("Replace Soon", HardwareHealthLogic.DeriveCondition(69));
    }

    [Fact]
    public void DeriveCondition_50_ReturnsReplaceSoon()
    {
        Assert.Equal("Replace Soon", HardwareHealthLogic.DeriveCondition(50));
    }

    [Fact]
    public void DeriveCondition_0_ReturnsReplaceSoon()
    {
        Assert.Equal("Replace Soon", HardwareHealthLogic.DeriveCondition(0));
    }

    // -------------------------------------------------------------------------
    // MapSmartStatus
    // -------------------------------------------------------------------------

    [Fact]
    public void MapSmartStatus_0_ReturnsVerified()
    {
        // HealthStatus 0 = Healthy
        Assert.Equal("Verified", HardwareHealthLogic.MapSmartStatus(0));
    }

    [Fact]
    public void MapSmartStatus_1_ReturnsFailing()
    {
        // HealthStatus 1 = Warning
        Assert.Equal("Failing", HardwareHealthLogic.MapSmartStatus(1));
    }

    [Fact]
    public void MapSmartStatus_2_ReturnsFailing()
    {
        // HealthStatus 2 = Unhealthy
        Assert.Equal("Failing", HardwareHealthLogic.MapSmartStatus(2));
    }

    [Fact]
    public void MapSmartStatus_5Unknown_ReturnsUndetermined()
    {
        // PAT-1720: HealthStatus 5 = Unknown is not a verdict; never "Failing" or "Verified".
        Assert.Equal("Undetermined", HardwareHealthLogic.MapSmartStatus(5));
    }

    [Fact]
    public void MapSmartStatus_UndefinedValue_ReturnsUndetermined()
    {
        // PAT-1720: a value Windows does not define is undetermined, not a failure claim.
        Assert.Equal("Undetermined", HardwareHealthLogic.MapSmartStatus(99));
    }

    [Fact]
    public void MapSmartStatus_Null_ReturnsUndetermined()
    {
        // PAT-1720: an unreadable HealthStatus must never default to "Verified".
        Assert.Equal("Undetermined", HardwareHealthLogic.MapSmartStatus(null));
    }

    // -------------------------------------------------------------------------
    // ComputeUsedPct
    // -------------------------------------------------------------------------

    [Fact]
    public void ComputeUsedPct_ZeroTotal_ReturnsZero()
    {
        // Prevents divide-by-zero on drives with unexpected totalBytes = 0.
        Assert.Equal(0, HardwareHealthLogic.ComputeUsedPct(0, 0));
    }

    [Fact]
    public void ComputeUsedPct_NegativeTotal_ReturnsZero()
    {
        Assert.Equal(0, HardwareHealthLogic.ComputeUsedPct(-1, 0));
    }

    [Fact]
    public void ComputeUsedPct_HalfFull_Returns50()
    {
        // 500 GiB used out of 1 TiB total = 50 %.
        var total = 1_000_000_000L;
        var free  =   500_000_000L;
        Assert.Equal(50, HardwareHealthLogic.ComputeUsedPct(total, free));
    }

    [Fact]
    public void ComputeUsedPct_CompletelyFull_Returns100()
    {
        Assert.Equal(100, HardwareHealthLogic.ComputeUsedPct(1_000_000L, 0L));
    }

    [Fact]
    public void ComputeUsedPct_CompletelyFree_Returns0()
    {
        Assert.Equal(0, HardwareHealthLogic.ComputeUsedPct(1_000_000L, 1_000_000L));
    }

    [Theory]
    [InlineData(1_000_000L, 580_000L, 42)]   // 42.0 % → 42
    [InlineData(1_000_000L, 245_000L, 76)]   // 75.5 % → 76 (rounds half-up)
    public void ComputeUsedPct_RoundsCorrectly(long total, long free, int expected)
    {
        Assert.Equal(expected, HardwareHealthLogic.ComputeUsedPct(total, free));
    }
    // -------------------------------------------------------------------------
    // PAT-1720: BuildBattery / BuildStorage / BuildDisks collection_status
    // -------------------------------------------------------------------------

    [Fact]
    public void BuildBattery_PresenceQueryFailed_IsUnavailable_NotADesktop()
    {
        var (battery, status) = HardwareHealthLogic.BuildBattery(new BatteryReading { Present = null });
        Assert.Equal(HardwareCollectionStatus.Unavailable, status);
        Assert.False(battery.Present); // schema-valid placeholder the server ignores
        Assert.Null(battery.CycleCount);
        Assert.Null(battery.Condition);
        Assert.Null(battery.MaxCapacityPct);
    }

    [Fact]
    public void BuildBattery_NoBatteryReadSuccessfully_IsCompleteDesktop()
    {
        var (battery, status) = HardwareHealthLogic.BuildBattery(new BatteryReading { Present = false });
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.False(battery.Present);
    }

    [Fact]
    public void BuildBattery_Present_ComputesFields_Complete()
    {
        var (battery, status) = HardwareHealthLogic.BuildBattery(new BatteryReading
        {
            Present = true, FullCharge = 4350, DesignedCapacity = 5000, CycleCount = 187,
        });
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.True(battery.Present);
        Assert.Equal(187, battery.CycleCount);
        Assert.Equal(87, battery.MaxCapacityPct);
        Assert.Equal("Normal", battery.Condition);
    }

    [Fact]
    public void BuildBattery_PresentButDetailsUnread_NullFieldsNotDefaults()
    {
        var (battery, status) = HardwareHealthLogic.BuildBattery(new BatteryReading { Present = true });
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.True(battery.Present);
        Assert.Null(battery.CycleCount);
        Assert.Null(battery.MaxCapacityPct);
        Assert.Null(battery.Condition);
    }

    [Fact]
    public void BuildStorage_EnumerationFailed_IsUnavailableEmpty()
    {
        var (volumes, status) = HardwareHealthLogic.BuildStorage([], enumerationFailed: true);
        Assert.Equal(HardwareCollectionStatus.Unavailable, status);
        Assert.Empty(volumes);
    }

    [Fact]
    public void BuildStorage_NoFixedVolumesReadSuccessfully_IsCompleteEmpty()
    {
        var (volumes, status) = HardwareHealthLogic.BuildStorage([], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Empty(volumes);
    }

    [Fact]
    public void BuildStorage_AllRead_IsComplete()
    {
        var (volumes, status) = HardwareHealthLogic.BuildStorage(
            [new VolumeReading { Mount = @"C:\", TotalBytes = 1_000_000L, FreeBytes = 580_000L }],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        var v = Assert.Single(volumes);
        Assert.Equal(@"C:\", v.Mount);
        Assert.Equal(42, v.UsedPct);
    }

    [Theory]
    [InlineData(null, 1_000_000L, 1L)]
    [InlineData(@"D:\", null, 1L)]
    [InlineData(@"D:\", 1_000_000L, null)]
    public void BuildStorage_UnreadableVolume_LeftOut_Partial(string? mount, long? total, long? free)
    {
        var (volumes, status) = HardwareHealthLogic.BuildStorage(
            [
                new VolumeReading { Mount = @"C:\", TotalBytes = 1_000_000L, FreeBytes = 500_000L },
                new VolumeReading { Mount = mount, TotalBytes = total, FreeBytes = free },
            ],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Equal(@"C:\", Assert.Single(volumes).Mount);
    }

    [Fact]
    public void BuildStorage_EnumerationFailedPartWay_KeepsRows_Partial()
    {
        var (volumes, status) = HardwareHealthLogic.BuildStorage(
            [new VolumeReading { Mount = @"C:\", TotalBytes = 10L, FreeBytes = 5L }],
            enumerationFailed: true);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Single(volumes);
    }

    private static PhysicalDiskReading Disk(
        string? name = "Samsung SSD 990 PRO 1TB", int? health = 0, int? media = 4, int? bus = 17,
        string? serial = "S7KHNJ0W123456A", string? uniqueId = "002538B431B2E5F1") =>
        new()
        {
            FriendlyName = name, SerialNumber = serial, UniqueId = uniqueId,
            HealthStatus = health, MediaType = media, BusType = bus,
        };

    [Fact]
    public void BuildDisks_EnumerationFailed_IsUnavailableEmpty()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([], enumerationFailed: true);
        Assert.Equal(HardwareCollectionStatus.Unavailable, status);
        Assert.Empty(disks);
    }

    [Fact]
    public void BuildDisks_NoDisksReadSuccessfully_IsCompleteEmpty()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Empty(disks);
    }

    [Fact]
    public void BuildDisks_AllRead_MapsFields_Complete()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [Disk(), Disk(name: "Seagate Expansion", health: 2, media: 3, bus: 7, serial: "NA8F1ZQX", uniqueId: "")],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Equal(2, disks.Count);
        Assert.Equal(("S7KHNJ0W123456A", "Verified", true, true),
            (disks[0].Device, disks[0].SmartStatus, disks[0].Internal, disks[0].SolidState));
        Assert.Equal(("NA8F1ZQX", "Failing", false, false),
            (disks[1].Device, disks[1].SmartStatus, disks[1].Internal, disks[1].SolidState));
    }

    // PAT-1733: two disks of the same model share FriendlyName; they must be two rows.
    [Fact]
    public void BuildDisks_SameFriendlyName_DistinctSerials_TwoRows_Complete()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [
                Disk(name: "Samsung SSD 990 PRO 1TB", serial: "S7KHNJ0W111111A", uniqueId: "002538B431B2E5F1"),
                Disk(name: "Samsung SSD 990 PRO 1TB", serial: "S7KHNJ0W222222B", uniqueId: "002538B431B2E5F2"),
            ],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Equal(["S7KHNJ0W111111A", "S7KHNJ0W222222B"], disks.Select(d => d.Device));
    }

    [Fact]
    public void BuildDisks_SameFriendlyName_NoSerials_KeyedByUniqueId_TwoRows()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [
                Disk(name: "Msft Virtual Disk", serial: "", uniqueId: "60022480A1B2C3D4E5F6000000000001"),
                Disk(name: "Msft Virtual Disk", serial: "   ", uniqueId: "60022480A1B2C3D4E5F6000000000002"),
            ],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Equal(
            ["60022480A1B2C3D4E5F6000000000001", "60022480A1B2C3D4E5F6000000000002"],
            disks.Select(d => d.Device));
    }

    [Fact]
    public void BuildDisks_DuplicateKeys_AllCollidingDisksLeftOut_Partial()
    {
        // Cheap USB bridges can report one serial for every enclosure; never emit a shared key.
        var reasons = new List<string>();
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [
                Disk(name: "Internal", serial: "UNIQUE-1"),
                Disk(name: "USB A", bus: 7, serial: "000000000000"),
                Disk(name: "USB B", bus: 7, serial: "000000000000"),
            ],
            enumerationFailed: false,
            (d, reason) => reasons.Add($"{d.FriendlyName}: {reason}"));
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Equal("UNIQUE-1", Assert.Single(disks).Device);
        Assert.Equal(2, reasons.Count);
        Assert.All(reasons, r => Assert.Contains("shared", r));
    }

    [Fact]
    public void BuildDisks_NeverUsesFriendlyNameAsDevice()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [Disk(name: "QEMU NVMe Ctrl", serial: "", uniqueId: "")], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Empty(disks);
    }

    [Fact]
    public void DiskDeviceKey_StagingVmQemuNvme_UsesSerialNumber()
    {
        // Values read from MSFT_PhysicalDisk on the Windows staging VM (PAT-1733).
        var key = HardwareHealthLogic.DiskDeviceKey(new PhysicalDiskReading
        {
            FriendlyName = "QEMU NVMe Ctrl",
            SerialNumber = "77267C90-1768-4C90-8_00000001.",
            UniqueId     = "1B36QEMU NVMe Ctrl                          000177267C90-1768-4C90-8",
        });
        Assert.Equal("77267C90-1768-4C90-8_00000001.", key);
    }

    [Fact]
    public void DiskDeviceKey_TrimsWhitespaceAndNulPadding()
    {
        Assert.Equal("WD-WCC4E1234567", HardwareHealthLogic.DiskDeviceKey(
            new PhysicalDiskReading { SerialNumber = "  WD-WCC4E1234567\0\0 ", UniqueId = "x" }));
    }

    [Fact]
    public void DiskDeviceKey_SerialReadFailed_NoFallback_ReturnsNull()
    {
        // A failed serial read must not flip the disk onto its UniqueId key for one run.
        Assert.Null(HardwareHealthLogic.DiskDeviceKey(
            new PhysicalDiskReading { SerialNumber = null, UniqueId = "002538B431B2E5F1" }));
    }

    [Fact]
    public void DiskDeviceKey_EmptySerial_UniqueIdReadFailed_ReturnsNull()
    {
        Assert.Null(HardwareHealthLogic.DiskDeviceKey(
            new PhysicalDiskReading { SerialNumber = "", UniqueId = null }));
    }

    [Fact]
    public void DiskDeviceKey_SerialWithControlChar_FallsBackToUniqueId()
    {
        Assert.Equal("002538B431B2E5F1", HardwareHealthLogic.DiskDeviceKey(
            new PhysicalDiskReading { SerialNumber = "AB\u0001CD", UniqueId = "002538B431B2E5F1" }));
    }

    [Fact]
    public void DiskDeviceKey_OverLengthCap_NotTruncated_FallsBack()
    {
        var tooLong = new string('A', HardwareHealthLogic.MaxDiskDeviceKeyLength + 1);
        var atCap   = new string('B', HardwareHealthLogic.MaxDiskDeviceKeyLength);
        Assert.Equal(atCap, HardwareHealthLogic.DiskDeviceKey(
            new PhysicalDiskReading { SerialNumber = tooLong, UniqueId = atCap }));
        Assert.Null(HardwareHealthLogic.DiskDeviceKey(
            new PhysicalDiskReading { SerialNumber = tooLong, UniqueId = tooLong }));
    }

    [Theory]
    [InlineData(3, false)]
    [InlineData(4, true)]
    [InlineData(5, true)]   // SCM
    [InlineData(0, null)]   // Unspecified: undetermined, not false
    [InlineData(1, null)]   // not defined for MSFT_PhysicalDisk
    [InlineData(null, null)]
    public void MapSolidState_MapsMediaType(int? media, bool? expected)
    {
        Assert.Equal(expected, HardwareHealthLogic.MapSolidState(media));
    }

    [Fact]
    public void BuildDisks_MediaTypeUnspecified_LeftOut_Partial_NotSolidStateFalse()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [Disk(), Disk(name: "Virtual NVMe", media: 0, serial: "VNVME-0001")],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.DoesNotContain(disks, d => d.Device == "VNVME-0001");
        Assert.Equal("S7KHNJ0W123456A", Assert.Single(disks).Device);
    }

    [Fact]
    public void BuildDisks_MediaTypeScm_SolidStateTrue()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([Disk(media: 5)], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.True(Assert.Single(disks).SolidState);
    }

    [Theory]
    [InlineData(null, "", 4, 17)]        // SerialNumber read failed: key source unknown
    [InlineData("", "", 4, 17)]          // no serial and no UniqueId
    [InlineData("SER-2", "", null, 17)]  // MediaType unreadable: solid_state unknown
    [InlineData("SER-2", "", 0, 17)]     // MediaType Unspecified: solid_state unknown
    [InlineData("SER-2", "", 4, null)]   // BusType unreadable: internal unknown
    public void BuildDisks_RequiredPropertyUnreadable_LeftOut_Partial(
        string? serial, string? uniqueId, int? media, int? bus)
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks(
            [Disk(), Disk(serial: serial, uniqueId: uniqueId, media: media, bus: bus)],
            enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Equal("S7KHNJ0W123456A", Assert.Single(disks).Device);
    }

    [Fact]
    public void BuildDisks_FriendlyNameUnreadable_StillKeyedBySerial_Complete()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([Disk(name: null)], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Equal("S7KHNJ0W123456A", Assert.Single(disks).Device);
    }

    [Fact]
    public void BuildDisks_SoleDiskUnreadable_EmptyButPartial_NeverCompleteZero()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([Disk(bus: null)], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Empty(disks);
    }

    [Fact]
    public void BuildDisks_HealthStatusUnreadable_KeptAsUndetermined_Complete()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([Disk(health: null)], enumerationFailed: false);
        Assert.Equal(HardwareCollectionStatus.Complete, status);
        Assert.Equal("Undetermined", Assert.Single(disks).SmartStatus);
    }

    [Fact]
    public void BuildDisks_EnumerationFailedPartWay_KeepsRows_Partial()
    {
        var (disks, status) = HardwareHealthLogic.BuildDisks([Disk()], enumerationFailed: true);
        Assert.Equal(HardwareCollectionStatus.Partial, status);
        Assert.Single(disks);
    }
}
