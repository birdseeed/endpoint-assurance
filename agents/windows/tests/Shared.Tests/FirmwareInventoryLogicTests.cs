using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Patched.Shared.Firmware;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2262: the firmware block's rules, off-box. Every WMI property arrives as a
/// <see cref="SourceRead"/>; these tests prove that a failed read is never a value, that an
/// empty or failed collection is never complete, and that every string is bounded.
/// </summary>
public sealed class FirmwareInventoryLogicTests
{
    private static SourceRead P(object value) => SourceRead.Present(value);

    private static FirmwareSources Full() => new(
        BiosManufacturer:      P("LENOVO"),
        BiosVersion:           P("N3HET82W (1.54 )"),
        SmbiosMajorVersion:    P((ushort)3),
        SmbiosMinorVersion:    P((ushort)2),
        BiosReleaseDate:       P("20230512000000.000000+000"),
        SystemManufacturer:    P("LENOVO"),
        SystemModel:           P("20XW0026UK"),
        BaseboardManufacturer: P("LENOVO"),
        BaseboardProduct:      P("20XW0026UK"));

    private static FirmwareSources AllFailed() => new(
        SourceRead.Failed, SourceRead.Failed, SourceRead.Failed, SourceRead.Failed, SourceRead.Failed,
        SourceRead.Failed, SourceRead.Failed, SourceRead.Failed, SourceRead.Failed);

    private static FirmwareSources AllAbsent() => new(
        SourceRead.Absent, SourceRead.Absent, SourceRead.Absent, SourceRead.Absent, SourceRead.Absent,
        SourceRead.Absent, SourceRead.Absent, SourceRead.Absent, SourceRead.Absent);

    // -------------------------------------------------------------------------
    // Complete
    // -------------------------------------------------------------------------

    [Fact]
    public void CompleteCollection_ReportsEveryValue_AndNoErrors()
    {
        var fw = FirmwareInventoryLogic.Build(Full());

        Assert.Equal(1, fw.SchemaVersion);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.CollectionStatus);
        Assert.Empty(fw.Errors);

        Assert.NotNull(fw.Bios);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.Bios!.CollectionStatus);
        Assert.Equal("LENOVO", fw.Bios.Manufacturer);
        Assert.Equal("N3HET82W (1.54 )", fw.Bios.Version);
        Assert.Equal("3.2", fw.Bios.SmbiosVersion);
        Assert.Equal("2023-05-12", fw.Bios.ReleaseDate);
        Assert.Null(fw.Bios.ReleaseDateRaw);

        Assert.Equal(FirmwareCollectionStatus.Complete, fw.System!.CollectionStatus);
        Assert.Equal("LENOVO", fw.System.Manufacturer);
        Assert.Equal("20XW0026UK", fw.System.Model);

        Assert.Equal(FirmwareCollectionStatus.Complete, fw.Baseboard!.CollectionStatus);
        Assert.Equal("LENOVO", fw.Baseboard.Manufacturer);
        Assert.Equal("20XW0026UK", fw.Baseboard.Product);
    }

    [Fact]
    public void ValuesAreTrimmed()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { SystemModel = P("  Virtual Machine \t") });

        Assert.Equal("Virtual Machine", fw.System!.Model);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.CollectionStatus);
    }

    [Fact]
    public void AbsentProperty_IsNullButStillComplete()
    {
        // A VM's baseboard often has no product: the read succeeded and the firmware
        // simply does not populate it. That is a fact, not a gap.
        var fw = FirmwareInventoryLogic.Build(Full() with
        {
            BaseboardProduct = SourceRead.Absent,
            BaseboardManufacturer = P("   "),
        });

        Assert.Equal(FirmwareCollectionStatus.Complete, fw.CollectionStatus);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.Baseboard!.CollectionStatus);
        Assert.Null(fw.Baseboard.Product);
        Assert.Null(fw.Baseboard.Manufacturer);
        Assert.Empty(fw.Errors);
    }

    // -------------------------------------------------------------------------
    // Partial
    // -------------------------------------------------------------------------

    [Fact]
    public void OneClassFailed_IsPartial_WithThatSectionUnavailableAndItsValuesWithheld()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with
        {
            BaseboardManufacturer = SourceRead.Failed,
            BaseboardProduct      = SourceRead.Failed,
        });

        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Equal(new[] { FirmwareErrorCode.BaseboardQueryFailed }, fw.Errors);

        Assert.Equal(FirmwareCollectionStatus.Unavailable, fw.Baseboard!.CollectionStatus);
        Assert.Null(fw.Baseboard.Manufacturer);
        Assert.Null(fw.Baseboard.Product);

        // The classes that were read are still reported in full.
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.Bios!.CollectionStatus);
        Assert.Equal("N3HET82W (1.54 )", fw.Bios.Version);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.System!.CollectionStatus);
    }

    [Fact]
    public void BiosClassFailed_IsPartial_NotComplete()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with
        {
            BiosManufacturer   = SourceRead.Failed,
            BiosVersion        = SourceRead.Failed,
            SmbiosMajorVersion = SourceRead.Failed,
            SmbiosMinorVersion = SourceRead.Failed,
            BiosReleaseDate    = SourceRead.Failed,
        });

        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Equal(FirmwareCollectionStatus.Unavailable, fw.Bios!.CollectionStatus);
        Assert.Contains(FirmwareErrorCode.BiosQueryFailed, fw.Errors);
        Assert.Null(fw.Bios.Version);
        Assert.Null(fw.Bios.ReleaseDate);
    }

    [Fact]
    public void OnePropertyFailed_IsPartialSection_AndNeverAValue()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { BiosVersion = SourceRead.Failed });

        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.Bios!.CollectionStatus);
        Assert.Null(fw.Bios.Version);
        Assert.Equal("LENOVO", fw.Bios.Manufacturer);
        Assert.Equal(new[] { FirmwareErrorCode.BiosPropertyFailed }, fw.Errors);
    }

    [Fact]
    public void SmbiosVersion_OneHalfFailed_IsPartialAndOmitted()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { SmbiosMinorVersion = SourceRead.Failed });

        Assert.Null(fw.Bios!.SmbiosVersion);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.Bios.CollectionStatus);
        Assert.Contains(FirmwareErrorCode.BiosPropertyFailed, fw.Errors);
    }

    [Fact]
    public void SmbiosVersion_OneHalfAbsent_IsOmittedButComplete()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { SmbiosMajorVersion = SourceRead.Absent });

        Assert.Null(fw.Bios!.SmbiosVersion);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.CollectionStatus);
    }

    [Theory]
    [InlineData("3")]
    [InlineData(-1)]
    [InlineData(70000)]
    [InlineData(3.5)]
    public void SmbiosVersion_NonIntegralOrOutOfRange_IsUnusable(object major)
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { SmbiosMajorVersion = P(major) });

        Assert.Null(fw.Bios!.SmbiosVersion);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.Bios.CollectionStatus);
        Assert.Contains(FirmwareErrorCode.BiosValueUnusable, fw.Errors);
    }

    [Fact]
    public void SmbiosVersion_AcceptsAnyIntegralWmiType()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with
        {
            SmbiosMajorVersion = P(3u),
            SmbiosMinorVersion = P((byte)4),
        });

        Assert.Equal("3.4", fw.Bios!.SmbiosVersion);
    }

    // -------------------------------------------------------------------------
    // Unavailable
    // -------------------------------------------------------------------------

    [Fact]
    public void WmiTotalFailure_IsUnavailable_WithBoundedErrors_AndNoSections()
    {
        var fw = FirmwareInventoryLogic.Build(AllFailed());

        Assert.Equal(FirmwareCollectionStatus.Unavailable, fw.CollectionStatus);
        Assert.Null(fw.Bios);
        Assert.Null(fw.System);
        Assert.Null(fw.Baseboard);
        Assert.Equal(
            new[]
            {
                FirmwareErrorCode.BiosQueryFailed,
                FirmwareErrorCode.SystemQueryFailed,
                FirmwareErrorCode.BaseboardQueryFailed,
            },
            fw.Errors);
        Assert.True(fw.Errors.Count <= FirmwareErrorCode.MaxErrors);
    }

    [Fact]
    public void EveryQuerySucceededWithNothing_IsUnavailable_NeverEmptySuccess()
    {
        var fw = FirmwareInventoryLogic.Build(AllAbsent());

        Assert.Equal(FirmwareCollectionStatus.Unavailable, fw.CollectionStatus);
        Assert.Null(fw.Bios);
        Assert.Null(fw.System);
        Assert.Null(fw.Baseboard);
        Assert.Equal(new[] { FirmwareErrorCode.NoFirmwareValues }, fw.Errors);
    }

    [Fact]
    public void OnlyUnusableValues_IsUnavailable()
    {
        var control = P("bad\u0000value");
        var fw = FirmwareInventoryLogic.Build(new FirmwareSources(
            control, control, SourceRead.Absent, SourceRead.Absent, SourceRead.Absent,
            control, control, SourceRead.Failed, SourceRead.Failed));

        Assert.Equal(FirmwareCollectionStatus.Unavailable, fw.CollectionStatus);
        Assert.Null(fw.Bios);
        Assert.Contains(FirmwareErrorCode.NoFirmwareValues, fw.Errors);
        Assert.Contains(FirmwareErrorCode.BiosValueUnusable, fw.Errors);
        Assert.Contains(FirmwareErrorCode.BaseboardQueryFailed, fw.Errors);
    }

    [Fact]
    public void UnparseableDateAlone_IsPartial_BecauseTheRawDateIsEvidence()
    {
        // A raw release date is evidence, so the block is partial, not unavailable.
        var fw = FirmwareInventoryLogic.Build(AllAbsent() with { BiosReleaseDate = P("not a date") });

        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Equal("not a date", fw.Bios!.ReleaseDateRaw);
        Assert.Null(fw.Bios.ReleaseDate);
    }

    // -------------------------------------------------------------------------
    // String bounding
    // -------------------------------------------------------------------------

    [Fact]
    public void ValueAtTheBound_IsKept()
    {
        var atBound = new string('A', FirmwareInventoryLogic.MaxValueLength);
        var fw = FirmwareInventoryLogic.Build(Full() with { SystemModel = P(atBound) });

        Assert.Equal(atBound, fw.System!.Model);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.CollectionStatus);
    }

    [Fact]
    public void OverlongValue_IsDropped_NotTruncated_AndMarksPartial()
    {
        var tooLong = new string('A', FirmwareInventoryLogic.MaxValueLength + 1);
        var fw = FirmwareInventoryLogic.Build(Full() with { SystemModel = P(tooLong) });

        Assert.Null(fw.System!.Model);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.System.CollectionStatus);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Equal(new[] { FirmwareErrorCode.SystemValueUnusable }, fw.Errors);
    }

    [Theory]
    [InlineData("LEN\u0000OVO")]
    [InlineData("LENOVO\nInjected: yes")]
    [InlineData("\u001b[31mred")]
    public void ControlCharacters_AreUnusable(string value)
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { BiosManufacturer = P(value) });

        Assert.Null(fw.Bios!.Manufacturer);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Contains(FirmwareErrorCode.BiosValueUnusable, fw.Errors);
    }

    [Fact]
    public void NonStringValue_IsUnusable()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { BaseboardProduct = P(42) });

        Assert.Null(fw.Baseboard!.Product);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.Baseboard.CollectionStatus);
        Assert.Contains(FirmwareErrorCode.BaseboardValueUnusable, fw.Errors);
    }

    [Fact]
    public void ErrorsAreDistinctAndBounded()
    {
        // Every section degraded several ways at once still yields each code once.
        var bad = P(new string('x', 500));
        var fw = FirmwareInventoryLogic.Build(new FirmwareSources(
            bad, SourceRead.Failed, P("x"), SourceRead.Failed, P("garbage"),
            bad, SourceRead.Failed, bad, SourceRead.Failed));

        Assert.Equal(fw.Errors.Count, fw.Errors.Distinct().Count());
        Assert.True(fw.Errors.Count <= FirmwareErrorCode.MaxErrors);
        Assert.All(fw.Errors, e => Assert.Matches("^[a-z][a-z0-9_]{0,63}$", e));
    }

    // -------------------------------------------------------------------------
    // CIM datetime release date
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("20230512000000.000000+000", "2023-05-12")]
    [InlineData("20191231000000.000000-300", "2019-12-31")] // offset is not applied: a date, not an instant
    [InlineData("20240229235959.999999+060", "2024-02-29")]
    [InlineData("20200101******.******+***", "2020-01-01")] // CIM wildcards in the time part
    [InlineData("  20230512000000.000000+000  ", "2023-05-12")]
    public void CimDate_ParsesToCalendarDate(string raw, string expected)
    {
        Assert.Equal(expected, FirmwareInventoryLogic.ParseCimDate(raw));
    }

    [Theory]
    [InlineData("20230230000000.000000+000")] // 30 February
    [InlineData("20231301000000.000000+000")] // month 13
    [InlineData("20230500000000.000000+000")] // day 0
    [InlineData("2023****000000.000000+000")] // wildcard in the date
    [InlineData("05/12/2023")]                // SMBIOS text form, not CIM
    [InlineData("20230512")]                  // truncated
    [InlineData("20230512000000.000000+000X")]
    [InlineData("19000101000000.000000+000")] // year out of range
    [InlineData("21500101000000.000000+000")]
    [InlineData("")]
    [InlineData("２０２３0512000000.000000+000")] // non-ASCII digits
    public void CimDate_BadDates_DoNotParse(string raw)
    {
        Assert.Null(FirmwareInventoryLogic.ParseCimDate(raw));
    }

    [Fact]
    public void CimDate_DateTimeValue_IsAccepted()
    {
        Assert.Equal("2022-07-01", FirmwareInventoryLogic.ParseCimDate(new DateTime(2022, 7, 1, 13, 0, 0)));
    }

    [Fact]
    public void CimDate_NonStringNonDate_DoesNotParse()
    {
        Assert.Null(FirmwareInventoryLogic.ParseCimDate(20230512));
        Assert.Null(FirmwareInventoryLogic.ParseCimDate(null));
    }

    [Fact]
    public void UnparseableDate_KeepsBoundedRaw_AndMarksPartial()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { BiosReleaseDate = P("20230230000000.000000+000") });

        Assert.Null(fw.Bios!.ReleaseDate);
        Assert.Equal("20230230000000.000000+000", fw.Bios.ReleaseDateRaw);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.Bios.CollectionStatus);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
        Assert.Equal(new[] { FirmwareErrorCode.BiosReleaseDateUnparseable }, fw.Errors);
    }

    [Fact]
    public void UnparseableDate_OverlongOrControl_RawIsDropped()
    {
        var overlong = new string('9', FirmwareInventoryLogic.MaxRawDateLength + 1);
        var fw = FirmwareInventoryLogic.Build(Full() with { BiosReleaseDate = P(overlong) });
        Assert.Null(fw.Bios!.ReleaseDate);
        Assert.Null(fw.Bios.ReleaseDateRaw);
        Assert.Contains(FirmwareErrorCode.BiosReleaseDateUnparseable, fw.Errors);

        fw = FirmwareInventoryLogic.Build(Full() with { BiosReleaseDate = P("2023\u0007") });
        Assert.Null(fw.Bios!.ReleaseDateRaw);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
    }

    [Fact]
    public void UnparseableDate_NonString_HasNoRaw()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { BiosReleaseDate = P(12345) });
        Assert.Null(fw.Bios!.ReleaseDate);
        Assert.Null(fw.Bios.ReleaseDateRaw);
        Assert.Equal(FirmwareCollectionStatus.Partial, fw.CollectionStatus);
    }

    [Fact]
    public void AbsentDate_IsNullAndComplete()
    {
        var fw = FirmwareInventoryLogic.Build(Full() with { BiosReleaseDate = SourceRead.Absent });
        Assert.Null(fw.Bios!.ReleaseDate);
        Assert.Null(fw.Bios.ReleaseDateRaw);
        Assert.Equal(FirmwareCollectionStatus.Complete, fw.CollectionStatus);
    }

    // -------------------------------------------------------------------------
    // Wire shape (Shared mirror of the poster options; the real options are pinned in
    // Service.Tests InventoryPosterFirmwareWireTests)
    // -------------------------------------------------------------------------

    private static readonly JsonSerializerOptions Opts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    [Fact]
    public void UnavailableBlock_SerialisesStatusAndErrorsOnly()
    {
        var json = JsonSerializer.Serialize(FirmwareInventoryLogic.Build(AllFailed()), Opts);

        Assert.Equal(
            "{\"schema_version\":1,\"collection_status\":\"unavailable\"," +
            "\"errors\":[\"bios_query_failed\",\"system_query_failed\",\"baseboard_query_failed\"]}",
            json);
    }
}
