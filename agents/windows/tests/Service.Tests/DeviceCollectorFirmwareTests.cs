using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2262: the Windows-only wiring behind the firmware block. The collector reads one
/// instance of each of Win32_BIOS, Win32_ComputerSystem and Win32_BaseBoard through a
/// <see cref="WmiInstanceReader"/>; these tests swap it for a fake so the class and
/// property selection and the failure handling run off-box. The rules themselves are
/// covered in Shared.Tests (FirmwareInventoryLogicTests).
///
/// The wire tests serialise with the real <c>InventoryPoster.JsonOpts</c>, read by
/// reflection (the same technique as InventoryPosterLocalAdminWireTests), and pin the
/// exact bytes. The complete, partial and unavailable strings below are copied verbatim
/// into the platform repo's payload fixtures
/// (go-service/testdata/payload-fixtures/valid/with-firmware-*-windows.json) and its
/// ValidatePayload test, so agent and platform are checked against the same JSON.
/// </summary>
public sealed class DeviceCollectorFirmwareTests
{
    internal const string BiosQuery =
        "SELECT Manufacturer, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, ReleaseDate FROM Win32_BIOS";
    internal const string SystemQuery    = "SELECT Manufacturer, Model FROM Win32_ComputerSystem";
    internal const string BaseboardQuery = "SELECT Manufacturer, Product FROM Win32_BaseBoard";

    /// <summary>Canned instance reads per WMI class; a class not configured fails outright.</summary>
    private sealed class FakeWmiInstances
    {
        private readonly Dictionary<string, Dictionary<string, SourceRead>> _classes = new(StringComparer.Ordinal);

        public List<(string Query, IReadOnlyList<string> Properties)> Requested { get; } = new();

        public FakeWmiInstances Class(string query, params (string Property, SourceRead Read)[] props)
        {
            _classes[query] = props.ToDictionary(p => p.Property, p => p.Read, StringComparer.Ordinal);
            return this;
        }

        public IReadOnlyDictionary<string, SourceRead> Read(string query, IReadOnlyList<string> properties)
        {
            Requested.Add((query, properties));
            if (!_classes.TryGetValue(query, out var props))
                return properties.ToDictionary(p => p, _ => SourceRead.Failed);
            return properties.ToDictionary(p => p, p => props.TryGetValue(p, out var r) ? r : SourceRead.Absent);
        }
    }

    private static SourceRead P(object v) => SourceRead.Present(v);

    private static FakeWmiInstances Bios(FakeWmiInstances f) => f.Class(BiosQuery,
        ("Manufacturer",       P("LENOVO")),
        ("SMBIOSBIOSVersion",  P("N3HET82W (1.54 )")),
        ("SMBIOSMajorVersion", P((ushort)3)),
        ("SMBIOSMinorVersion", P((ushort)2)),
        ("ReleaseDate",        P("20230512000000.000000+000")));

    private static FakeWmiInstances System(FakeWmiInstances f) => f.Class(SystemQuery,
        ("Manufacturer", P("LENOVO")),
        ("Model",        P("20XW0026UK")));

    private static FakeWmiInstances Baseboard(FakeWmiInstances f) => f.Class(BaseboardQuery,
        ("Manufacturer", P("LENOVO")),
        ("Product",      P("20XW0026UK")));

    private static InventoryFirmware Collect(FakeWmiInstances wmi) =>
        new DeviceCollector(
            NullLogger<DeviceCollector>.Instance,
            wmi: (_, _) => SourceRead.Absent,
            installationType: () => SourceRead.Absent,
            wmiInstance: wmi.Read).CollectFirmware();

    private static JsonSerializerOptions PosterOpts()
    {
        var field = typeof(InventoryPoster).GetField("JsonOpts", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);
        return Assert.IsType<JsonSerializerOptions>(field!.GetValue(null));
    }

    // Copied verbatim into the platform's fixtures; change both together.
    internal const string CompleteJson =
        "{\"schema_version\":1,\"collection_status\":\"complete\",\"errors\":[]," +
        "\"bios\":{\"collection_status\":\"complete\",\"manufacturer\":\"LENOVO\",\"version\":\"N3HET82W (1.54 )\"," +
        "\"smbios_version\":\"3.2\",\"release_date\":\"2023-05-12\"}," +
        "\"system\":{\"collection_status\":\"complete\",\"manufacturer\":\"LENOVO\",\"model\":\"20XW0026UK\"}," +
        "\"baseboard\":{\"collection_status\":\"complete\",\"manufacturer\":\"LENOVO\",\"product\":\"20XW0026UK\"}}";

    internal const string PartialJson =
        "{\"schema_version\":1,\"collection_status\":\"partial\"," +
        "\"errors\":[\"bios_release_date_unparseable\",\"baseboard_query_failed\"]," +
        "\"bios\":{\"collection_status\":\"partial\",\"manufacturer\":\"LENOVO\",\"version\":\"N3HET82W (1.54 )\"," +
        "\"smbios_version\":\"3.2\",\"release_date_raw\":\"20230230000000.000000\\u002B000\"}," +
        "\"system\":{\"collection_status\":\"complete\",\"manufacturer\":\"LENOVO\",\"model\":\"20XW0026UK\"}," +
        "\"baseboard\":{\"collection_status\":\"unavailable\"}}";

    internal const string UnavailableJson =
        "{\"schema_version\":1,\"collection_status\":\"unavailable\"," +
        "\"errors\":[\"bios_query_failed\",\"system_query_failed\",\"baseboard_query_failed\"]}";

    [Fact]
    public void Collector_ReadsOneInstanceOfEachSmbiosClass_WithTheRightProperties()
    {
        var wmi = Baseboard(System(Bios(new FakeWmiInstances())));

        Collect(wmi);

        Assert.Equal(3, wmi.Requested.Count);
        Assert.Equal(
            new[] { "Manufacturer", "SMBIOSBIOSVersion", "SMBIOSMajorVersion", "SMBIOSMinorVersion", "ReleaseDate" },
            wmi.Requested.Single(r => r.Query == BiosQuery).Properties);
        Assert.Equal(new[] { "Manufacturer", "Model" }, wmi.Requested.Single(r => r.Query == SystemQuery).Properties);
        Assert.Equal(new[] { "Manufacturer", "Product" }, wmi.Requested.Single(r => r.Query == BaseboardQuery).Properties);
    }

    [Fact]
    public void Complete_SerialisesWithPosterOptions_ToThePinnedShape()
    {
        var fw = Collect(Baseboard(System(Bios(new FakeWmiInstances()))));

        Assert.Equal(CompleteJson, JsonSerializer.Serialize(fw, PosterOpts()));
    }

    [Fact]
    public void OneClassFailed_WithBadDate_SerialisesAsPartial_ToThePinnedShape()
    {
        var wmi = System(new FakeWmiInstances()).Class(BiosQuery,
            ("Manufacturer",       P("LENOVO")),
            ("SMBIOSBIOSVersion",  P("N3HET82W (1.54 )")),
            ("SMBIOSMajorVersion", P((ushort)3)),
            ("SMBIOSMinorVersion", P((ushort)2)),
            ("ReleaseDate",        P("20230230000000.000000+000")));
        // Win32_BaseBoard not configured: the fake fails every property, as a thrown query does.

        var fw = Collect(wmi);

        Assert.Equal(PartialJson, JsonSerializer.Serialize(fw, PosterOpts()));
    }

    [Fact]
    public void WmiTotalFailure_SerialisesAsUnavailable_ToThePinnedShape()
    {
        var fw = Collect(new FakeWmiInstances());

        Assert.Equal(UnavailableJson, JsonSerializer.Serialize(fw, PosterOpts()));
    }

    [Fact]
    public void Payload_CarriesFirmwareUnderTopLevelKey_WithPosterOptions()
    {
        var fw = Collect(new FakeWmiInstances());
        var json = JsonSerializer.Serialize(new { firmware = fw }, PosterOpts());
        Assert.StartsWith("{\"firmware\":{\"schema_version\":1,", json);

        var prop = typeof(InventoryPayload).GetProperty(nameof(InventoryPayload.Firmware));
        var name = prop!.GetCustomAttribute<System.Text.Json.Serialization.JsonPropertyNameAttribute>();
        Assert.Equal("firmware", name!.Name);
    }

    /// <summary>
    /// Production constructor, real WMI. Off Windows every read throws inside
    /// System.Management, which must become an unavailable block rather than escape
    /// and abort the inventory cycle; on Windows it is a smoke test of the real reads.
    /// Not OS-guarded, for the reason given on the device-class equivalent.
    /// </summary>
    [Fact]
    public void Collector_DefaultConstructor_ReadsTheRealMachineWithoutThrowing()
    {
        var fw = new DeviceCollector(NullLogger<DeviceCollector>.Instance).CollectFirmware();

        Assert.Contains(fw.CollectionStatus, new[]
        {
            FirmwareCollectionStatus.Complete, FirmwareCollectionStatus.Partial, FirmwareCollectionStatus.Unavailable,
        });

        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(FirmwareCollectionStatus.Unavailable, fw.CollectionStatus);
            Assert.Null(fw.Bios);
            Assert.NotEmpty(fw.Errors);
        }
    }
}
