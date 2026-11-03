using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.DeviceClassification;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1959: the Windows-only wiring behind device_class. The collector reads ProductType
/// and Caption through a <see cref="WmiPropertyReader"/> and InstallationType through an
/// injected registry read; these tests swap both for fakes, so the source selection and
/// the failure handling are exercised on a machine that has neither WMI nor a registry.
///
/// The decision itself is covered in Shared.Tests (DeviceClassResolverTests). What is
/// proved here is that the collector asks the right sources, and that a source which
/// throws produces an honest gap rather than a confident default.
/// </summary>
public sealed class DeviceCollectorDeviceClassTests
{
    private const string OsQuery = "SELECT ProductType, Caption FROM Win32_OperatingSystem";

    /// <summary>Named WMI properties are Present; every other property is <paramref name="otherwise"/>.</summary>
    private sealed class FakeWmi(SourceRead otherwise)
    {
        private readonly Dictionary<string, SourceRead> _properties = new(StringComparer.OrdinalIgnoreCase);

        public List<(string Query, string Property)> Requested { get; } = new();

        public FakeWmi Set(string property, SourceRead read)
        {
            _properties[property] = read;
            return this;
        }

        public SourceRead Read(string query, string property)
        {
            Requested.Add((query, property));
            return _properties.TryGetValue(property, out var read) ? read : otherwise;
        }
    }

    private static DeviceClassResult Collect(FakeWmi wmi, SourceRead installationType)
    {
        var collector = new DeviceCollector(
            NullLogger<DeviceCollector>.Instance,
            wmi.Read,
            () => installationType);
        return collector.CollectDeviceClass();
    }

    [Fact]
    public void Collector_ReadsProductTypeAndCaptionFromWin32OperatingSystem()
    {
        var wmi = new FakeWmi(SourceRead.Absent)
            .Set("ProductType", SourceRead.Present(1u))
            .Set("Caption", SourceRead.Present("Microsoft Windows 11 Pro"));

        Collect(wmi, SourceRead.Present("Client"));

        Assert.Contains((OsQuery, "ProductType"), wmi.Requested);
        Assert.Contains((OsQuery, "Caption"),     wmi.Requested);
    }

    [Theory]
    [InlineData(1u, "Client",      DeviceClassValue.Workstation)]
    [InlineData(2u, "Server Core", DeviceClassValue.DomainController)]
    [InlineData(3u, "Server",      DeviceClassValue.Server)]
    public void Collector_ResolvesEachProductType(uint productType, string installationType, string expected)
    {
        var wmi = new FakeWmi(SourceRead.Absent).Set("ProductType", SourceRead.Present(productType));

        var result = Collect(wmi, SourceRead.Present(installationType));

        Assert.Equal(expected, result.DeviceClass);
        Assert.Equal(installationType, result.InstallationType);
    }

    /// <summary>
    /// A WMI query that throws (no WMI service, a corrupted repository, a denied call)
    /// must not become a workstation, and must not take the cycle down with it.
    /// </summary>
    [Fact]
    public void Collector_ThrowingWmiQuery_IsUnknown_AndDoesNotPropagate()
    {
        var collector = new DeviceCollector(
            NullLogger<DeviceCollector>.Instance,
            (_, _) => SourceRead.Capture(() => throw new InvalidOperationException("WMI unavailable")),
            () => SourceRead.Present("Client"));

        var result = collector.CollectDeviceClass();

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.Null(result.OsCaption);
        Assert.Equal("Client", result.InstallationType);
    }

    [Fact]
    public void Collector_AbsentProductType_IsUnknown()
    {
        var wmi = new FakeWmi(SourceRead.Absent).Set("Caption", SourceRead.Present("Microsoft Windows 11 Pro"));

        var result = Collect(wmi, SourceRead.Present("Client"));

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.Equal("Microsoft Windows 11 Pro", result.OsCaption);
    }

    [Fact]
    public void Collector_AbsentInstallationTypeRegistryValue_OmitsIt_AndKeepsTheClass()
    {
        var wmi = new FakeWmi(SourceRead.Absent).Set("ProductType", SourceRead.Present(3u));

        var result = Collect(wmi, SourceRead.Absent);

        Assert.Equal(DeviceClassValue.Server, result.DeviceClass);
        Assert.Null(result.InstallationType);
    }

    [Fact]
    public void Collector_FailedInstallationTypeRegistryRead_OmitsIt_AndKeepsTheClass()
    {
        var wmi = new FakeWmi(SourceRead.Absent).Set("ProductType", SourceRead.Present(3u));

        var result = Collect(wmi, SourceRead.Failed);

        Assert.Equal(DeviceClassValue.Server, result.DeviceClass);
        Assert.Null(result.InstallationType);
    }

    [Fact]
    public void Collector_UnrecognisedInstallationType_OmitsIt_AndKeepsTheClass()
    {
        var wmi = new FakeWmi(SourceRead.Absent).Set("ProductType", SourceRead.Present(1u));

        var result = Collect(wmi, SourceRead.Present("Nano Server"));

        Assert.Equal(DeviceClassValue.Workstation, result.DeviceClass);
        Assert.Null(result.InstallationType);
    }

    /// <summary>
    /// Nothing readable anywhere is the case that has to stay honest: unknown, with both
    /// optional strings omitted, and no exception out of the collector.
    /// </summary>
    [Fact]
    public void Collector_NothingReadable_IsUnknownWithNothingInvented()
    {
        var result = Collect(new FakeWmi(SourceRead.Failed), SourceRead.Failed);

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.Null(result.InstallationType);
        Assert.Null(result.OsCaption);
    }

    /// <summary>
    /// The production constructor, wired to the real WMI and registry readers, asserted
    /// on every platform rather than only on Windows.
    ///
    /// It says something different on each, and both statements are worth having. On
    /// Windows it is a smoke test that the real reads return a value in the vocabulary.
    /// Off Windows every read throws PlatformNotSupportedException deep inside
    /// System.Management and Microsoft.Win32.Registry, so it proves the thing that
    /// actually matters on a customer estate: those exceptions are caught by
    /// SourceRead.Capture and become an honest "unknown", they do not escape
    /// CollectDeviceClass and abort the inventory cycle.
    ///
    /// Deliberately not guarded by an OS check. A test that returns early asserts
    /// nothing while still reporting as passed, and CI for this repo runs on
    /// windows-latest, so an "off Windows only" guard here would have meant this never
    /// ran anywhere that counts.
    /// </summary>
    [Fact]
    public void Collector_DefaultConstructor_ReadsTheRealMachineWithoutThrowing()
    {
        var result = new DeviceCollector(NullLogger<DeviceCollector>.Instance).CollectDeviceClass();

        Assert.Contains(result.DeviceClass, new[]
        {
            DeviceClassValue.Workstation,
            DeviceClassValue.Server,
            DeviceClassValue.DomainController,
            DeviceClassValue.Unknown,
        });

        if (!OperatingSystem.IsWindows())
        {
            // No WMI and no registry here, so nothing can be read and nothing is invented.
            Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
            Assert.Null(result.InstallationType);
            Assert.Null(result.OsCaption);
        }
    }
}
