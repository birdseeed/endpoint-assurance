using Patched.Shared.DeviceClassification;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1959: the device-class decision. Every source here is a fixture, so the whole
/// decision is exercised off-box where neither WMI nor the registry exists.
///
/// The assertions that matter most are the negative ones. On the platform side an absent
/// or "unknown" class is scored the way the device was scored before device class
/// existed, so a wrong confident answer produces a wrong assessment nobody sees, while
/// an honest "unknown" produces a gap the platform is built to handle. Each case below
/// that feeds the resolver a missing, unreadable or unrecognised value asserts "unknown"
/// or an omitted string, never a value the resolver made up.
/// </summary>
public sealed class DeviceClassResolverTests
{
    private static DeviceClassResult Resolve(
        SourceRead? productType      = null,
        SourceRead? installationType = null,
        SourceRead? osCaption        = null) =>
        DeviceClassResolver.Resolve(new DeviceClassSources(
            productType      ?? SourceRead.Absent,
            installationType ?? SourceRead.Absent,
            osCaption        ?? SourceRead.Absent));

    // ---------------------------------------------------------------- ProductType

    [Fact]
    public void ProductType1_IsWorkstation()
    {
        Assert.Equal(DeviceClassValue.Workstation,
            Resolve(productType: SourceRead.Present(1)).DeviceClass);
    }

    /// <summary>
    /// The ordering is not intuitive and getting it backwards is the obvious mistake:
    /// ProductType 2 is the DOMAIN CONTROLLER, not the member server.
    /// </summary>
    [Fact]
    public void ProductType2_IsDomainController_NotMemberServer()
    {
        var result = Resolve(productType: SourceRead.Present(2));
        Assert.Equal(DeviceClassValue.DomainController, result.DeviceClass);
        Assert.NotEqual(DeviceClassValue.Server, result.DeviceClass);
    }

    [Fact]
    public void ProductType3_IsServer_NotDomainController()
    {
        var result = Resolve(productType: SourceRead.Present(3));
        Assert.Equal(DeviceClassValue.Server, result.DeviceClass);
        Assert.NotEqual(DeviceClassValue.DomainController, result.DeviceClass);
    }

    /// <summary>WMI hands ProductType over as a uint32, which is what production sees.</summary>
    [Theory]
    [InlineData(1u, DeviceClassValue.Workstation)]
    [InlineData(2u, DeviceClassValue.DomainController)]
    [InlineData(3u, DeviceClassValue.Server)]
    public void ProductType_AsWmiUInt32_ResolvesTheSame(uint productType, string expected)
    {
        Assert.Equal(expected, Resolve(productType: SourceRead.Present(productType)).DeviceClass);
    }

    [Theory]
    [InlineData((ushort)3, DeviceClassValue.Server)]
    [InlineData((long)2, DeviceClassValue.DomainController)]
    [InlineData("1", DeviceClassValue.Workstation)]
    public void ProductType_InOtherIntegralOrTextForms_ResolvesTheSame(object productType, string expected)
    {
        Assert.Equal(expected, Resolve(productType: SourceRead.Present(productType)).DeviceClass);
    }

    /// <summary>A WMI query that threw tells us nothing, so the class is unknown.</summary>
    [Fact]
    public void ProductType_UnreadableWmiQuery_IsUnknown_NotWorkstation()
    {
        var result = Resolve(productType: SourceRead.Failed);
        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.NotEqual(DeviceClassValue.Workstation, result.DeviceClass);
    }

    /// <summary>
    /// A query that ran and matched nothing is equally no evidence. Absent must not
    /// become the most common class just because most machines are workstations.
    /// </summary>
    [Fact]
    public void ProductType_Absent_IsUnknown_NotWorkstation()
    {
        var result = Resolve(productType: SourceRead.Absent);
        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.NotEqual(DeviceClassValue.Workstation, result.DeviceClass);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(-1)]
    [InlineData("server")]
    [InlineData("")]
    [InlineData(true)]
    [InlineData(1.5)]
    public void ProductType_Unrecognised_IsUnknown(object productType)
    {
        Assert.Equal(DeviceClassValue.Unknown,
            Resolve(productType: SourceRead.Present(productType)).DeviceClass);
    }

    // ----------------------------------------------------------- InstallationType

    [Theory]
    [InlineData("Client", InstallationTypeValue.Client)]
    [InlineData("Server", InstallationTypeValue.Server)]
    [InlineData("Server Core", InstallationTypeValue.ServerCore)]
    public void InstallationType_DocumentedValues_AreEmittedVerbatim(string raw, string expected)
    {
        Assert.Equal(expected, Resolve(installationType: SourceRead.Present(raw)).InstallationType);
    }

    [Theory]
    [InlineData("  Client  ", InstallationTypeValue.Client)]
    [InlineData("server core", InstallationTypeValue.ServerCore)]
    [InlineData("SERVER", InstallationTypeValue.Server)]
    public void InstallationType_IsMatchedCaseInsensitively_AndEmittedCanonically(string raw, string expected)
    {
        Assert.Equal(expected, Resolve(installationType: SourceRead.Present(raw)).InstallationType);
    }

    /// <summary>An absent registry value omits the string; it never becomes "Client".</summary>
    [Fact]
    public void InstallationType_AbsentRegistryValue_IsOmitted()
    {
        var result = Resolve(productType: SourceRead.Present(1), installationType: SourceRead.Absent);
        Assert.Null(result.InstallationType);
        Assert.Equal(DeviceClassValue.Workstation, result.DeviceClass);
    }

    [Fact]
    public void InstallationType_FailedRegistryRead_IsOmitted()
    {
        Assert.Null(Resolve(installationType: SourceRead.Failed).InstallationType);
    }

    /// <summary>
    /// An undocumented string is dropped rather than mapped onto one of the three. It
    /// also says nothing about the class, so it cannot contradict ProductType either.
    /// </summary>
    [Theory]
    [InlineData("Nano Server")]
    [InlineData("ServerCore")]
    [InlineData("")]
    [InlineData("   ")]
    public void InstallationType_UnrecognisedValue_IsOmitted_AndDoesNotChangeTheClass(string raw)
    {
        var result = Resolve(productType: SourceRead.Present(3), installationType: SourceRead.Present(raw));
        Assert.Null(result.InstallationType);
        Assert.Equal(DeviceClassValue.Server, result.DeviceClass);
    }

    [Fact]
    public void InstallationType_NonStringValue_IsOmitted()
    {
        Assert.Null(Resolve(installationType: SourceRead.Present(3)).InstallationType);
    }

    // ------------------------------------------------ the two sources together

    [Theory]
    [InlineData(1, "Client", DeviceClassValue.Workstation)]
    [InlineData(3, "Server", DeviceClassValue.Server)]
    [InlineData(3, "Server Core", DeviceClassValue.Server)]
    [InlineData(2, "Server", DeviceClassValue.DomainController)]
    [InlineData(2, "Server Core", DeviceClassValue.DomainController)]
    public void AgreeingSources_KeepTheProductTypeClass(int productType, string installationType, string expected)
    {
        Assert.Equal(expected, Resolve(
            productType:      SourceRead.Present(productType),
            installationType: SourceRead.Present(installationType)).DeviceClass);
    }

    /// <summary>
    /// The failure this ticket exists to remove: a machine that says "Server" but reports
    /// ProductType 1 must not be assessed as a laptop. The sources contradict each other,
    /// which one is wrong is not knowable here, so the class is withdrawn.
    /// </summary>
    [Theory]
    [InlineData(1, "Server")]
    [InlineData(1, "Server Core")]
    [InlineData(2, "Client")]
    [InlineData(3, "Client")]
    public void ContradictingSources_AreUnknown_NotAGuess(int productType, string installationType)
    {
        var result = Resolve(
            productType:      SourceRead.Present(productType),
            installationType: SourceRead.Present(installationType));

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        // The raw reading is still reported; only the derived class is withdrawn.
        Assert.Equal(installationType, result.InstallationType);
    }

    /// <summary>
    /// InstallationType never supplies a class ProductType did not: it cannot tell a
    /// domain controller from a member server, so "Server" alone would be a guess.
    /// </summary>
    [Theory]
    [InlineData("Server")]
    [InlineData("Server Core")]
    [InlineData("Client")]
    public void InstallationTypeAlone_NeverInfersAClass(string installationType)
    {
        var result = Resolve(
            productType:      SourceRead.Failed,
            installationType: SourceRead.Present(installationType));

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.Equal(installationType, result.InstallationType);
    }

    // ------------------------------------------------------------------ OsCaption

    [Fact]
    public void OsCaption_Present_IsEmittedTrimmed()
    {
        Assert.Equal("Microsoft Windows Server 2022 Standard",
            Resolve(osCaption: SourceRead.Present("  Microsoft Windows Server 2022 Standard  ")).OsCaption);
    }

    [Fact]
    public void OsCaption_AbsentOrFailed_IsOmitted()
    {
        Assert.Null(Resolve(osCaption: SourceRead.Absent).OsCaption);
        Assert.Null(Resolve(osCaption: SourceRead.Failed).OsCaption);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void OsCaption_EmptyOrWhitespace_IsOmitted(string raw)
    {
        Assert.Null(Resolve(osCaption: SourceRead.Present(raw)).OsCaption);
    }

    [Fact]
    public void OsCaption_NonString_IsOmitted()
    {
        Assert.Null(Resolve(osCaption: SourceRead.Present(11)).OsCaption);
    }

    /// <summary>Dropped whole, not truncated: a truncated caption still reads as a real reading.</summary>
    [Fact]
    public void OsCaption_OverLengthLimit_IsOmitted()
    {
        var tooLong = new string('W', DeviceClassResolver.MaxOsCaptionLength + 1);
        Assert.Null(Resolve(osCaption: SourceRead.Present(tooLong)).OsCaption);

        var atLimit = new string('W', DeviceClassResolver.MaxOsCaptionLength);
        Assert.Equal(atLimit, Resolve(osCaption: SourceRead.Present(atLimit)).OsCaption);
    }

    [Fact]
    public void OsCaption_WithControlCharacters_IsOmitted()
    {
        Assert.Null(Resolve(osCaption: SourceRead.Present("Microsoft Windows 11 Pro\u0000\u001b[31m")).OsCaption);
    }

    /// <summary>
    /// The caption is evidence for an operator, never a source of class. Server 2019 and
    /// Windows 10 1809 LTSC share build 17763, and captions are localised, so a caption
    /// that says "Server" with no ProductType behind it still leaves the class unknown.
    /// </summary>
    [Fact]
    public void OsCaption_IsNeverParsedIntoAClass()
    {
        var result = Resolve(
            productType: SourceRead.Absent,
            osCaption:   SourceRead.Present("Microsoft Windows Server 2019 Datacenter"));

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.Equal("Microsoft Windows Server 2019 Datacenter", result.OsCaption);
    }

    // --------------------------------------------------------- the whole snapshot

    [Fact]
    public void EverySourceUnreadable_IsUnknownWithNothingInvented()
    {
        var result = DeviceClassResolver.Resolve(new DeviceClassSources(
            SourceRead.Failed, SourceRead.Failed, SourceRead.Failed));

        Assert.Equal(DeviceClassValue.Unknown, result.DeviceClass);
        Assert.Null(result.InstallationType);
        Assert.Null(result.OsCaption);
    }

    [Fact]
    public void AHealthyWorkstation_ResolvesAllThreeFields()
    {
        var result = DeviceClassResolver.Resolve(new DeviceClassSources(
            SourceRead.Present(1u),
            SourceRead.Present("Client"),
            SourceRead.Present("Microsoft Windows 11 Pro")));

        Assert.Equal(DeviceClassValue.Workstation, result.DeviceClass);
        Assert.Equal("Client", result.InstallationType);
        Assert.Equal("Microsoft Windows 11 Pro", result.OsCaption);
    }

    [Fact]
    public void ADomainController_ResolvesAllThreeFields()
    {
        var result = DeviceClassResolver.Resolve(new DeviceClassSources(
            SourceRead.Present(2u),
            SourceRead.Present("Server Core"),
            SourceRead.Present("Microsoft Windows Server 2022 Datacenter")));

        Assert.Equal(DeviceClassValue.DomainController, result.DeviceClass);
        Assert.Equal("Server Core", result.InstallationType);
        Assert.Equal("Microsoft Windows Server 2022 Datacenter", result.OsCaption);
    }

    // ------------------------------------------------------------- SourceRead

    [Fact]
    public void SourceRead_Capture_ClassifiesValueAbsenceAndFailure()
    {
        Assert.Equal(SourceReadState.Present, SourceRead.Capture(() => "Client").State);
        Assert.Equal(SourceReadState.Absent,  SourceRead.Capture(() => null).State);

        Exception? seen = null;
        var failed = SourceRead.Capture(
            () => throw new InvalidOperationException("WMI is not available"),
            ex => seen = ex);

        Assert.Equal(SourceReadState.Failed, failed.State);
        Assert.IsType<InvalidOperationException>(seen);
    }
}
