using System.Text.Json;
using Patched.Shared.DeviceClassification;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1959: ties contracts/inventory-device-class.schema.json to the code that fills it.
/// The platform side is written against these names and this vocabulary, so a rename on
/// either side has to break here rather than surface as an estate quietly classed
/// unknown. The sample pair is checked too, including the macOS one, whose whole point is
/// that it omits all three keys.
/// </summary>
public sealed class DeviceClassContractFileTests
{
    private static JsonElement Schema =>
        JsonDocument.Parse(File.ReadAllText(LocateContractsFile("inventory-device-class.schema.json")))
            .RootElement;

    [Fact]
    public void Schema_DeclaresTheThreeFieldNamesExactly()
    {
        var properties = Schema.GetProperty("properties");

        Assert.True(properties.TryGetProperty("device_class",      out _));
        Assert.True(properties.TryGetProperty("installation_type", out _));
        Assert.True(properties.TryGetProperty("os_caption",        out _));
        Assert.Equal(3, properties.EnumerateObject().Count());
    }

    /// <summary>
    /// The fields are additive and optional on every platform, so the schema must not
    /// require any of them. A required key would make the macOS payload invalid and would
    /// make every agent older than 0.15.0 invalid with it.
    /// </summary>
    [Fact]
    public void Schema_RequiresNothing()
    {
        Assert.False(Schema.TryGetProperty("required", out _));
    }

    [Fact]
    public void Schema_DeviceClassEnum_MatchesTheCodeVocabulary()
    {
        var declared = Schema.GetProperty("properties").GetProperty("device_class")
            .GetProperty("enum").EnumerateArray().Select(e => e.GetString()).ToArray();

        Assert.Equal(
            new[]
            {
                DeviceClassValue.Workstation,
                DeviceClassValue.Server,
                DeviceClassValue.DomainController,
                DeviceClassValue.Unknown,
            },
            declared);
    }

    [Fact]
    public void Schema_InstallationTypeExamples_MatchTheCodeVocabulary()
    {
        var declared = Schema.GetProperty("properties").GetProperty("installation_type")
            .GetProperty("examples").EnumerateArray().Select(e => e.GetString()).ToArray();

        Assert.Equal(
            new[]
            {
                InstallationTypeValue.Client,
                InstallationTypeValue.Server,
                InstallationTypeValue.ServerCore,
            },
            declared);
    }

    [Fact]
    public void Schema_OsCaptionMaxLength_MatchesTheResolver()
    {
        var maxLength = Schema.GetProperty("properties").GetProperty("os_caption")
            .GetProperty("maxLength").GetInt32();

        Assert.Equal(DeviceClassResolver.MaxOsCaptionLength, maxLength);
    }

    [Fact]
    public void WindowsSample_CarriesAllThreeFieldsWithContractValues()
    {
        var sample = JsonDocument
            .Parse(File.ReadAllText(LocateContractsFile("inventory-device-class.sample.windows.json")))
            .RootElement;

        Assert.Equal(DeviceClassValue.DomainController, sample.GetProperty("device_class").GetString());
        Assert.Equal(InstallationTypeValue.ServerCore,  sample.GetProperty("installation_type").GetString());
        Assert.False(string.IsNullOrWhiteSpace(sample.GetProperty("os_caption").GetString()));
    }

    /// <summary>
    /// macOS omits all three. This is the parity assertion: the seam carries no
    /// Windows-only structure, and an omitted field is a valid, defined reading.
    /// </summary>
    [Fact]
    public void MacosSample_OmitsAllThreeFields()
    {
        var sample = JsonDocument
            .Parse(File.ReadAllText(LocateContractsFile("inventory-device-class.sample.macos.json")))
            .RootElement;

        Assert.False(sample.TryGetProperty("device_class",      out _));
        Assert.False(sample.TryGetProperty("installation_type", out _));
        Assert.False(sample.TryGetProperty("os_caption",        out _));
    }

    /// <summary>
    /// Finds a device-class contract file. Shared.Tests.csproj copies these files into a
    /// 'contracts' folder beside the test binary on every build, so the first step of the
    /// walk below hits and the lookup does not depend on the runner's working directory
    /// or on how the repository was checked out. The walk up to a repo-root 'contracts/'
    /// sibling of 'windows/' is kept as a fallback for a binary run from a tree where that
    /// copy did not happen.
    ///
    /// Throws rather than skipping when neither is found: these tests are the only thing
    /// holding the wire names in the schema to the constants in the code, and a silent
    /// skip would let the two drift apart while the suite stayed green.
    /// </summary>
    private static string LocateContractsFile(string fileName)
    {
        var start = AppContext.BaseDirectory;
        var dir = new DirectoryInfo(start);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "contracts", fileName);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException(
            $"Could not locate '{fileName}' under a 'contracts' directory walking up from " +
            $"'{start}'. Shared.Tests.csproj copies the device-class contract files into " +
            "'contracts/' beside the test binary; if that copy is missing, check the None " +
            "item in Shared.Tests.csproj and that the checkout includes the repo-root " +
            "'contracts/' directory, which is a sibling of 'windows/'.");
    }
}
