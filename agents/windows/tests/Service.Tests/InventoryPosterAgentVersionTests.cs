using System.Reflection;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2238: the payload's agent_version comes from the running build's
/// InformationalVersion, never a literal. The value is read by reflection so this test
/// compiles against the old const and fails on it, rather than failing to build.
/// </summary>
public sealed class InventoryPosterAgentVersionTests
{
    private static string PayloadAgentVersion()
    {
        var field = typeof(InventoryPoster).GetField(
            "AgentVersion", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(field);
        return Assert.IsType<string>(field!.GetValue(null));
    }

    [Fact]
    public void AgentVersion_IsTheSemanticPartOfTheAssemblyInformationalVersion()
    {
        var informational = typeof(InventoryPoster).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        var expected = InstalledAppScanner.SemanticReleaseFromInformationalVersion(informational) ?? "0.0.0-dev";

        Assert.Equal(expected, PayloadAgentVersion());
    }

    [Fact]
    public void AgentVersionFrom_StampedReleaseBuild_IsTheReleaseTag()
    {
        Assert.Equal("0.14.5", InventoryPoster.AgentVersionFrom(
            "0.14.5+e7c858df0123456789abcdef0123456789abcdef"));
    }

    [Fact]
    public void AgentVersionFrom_InstalledBetaBuild_PreservesItsRevision()
    {
        // Actual HOMESERVER ProductVersion; FileVersion 2.15.102.0 is an MSI
        // encoding, not the release identity sent to the platform.
        Assert.Equal("0.15.1.2", InventoryPoster.AgentVersionFrom(
            "0.15.1.2+00cc3f440f684c68eff34748197ec5ce32e9e257"));
    }

    [Theory]
    [MemberData(nameof(InstalledAppScannerVersionTests.ResolverBetaVersions), MemberType = typeof(InstalledAppScannerVersionTests))]
    public void AgentVersionFrom_ResolverBetaOutput_PreservesFullNumericIdentity(
        string informational, string identity, string msiVersion)
    {
        Assert.NotEqual(msiVersion, identity);
        Assert.Equal(identity, InventoryPoster.AgentVersionFrom(informational));
    }

    [Theory]
    [MemberData(nameof(InstalledAppScannerVersionTests.InvalidReleaseVersions), MemberType = typeof(InstalledAppScannerVersionTests))]
    public void AgentVersionFrom_InvalidReleaseIdentity_IsExplicitDev(string informational)
    {
        Assert.Equal(InventoryPoster.DevAgentVersion, InventoryPoster.AgentVersionFrom(informational));
    }

    [Fact]
    public void AgentVersionFrom_ExistingStableMaximum_PreservesCompatibility()
    {
        Assert.Equal("253.255.65535", InventoryPoster.AgentVersionFrom(
            "253.255.65535+0123456789abcdef0123456789abcdef01234567"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1.0.0")]
    [InlineData("0.15.0-rc.1+e7c858df0123456789abcdef0123456789abcdef")]
    public void AgentVersionFrom_UnstampedOrUnrecognisedBuild_IsExplicitDev(string? informational)
    {
        Assert.Equal(InventoryPoster.DevAgentVersion, InventoryPoster.AgentVersionFrom(informational));
    }
}
