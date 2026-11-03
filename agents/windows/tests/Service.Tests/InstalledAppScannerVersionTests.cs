using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

public class InstalledAppScannerVersionTests
{
    private const string Sha = "0123456789abcdef0123456789abcdef01234567";

    // Captured from resolve-release-version.sh for 0.15.1-beta.1,
    // 0.15.1-beta.2 and the maximum 253.255.654-beta.99 tag.
    public static TheoryData<string, string, string> ResolverBetaVersions => new()
    {
        { $"0.15.1.1+{Sha}", "0.15.1.1", "2.15.101" },
        { $"0.15.1.2+{Sha}", "0.15.1.2", "2.15.102" },
        { $"253.255.654.99+{Sha}", "253.255.654.99", "255.255.65499" },
    };

    public static TheoryData<string> InvalidReleaseVersions => new()
    {
        $"254.0.0.1+{Sha}", $"0.256.0.1+{Sha}", $"0.0.655.1+{Sha}",
        $"0.15.1.0+{Sha}", $"0.15.1.100+{Sha}", $"0.15.1.02+{Sha}",
        $"00.15.1.2+{Sha}", $"0.015.1.2+{Sha}", $"0.15.01.2+{Sha}",
        $"0.15.1-beta.2+{Sha}", $"0.15.1-rc.2+{Sha}", "0.15.1.2", "0.0.0-dev",
        "0.15.1.2+abc123", "0.15.1.2+" + new string('a', 39),
        "0.15.1.2+" + new string('a', 41), "0.15.1.2+" + new string('g', 40),
        $"0.15.1.2+{Sha}+extra", $"0.15.1.2.3+{Sha}",
        $" 0.15.1.2+{Sha}", $"0.15.1.2+{Sha}\n", $"0.15.1٢.2+{Sha}",
        $"254.0.0+{Sha}", $"0.256.0+{Sha}", $"0.0.65536+{Sha}",
    };

    [Theory]
    [MemberData(nameof(ResolverBetaVersions))]
    public void PatchedAgent_ResolverBetaOutput_PreservesFullNumericIdentity(
        string informational, string identity, string msiVersion)
    {
        Assert.Equal(identity, InstalledAppScanner.SemanticReleaseFromInformationalVersion(informational));
        Assert.Equal(identity, InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Patched", msiVersion, informational));
        Assert.Equal(msiVersion, InstalledAppScanner.NormalizePatchedAgentVersion(
            "Contoso Agent", "Contoso", msiVersion, informational));
        Assert.Equal(msiVersion, InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Other Publisher", msiVersion, informational));
    }

    [Theory]
    [MemberData(nameof(InvalidReleaseVersions))]
    public void PatchedAgent_InvalidReleaseIdentity_KeepsObservedDisplayVersion(string informational)
    {
        Assert.Null(InstalledAppScanner.SemanticReleaseFromInformationalVersion(informational));
        Assert.Equal("2.15.102", InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Patched", "2.15.102", informational));
    }

    [Fact]
    public void PatchedAgent_UsesSemanticReleaseFromServiceInformationalVersion()
    {
        var version = InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Patched", "2.13.1", $"0.13.1+{Sha}");

        Assert.Equal("0.13.1", version);
    }

    [Fact]
    public void PatchedAgent_InstalledBetaBuild_UsesReleaseIdentityInsteadOfEncodedMsiVersion()
    {
        Assert.Equal("0.15.1.2", InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Patched", "2.15.102",
            "0.15.1.2+00cc3f440f684c68eff34748197ec5ce32e9e257"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0.13.1")]
    [InlineData("0.13.1+abc123")]
    [InlineData("0.13.1-rc.1+0123456789abcdef0123456789abcdef01234567")]
    [InlineData("254.0.0+0123456789abcdef0123456789abcdef01234567")]
    public void PatchedAgent_MissingOrInvalidInformationalVersion_KeepsArpDisplayVersion(string? informationalVersion)
    {
        var version = InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Patched", "2.13.1", informationalVersion);

        Assert.Equal("2.13.1", version);
    }

    [Fact]
    public void OtherEntries_AreNeverNormalizedFromTheServiceVersion()
    {
        var version = InstalledAppScanner.NormalizePatchedAgentVersion(
            "Contoso Agent", "Contoso", "2.13.1", $"0.13.1+{Sha}");

        Assert.Equal("2.13.1", version);
    }

    [Fact]
    public void SameNameWithDifferentPublisher_IsNotTreatedAsPatchedAgent()
    {
        var version = InstalledAppScanner.NormalizePatchedAgentVersion(
            "Patched Agent", "Other Publisher", "2.13.1", $"0.13.1+{Sha}");

        Assert.Equal("2.13.1", version);
    }

    [Fact]
    public void SemanticReleaseParser_PreservesFullReleaseWithoutCommitMetadata()
    {
        Assert.Equal(
            "253.255.65535",
            InstalledAppScanner.SemanticReleaseFromInformationalVersion(
                $"253.255.65535+{Sha}"));
    }
}
