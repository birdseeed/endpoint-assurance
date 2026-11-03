using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1751: the pure mdm_enrolled decision over a snapshot of
/// HKLM\SOFTWARE\Microsoft\Enrollments subkeys. Subkey presence alone is not
/// enrollment; only a real MDM enrollment reads "Yes".
/// </summary>
public class MdmEnrollmentParserTests
{
    private const string IntuneDiscovery =
        "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc";

    // The three built-in local management authorities seen on an unenrolled
    // Windows 11 VM and the windows-latest runner. EnrollmentType is not modelled
    // because the decision does not read it.
    private static IEnumerable<EnrollmentSubkey> BuiltInAuthorities() => new[]
    {
        new EnrollmentSubkey("{A1B2C3D4-0000-0000-0000-000000000001}", "Deploy Authority", 1, null),
        new EnrollmentSubkey("{A1B2C3D4-0000-0000-0000-000000000002}", "Cloud Authority", 1, null),
        new EnrollmentSubkey("{A1B2C3D4-0000-0000-0000-000000000003}", "Local Authority", 1, null),
    };

    // WIN-STAGING shape: 30 GUID keys with no values, Context, and the three authorities.
    private static List<EnrollmentSubkey> WinStagingShape()
    {
        var keys = new List<EnrollmentSubkey>();
        for (var i = 0; i < 30; i++)
            keys.Add(new EnrollmentSubkey($"{{{Guid.NewGuid().ToString().ToUpperInvariant()}}}", null, null, null));
        keys.Add(new EnrollmentSubkey("Context", null, null, null));
        keys.AddRange(BuiltInAuthorities());
        return keys;
    }

    [Fact]
    public void Evaluate_WinStagingShape_IsNo()
    {
        var snapshot = WinStagingShape();
        Assert.Equal(34, snapshot.Count);
        Assert.Equal("No", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Fact]
    public void Evaluate_IntuneEnrollmentAlongsideAuthorities_IsYes()
    {
        var snapshot = WinStagingShape();
        snapshot.Add(new EnrollmentSubkey("{0F6B7C1E-1111-4A2B-9C3D-4E5F60718293}", "MS DM Server", 1, IntuneDiscovery));

        Assert.Equal("Yes", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Fact]
    public void Evaluate_ThirdPartyMdmWithDiscoveryUrl_IsYes()
    {
        var snapshot = BuiltInAuthorities().ToList();
        snapshot.Add(new EnrollmentSubkey("{9A8B7C6D-2222-4E5F-8A9B-0C1D2E3F4A5B}", "Example MDM",
            1, "https://mdm.example.com/EnrollmentServer/Discovery.svc"));

        Assert.Equal("Yes", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(null)]
    public void Evaluate_MdmEntryNotInEnrolledState_IsNo(int? state)
    {
        var snapshot = BuiltInAuthorities().ToList();
        snapshot.Add(new EnrollmentSubkey("{0F6B7C1E-1111-4A2B-9C3D-4E5F60718293}", "MS DM Server", state, IntuneDiscovery));

        Assert.Equal("No", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Fact]
    public void Evaluate_EmptyOrNullSnapshot_IsNo()
    {
        Assert.Equal("No", MdmEnrollmentParser.Evaluate(Array.Empty<EnrollmentSubkey>()));
        Assert.Equal("No", MdmEnrollmentParser.Evaluate(null));
    }

    [Theory]
    [InlineData("local authority")]
    [InlineData("DEPLOY AUTHORITY")]
    [InlineData(" Cloud Authority ")]
    public void Evaluate_BuiltInAuthorityWithDiscoveryUrl_IsNo(string provider)
    {
        // A discovery URL does not turn a built-in authority into an MDM.
        var snapshot = new[] { new EnrollmentSubkey("{X}", provider, 1, IntuneDiscovery) };
        Assert.Equal("No", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Evaluate_EnrolledStateWithoutDiscoveryUrl_IsNo(string? url)
    {
        var snapshot = new[] { new EnrollmentSubkey("{X}", "MS DM Server", 1, url) };
        Assert.Equal("No", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Evaluate_EnrolledStateWithoutProviderId_IsNo(string? provider)
    {
        var snapshot = new[] { new EnrollmentSubkey("{X}", provider, 1, IntuneDiscovery) };
        Assert.Equal("No", MdmEnrollmentParser.Evaluate(snapshot));
    }

    [Fact]
    public void ToInt_ConvertsRegistryValueShapes()
    {
        Assert.Equal(1, MdmEnrollmentParser.ToInt(1));
        Assert.Equal(1, MdmEnrollmentParser.ToInt(1L));
        Assert.Equal(1, MdmEnrollmentParser.ToInt("1"));
        Assert.Null(MdmEnrollmentParser.ToInt(null));
        Assert.Null(MdmEnrollmentParser.ToInt("enrolled"));
        Assert.Null(MdmEnrollmentParser.ToInt(new byte[] { 1 }));
        Assert.Null(MdmEnrollmentParser.ToInt((long)int.MaxValue + 1));
    }

    [Fact]
    public void ToText_OnlyAcceptsStrings()
    {
        Assert.Equal("MS DM Server", MdmEnrollmentParser.ToText("MS DM Server"));
        Assert.Null(MdmEnrollmentParser.ToText(1));
        Assert.Null(MdmEnrollmentParser.ToText(new[] { "a", "b" }));
        Assert.Null(MdmEnrollmentParser.ToText(null));
    }
}
