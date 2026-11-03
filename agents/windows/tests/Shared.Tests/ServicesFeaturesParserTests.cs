using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-427: §18 services-&-features normalization (server migration 0027).
/// PAT-1772: a successful read that found the value genuinely absent is
/// "NotConfigured"; PAT-1767: a failed read omits the signal.
/// </summary>
public class ServicesFeaturesParserTests
{
    private static readonly string[] Names =
    [
        "mrxsmb10_start", "llmnr_enable_multicast", "autoplay_no_drive_type",
        "always_install_elevated", "remote_assistance_allow", "wdigest_use_logon_credential",
    ];

    private static Dictionary<string, RegistryRead> All(RegistryRead read) =>
        Names.ToDictionary(n => n, _ => read);

    private static RegistryRead P(int v) => RegistryRead.Present(v);

    [Fact]
    public void Evaluate_AllAbsent_IsNotConfigured()
    {
        // PAT-1772: absence no longer resolves to a hardcoded per-control
        // default here; the server's treat_not_configured_as decides. Always 6 signals.
        var s = ServicesFeaturesParser.Evaluate(All(RegistryRead.Absent));

        Assert.Equal(6, s.Count);
        Assert.All(s.Values, v => Assert.Equal("NotConfigured", v));
    }

    [Fact]
    public void Evaluate_AllFailed_OmitsEverySignal_NeverTheAbsentDefault()
    {
        Assert.Empty(ServicesFeaturesParser.Evaluate(All(RegistryRead.Failed)));
    }

    [Fact]
    public void Evaluate_NonDwordValues_OmitEverySignal()
    {
        Assert.Empty(ServicesFeaturesParser.Evaluate(All(RegistryRead.Present("4"))));
    }

    [Fact]
    public void Evaluate_ValuesNotRead_AreOmitted()
    {
        Assert.Empty(ServicesFeaturesParser.Evaluate(new Dictionary<string, RegistryRead>()));
    }

    [Fact]
    public void Evaluate_FullyHardened_AllYes()
    {
        var s = ServicesFeaturesParser.Evaluate(new Dictionary<string, RegistryRead>
        {
            ["mrxsmb10_start"] = P(4),
            ["llmnr_enable_multicast"] = P(0),
            ["autoplay_no_drive_type"] = P(255),
            ["always_install_elevated"] = P(0),
            ["remote_assistance_allow"] = P(0),
            ["wdigest_use_logon_credential"] = P(0),
        });
        Assert.Equal(6, s.Count);
        Assert.All(s.Values, v => Assert.Equal("Yes", v));
    }

    [Fact]
    public void Evaluate_InsecureExplicitValues_MapToNo()
    {
        var s = ServicesFeaturesParser.Evaluate(new Dictionary<string, RegistryRead>
        {
            ["mrxsmb10_start"] = P(2),                  // SMBv1 driver enabled (auto)
            ["always_install_elevated"] = P(1),         // elevated installs on
            ["wdigest_use_logon_credential"] = P(1),    // cleartext caching on
        });
        Assert.Equal("No", s["smbv1_disabled"]);
        Assert.Equal("No", s["always_install_elevated_disabled"]);
        Assert.Equal("No", s["wdigest_cleartext_disabled"]);
    }

    [Fact]
    public void Evaluate_Null_ReturnsEmpty() => Assert.Empty(ServicesFeaturesParser.Evaluate(null!));
}
