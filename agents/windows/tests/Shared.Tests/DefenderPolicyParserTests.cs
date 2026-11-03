using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-428: §18.9.47 Defender policy normalization (server migration 0028).
/// PAT-1772: a successful read that found the value genuinely absent is
/// "NotConfigured"; PAT-1767: a failed read omits the signal.
/// </summary>
public class DefenderPolicyParserTests
{
    private static readonly string[] Names =
    [
        "spynet_reporting", "submit_samples_consent", "pua_protection",
        "disable_behavior_monitoring", "disable_removable_scanning", "disable_archive_scanning",
    ];

    private static Dictionary<string, RegistryRead> All(RegistryRead read) =>
        Names.ToDictionary(n => n, _ => read);

    private static RegistryRead P(int v) => RegistryRead.Present(v);

    [Fact]
    public void Evaluate_AllAbsent_IsNotConfigured()
    {
        // PAT-1772: absence no longer resolves to a hardcoded per-control
        // default here; the server's treat_not_configured_as decides.
        var s = DefenderPolicyParser.Evaluate(All(RegistryRead.Absent));

        Assert.Equal(6, s.Count);
        Assert.All(s.Values, v => Assert.Equal("NotConfigured", v));
    }

    [Fact]
    public void Evaluate_AllFailed_OmitsEverySignal_NeverTheAbsentDefault()
    {
        Assert.Empty(DefenderPolicyParser.Evaluate(All(RegistryRead.Failed)));
    }

    [Fact]
    public void Evaluate_NonDwordValues_OmitEverySignal()
    {
        Assert.Empty(DefenderPolicyParser.Evaluate(All(RegistryRead.Present("1"))));
    }

    [Fact]
    public void Evaluate_ValuesNotRead_AreOmitted()
    {
        Assert.Empty(DefenderPolicyParser.Evaluate(new Dictionary<string, RegistryRead>()));
    }

    [Fact]
    public void Evaluate_FullyHardened_AllYes()
    {
        var s = DefenderPolicyParser.Evaluate(new Dictionary<string, RegistryRead>
        {
            ["spynet_reporting"] = P(2),
            ["submit_samples_consent"] = P(1),
            ["pua_protection"] = P(1),
            ["disable_behavior_monitoring"] = P(0),
            ["disable_removable_scanning"] = P(0),
            ["disable_archive_scanning"] = P(0),
        });
        Assert.Equal(6, s.Count);
        Assert.All(s.Values, v => Assert.Equal("Yes", v));
    }

    [Fact]
    public void Evaluate_DisabledProtections_MapToNo()
    {
        var s = DefenderPolicyParser.Evaluate(new Dictionary<string, RegistryRead>
        {
            ["spynet_reporting"] = P(0),               // MAPS off
            ["submit_samples_consent"] = P(2),         // never send
            ["disable_behavior_monitoring"] = P(1),    // monitoring off
            ["disable_archive_scanning"] = P(1),       // archives skipped
        });
        Assert.Equal("No", s["defender_cloud_protection"]);
        Assert.Equal("No", s["defender_sample_submission"]);
        Assert.Equal("No", s["defender_behavior_monitoring"]);
        Assert.Equal("No", s["defender_archive_scanning"]);
    }

    [Fact]
    public void Evaluate_Null_ReturnsEmpty() => Assert.Empty(DefenderPolicyParser.Evaluate(null!));
}
