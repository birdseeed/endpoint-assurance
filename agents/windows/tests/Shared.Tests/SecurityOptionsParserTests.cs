using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-425: pure normalization of §2.3 Security Options registry values into the
/// compliance signals (server migration 0026). PAT-1767: absent is NotConfigured,
/// a failed read is omitted and never NotConfigured.
/// </summary>
public class SecurityOptionsParserTests
{
    private static RegistryRead P(object v) => RegistryRead.Present(v);

    // Registry value name -> signal key, for every §2.3 control.
    public static TheoryData<string, string> Controls => new()
    {
        { "NoConnectedUser", "block_microsoft_accounts" },
        { "SCENoApplyLegacyAuditPolicy", "audit_force_subcategory_policy" },
        { "DontDisplayLastUserName", "dont_display_last_username" },
        { "InactivityTimeoutSecs", "machine_inactivity_limit_seconds" },
        { "RestrictAnonymousSAM", "restrict_anonymous_sam" },
        { "NoLMHash", "no_lm_hash" },
        { "LmCompatibilityLevel", "lan_manager_auth_level" },
        { "FilterAdministratorToken", "uac_admin_approval_builtin" },
    };

    [Fact]
    public void Evaluate_CompliantValues_AllPassShaped()
    {
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead>
        {
            ["NoConnectedUser"] = P(3),
            ["SCENoApplyLegacyAuditPolicy"] = P(1),
            ["DontDisplayLastUserName"] = P(1),
            ["InactivityTimeoutSecs"] = P(600),
            ["RestrictAnonymousSAM"] = P(1),
            ["NoLMHash"] = P(1),
            ["LmCompatibilityLevel"] = P(5),
            ["FilterAdministratorToken"] = P(1),
        });

        Assert.Equal(8, s.Count);
        Assert.Equal("Yes", s["block_microsoft_accounts"]);
        Assert.Equal("Yes", s["audit_force_subcategory_policy"]);
        Assert.Equal("Yes", s["dont_display_last_username"]);
        Assert.Equal(600, s["machine_inactivity_limit_seconds"]);
        Assert.Equal("Yes", s["restrict_anonymous_sam"]);
        Assert.Equal("Yes", s["no_lm_hash"]);
        Assert.Equal(5, s["lan_manager_auth_level"]);
        Assert.Equal("Yes", s["uac_admin_approval_builtin"]);
    }

    [Fact]
    public void Evaluate_NonCompliantValues_MapToNo()
    {
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead>
        {
            ["NoConnectedUser"] = P(0),         // not 3
            ["RestrictAnonymousSAM"] = P(0),
            ["NoLMHash"] = P(0),
            ["LmCompatibilityLevel"] = P(2),    // < 5
        });

        Assert.Equal("No", s["block_microsoft_accounts"]);
        Assert.Equal("No", s["restrict_anonymous_sam"]);
        Assert.Equal("No", s["no_lm_hash"]);
        Assert.Equal(2, s["lan_manager_auth_level"]);
    }

    [Fact]
    public void Evaluate_InactivityZero_ClampsToFailingSentinel()
    {
        // 0 = "no limit" → must fail `lte 900`.
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead> { ["InactivityTimeoutSecs"] = P(0) });
        Assert.Equal(99999, s["machine_inactivity_limit_seconds"]);
    }

    [Theory]
    [MemberData(nameof(Controls))]
    public void Evaluate_AbsentValue_IsNotConfigured(string valueName, string signal)
    {
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead> { [valueName] = RegistryRead.Absent });
        Assert.Equal("NotConfigured", s[signal]);
        Assert.Single(s);
    }

    [Theory]
    [MemberData(nameof(Controls))]
    public void Evaluate_FailedRead_IsOmitted_NeverNotConfigured(string valueName, string signal)
    {
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead> { [valueName] = RegistryRead.Failed });
        Assert.False(s.ContainsKey(signal));
        Assert.Empty(s);
    }

    [Theory]
    [MemberData(nameof(Controls))]
    public void Evaluate_NonDwordValue_IsOmitted(string valueName, string signal)
    {
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead> { [valueName] = P("3") });
        Assert.False(s.ContainsKey(signal));
    }

    [Fact]
    public void Evaluate_ValuesNotRead_AreOmitted()
    {
        var s = SecurityOptionsParser.Evaluate(new Dictionary<string, RegistryRead> { ["NoLMHash"] = P(1) });
        Assert.Equal("Yes", s["no_lm_hash"]);
        Assert.Single(s);
    }

    [Fact]
    public void Evaluate_NullMap_ReturnsEmpty()
    {
        Assert.Empty(SecurityOptionsParser.Evaluate(null!));
    }
}
