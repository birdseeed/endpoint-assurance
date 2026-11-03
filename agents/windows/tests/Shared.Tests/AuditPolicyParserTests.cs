using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-423: the pure auditpol /r CSV parser feeding the CIS Win11 §17 advanced
/// audit-policy signals (server migration 0025).
/// </summary>
public class AuditPolicyParserTests
{
    // Representative `auditpol /get /category:* /r` output (header + a mix of
    // scored and unscored subcategories), matching the real win-staging shape.
    private const string Csv =
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
        "WIN-STAGING,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},No Auditing,\r\n" +
        "WIN-STAGING,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success,\r\n" +
        "WIN-STAGING,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success,\r\n" +
        "WIN-STAGING,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,\r\n" +
        "WIN-STAGING,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n" +
        "WIN-STAGING,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Success,\r\n" +
        "WIN-STAGING,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success,\r\n" +
        "WIN-STAGING,System,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},No Auditing,\r\n" +
        "WIN-STAGING,System,Non Sensitive Privilege Use,{0CCE9229-69AE-11D9-BED3-505054503030},No Auditing,\r\n" +
        "WIN-STAGING,System,System Integrity,{0CCE9212-69AE-11D9-BED3-505054503030},Success and Failure,\r\n" +
        "WIN-STAGING,System,Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success,\r\n";

    [Fact]
    public void Parse_RealShape_MapsTenScoredSubcategories()
    {
        var s = AuditPolicyParser.Parse(Csv);

        Assert.Equal(10, s.Count);
        Assert.Equal("No Auditing", s["audit_credential_validation"]);
        Assert.Equal("Success", s["audit_user_account_management"]);
        Assert.Equal("Success", s["audit_security_group_management"]);
        Assert.Equal("No Auditing", s["audit_process_creation"]);
        Assert.Equal("Success and Failure", s["audit_logon"]);
        Assert.Equal("Success", s["audit_account_lockout"]);
        Assert.Equal("Success", s["audit_policy_change"]);
        Assert.Equal("No Auditing", s["audit_sensitive_privilege_use"]);
        Assert.Equal("Success and Failure", s["audit_system_integrity"]);
        Assert.Equal("Success", s["audit_security_state_change"]);
    }

    [Fact]
    public void Parse_DoesNotConfuseLogonWithSimilarSubcategories()
    {
        // "Logon" must match exactly — not "Special Logon" or "Other Logon/Logoff Events".
        var s = AuditPolicyParser.Parse(
            "WIN,System,Special Logon,{g},Success,\r\n" +
            "WIN,System,Other Logon/Logoff Events,{g},Success and Failure,\r\n" +
            "WIN,System,Logon,{g},Failure,\r\n");
        Assert.Single(s);
        Assert.Equal("Failure", s["audit_logon"]);
    }

    [Fact]
    public void Parse_SkipsHeaderAndUnscoredAndBlankLines()
    {
        var s = AuditPolicyParser.Parse(
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
            "\r\n" +
            "WIN,System,Filtering Platform Connection,{g},Success,\r\n" +   // not scored
            "WIN,System,Process Creation,{g},Success,\r\n");
        Assert.Single(s);
        Assert.Equal("Success", s["audit_process_creation"]);
    }

    [Fact]
    public void Parse_EmptyOrNull_ReturnsEmpty()
    {
        Assert.Empty(AuditPolicyParser.Parse(""));
        Assert.Empty(AuditPolicyParser.Parse(null!));
    }
}
