using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-406: the pure secedit [System Access] parser feeding the CIS Win11
/// §1.1/§1.2 account &amp; password-policy signals (server migration 0024).
/// </summary>
public class AccountPolicyParserTests
{
    // A representative, CIS-compliant secedit export (trimmed to relevant areas).
    private const string CompliantCfg =
        "﻿[Unicode]\r\n" +
        "Unicode=yes\r\n" +
        "[System Access]\r\n" +
        "MinimumPasswordAge = 1\r\n" +
        "MaximumPasswordAge = 365\r\n" +
        "MinimumPasswordLength = 14\r\n" +
        "PasswordComplexity = 1\r\n" +
        "PasswordHistorySize = 24\r\n" +
        "ClearTextPassword = 0\r\n" +
        "LockoutBadCount = 5\r\n" +
        "ResetLockoutCount = 30\r\n" +
        "LockoutDuration = 30\r\n" +
        "[Event Audit]\r\n" +
        "AuditSystemEvents = 0\r\n";

    [Fact]
    public void Parse_CompliantExport_MapsAllNineSignals()
    {
        var s = AccountPolicyParser.Parse(CompliantCfg);

        Assert.Equal(24, s["password_history_count"]);
        Assert.Equal(365, s["password_max_age_days"]);
        Assert.Equal(1, s["password_min_age_days"]);
        Assert.Equal(14, s["password_min_length"]);
        Assert.Equal("Yes", s["password_complexity_enabled"]);
        Assert.Equal("Yes", s["password_reversible_encryption_disabled"]);
        Assert.Equal(30, s["account_lockout_duration_minutes"]);
        Assert.Equal(5, s["account_lockout_threshold"]);
        Assert.Equal(30, s["account_lockout_reset_minutes"]);
        Assert.Equal(9, s.Count);
    }

    [Fact]
    public void Parse_MaxAgeZeroOrNegative_ClampsToFailingSentinel()
    {
        // 0 = "never expires"; secedit can also emit -1. Both must fail `lte 365`.
        var zero = AccountPolicyParser.Parse("[System Access]\nMaximumPasswordAge = 0\n");
        Assert.Equal(99999, zero["password_max_age_days"]);

        var never = AccountPolicyParser.Parse("[System Access]\nMaximumPasswordAge = -1\n");
        Assert.Equal(99999, never["password_max_age_days"]);
    }

    [Fact]
    public void Parse_LockoutThresholdZero_ClampsToFailingSentinel()
    {
        // 0 = "never lock out" → must fail `lte 5`.
        var s = AccountPolicyParser.Parse("[System Access]\nLockoutBadCount = 0\n");
        Assert.Equal(999, s["account_lockout_threshold"]);
    }

    [Fact]
    public void Parse_NonCompliantFlags_MapToNo()
    {
        var s = AccountPolicyParser.Parse(
            "[System Access]\nPasswordComplexity = 0\nClearTextPassword = 1\n");
        Assert.Equal("No", s["password_complexity_enabled"]);
        Assert.Equal("No", s["password_reversible_encryption_disabled"]);
    }

    [Fact]
    public void Parse_IgnoresKeysOutsideSystemAccess()
    {
        // A key with the same name in another section must not leak in.
        var s = AccountPolicyParser.Parse(
            "[Event Audit]\nMinimumPasswordLength = 99\n[System Access]\nMinimumPasswordLength = 14\n");
        Assert.Equal(14, s["password_min_length"]);
    }

    [Fact]
    public void Parse_MissingOrJunkValues_AreOmitted()
    {
        var s = AccountPolicyParser.Parse(
            "[System Access]\nMinimumPasswordLength = notanumber\nPasswordHistorySize = 12\n");
        Assert.False(s.ContainsKey("password_min_length"));   // junk → omitted (server fails closed)
        Assert.Equal(12, s["password_history_count"]);
        Assert.False(s.ContainsKey("account_lockout_threshold")); // absent → omitted
    }

    [Fact]
    public void Parse_EmptyOrNull_ReturnsEmpty()
    {
        Assert.Empty(AccountPolicyParser.Parse(""));
        Assert.Empty(AccountPolicyParser.Parse(null!));
    }
}
