namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-406 / PAT-405 T2 batch 1 — pure parser for the <c>[System Access]</c> section
/// of <c>secedit /export</c> output, producing the CIS Windows 11 §1.1/§1.2
/// account &amp; password-policy compliance signals.
///
/// Kept free of any Windows API so it is unit-testable on any platform; the
/// <c>secedit.exe</c> invocation lives in the Service-side collector.
///
/// Signal contract is defined by the server rule pack
/// (patched.im migration 0024_windows_t2_account_policy.sql). Keys are the flat
/// snake_case keys the server evaluates; values are ints or "Yes"/"No" strings.
/// Anything missing or unparseable is simply omitted — the server's
/// treat_unknown_as='fail' then applies (fail-closed).
/// </summary>
public static class AccountPolicyParser
{
    // Sentinels that make a single-comparator server rule fail correctly when a
    // value of 0 actually means "disabled" (never expire / never lock out).
    // Mirrors the clamp documented in migration 0024.
    private const int MaxAgeNeverSentinel = 99999;   // MaximumPasswordAge 0/-1 → fail `lte 365`
    private const int LockoutNeverSentinel = 999;    // LockoutBadCount 0 → fail `lte 5`

    /// <summary>
    /// Parses secedit export text and returns the account-policy signals present.
    /// Only keys that parse cleanly are included.
    /// </summary>
    public static IReadOnlyDictionary<string, object> Parse(string seceditCfgText)
    {
        var raw = ReadSystemAccess(seceditCfgText);
        var s = new Dictionary<string, object>();

        if (TryInt(raw, "PasswordHistorySize", out var history))
            s["password_history_count"] = history;

        if (TryInt(raw, "MaximumPasswordAge", out var maxAge))
            // 0 or -1 means "never expires" → clamp to a value that fails `lte 365`.
            s["password_max_age_days"] = maxAge <= 0 ? MaxAgeNeverSentinel : maxAge;

        if (TryInt(raw, "MinimumPasswordAge", out var minAge))
            s["password_min_age_days"] = minAge;

        if (TryInt(raw, "MinimumPasswordLength", out var minLen))
            s["password_min_length"] = minLen;

        if (TryInt(raw, "PasswordComplexity", out var complexity))
            s["password_complexity_enabled"] = complexity == 1 ? "Yes" : "No";

        if (TryInt(raw, "ClearTextPassword", out var clearText))
            // ClearTextPassword (reversible encryption) must be off; 0 = compliant.
            s["password_reversible_encryption_disabled"] = clearText == 0 ? "Yes" : "No";

        if (TryInt(raw, "LockoutDuration", out var lockoutDuration))
            s["account_lockout_duration_minutes"] = lockoutDuration;

        if (TryInt(raw, "LockoutBadCount", out var lockoutThreshold))
            // 0 means "never lock out" → clamp to a value that fails `lte 5`.
            s["account_lockout_threshold"] = lockoutThreshold <= 0 ? LockoutNeverSentinel : lockoutThreshold;

        if (TryInt(raw, "ResetLockoutCount", out var resetLockout))
            s["account_lockout_reset_minutes"] = resetLockout;

        return s;
    }

    /// <summary>
    /// Extracts the key=value pairs in the <c>[System Access]</c> section into a
    /// case-insensitive map. Stops at the next section header. Robust to BOM,
    /// CRLF/LF, and arbitrary whitespace around '='.
    /// </summary>
    private static Dictionary<string, string> ReadSystemAccess(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(text))
            return map;

        var inSection = false;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimStart('﻿');
            if (line.Length == 0)
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                inSection = line.Equals("[System Access]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (!inSection)
                continue;

            var eq = line.IndexOf('=');
            if (eq <= 0)
                continue;

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (key.Length > 0)
                map[key] = value;
        }

        return map;
    }

    private static bool TryInt(IReadOnlyDictionary<string, string> raw, string key, out int value)
    {
        value = 0;
        return raw.TryGetValue(key, out var s)
            && int.TryParse(s, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out value);
    }
}
