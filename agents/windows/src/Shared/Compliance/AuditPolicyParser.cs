namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-423 / PAT-405 T2 batch 2 — pure parser for <c>auditpol /get /category:* /r</c>
/// CSV output, producing the CIS Windows 11 §17 Advanced Audit Policy signals.
///
/// CSV columns: Machine Name, Policy Target, Subcategory, Subcategory GUID,
/// Inclusion Setting, Exclusion Setting. We emit the verbatim Inclusion Setting
/// ("No Auditing" | "Success" | "Failure" | "Success and Failure") for the
/// subcategories the server rule pack scores (migration 0025); the server rule
/// (contains/eq) decides pass/fail.
///
/// No Windows API — unit-testable on any platform; the auditpol invocation lives
/// in the Service-side collector. Missing subcategories are omitted (server's
/// treat_unknown_as='fail' applies).
/// </summary>
public static class AuditPolicyParser
{
    // auditpol subcategory display name -> flat snake_case signal key.
    private static readonly IReadOnlyDictionary<string, string> SubcategoryToSignal =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Credential Validation"]      = "audit_credential_validation",
            ["User Account Management"]    = "audit_user_account_management",
            ["Security Group Management"]  = "audit_security_group_management",
            ["Process Creation"]           = "audit_process_creation",
            ["Logon"]                      = "audit_logon",
            ["Account Lockout"]            = "audit_account_lockout",
            ["Audit Policy Change"]        = "audit_policy_change",
            ["Sensitive Privilege Use"]    = "audit_sensitive_privilege_use",
            ["System Integrity"]           = "audit_system_integrity",
            ["Security State Change"]      = "audit_security_state_change",
        };

    /// <summary>
    /// Parses <c>auditpol /r</c> CSV text and returns the scored audit signals present.
    /// </summary>
    public static IReadOnlyDictionary<string, object> Parse(string auditpolCsv)
    {
        var s = new Dictionary<string, object>();
        if (string.IsNullOrEmpty(auditpolCsv))
            return s;

        foreach (var rawLine in auditpolCsv.Split('\n'))
        {
            var line = rawLine.Trim().TrimStart('﻿');
            if (line.Length == 0)
                continue;

            var cols = line.Split(',');
            if (cols.Length < 5)
                continue;

            var subcategory = cols[2].Trim();
            // Skip the CSV header row.
            if (subcategory.Equals("Subcategory", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!SubcategoryToSignal.TryGetValue(subcategory, out var key))
                continue;

            var setting = cols[4].Trim();
            if (setting.Length > 0)
                s[key] = setting;
        }

        return s;
    }
}
