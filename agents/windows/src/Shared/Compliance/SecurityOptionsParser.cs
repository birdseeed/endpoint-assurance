namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-425 / PAT-405 T2 batch 3 — pure normalization of the CIS Windows 11 §2.3
/// Security Options registry values into compliance signals (server migration
/// 0026). The Service reads the raw registry values (Windows-only) and passes
/// them here as a name→value map; this class is API-free and unit-testable
/// off-box.
///
/// Binary controls emit "Yes"/"No" (Yes = compliant, matching the T1
/// uac_enabled style); two emit raw numerics. PAT-1767: a value the read found
/// absent (key or value missing) is "NotConfigured", so the server rule decides
/// what the OS default means. A failed read, a value that is not a DWORD, or a
/// value the caller did not read is omitted, which the server treats as Unknown.
/// </summary>
public static class SecurityOptionsParser
{
    // 0 = "no limit" for the inactivity timeout → clamp so `lte 900` fails.
    private const int NoInactivityLimitSentinel = 99999;

    /// <summary>
    /// Maps raw §2.3 registry values (keyed by their registry value name) to the
    /// compliance signals present.
    /// </summary>
    public static IReadOnlyDictionary<string, object> Evaluate(IReadOnlyDictionary<string, RegistryRead> raw)
    {
        var s = new Dictionary<string, object>();
        if (raw is null)
            return s;

        Set(s, raw, "NoConnectedUser", "block_microsoft_accounts", noConnected => noConnected == 3 ? "Yes" : "No");
        Set(s, raw, "SCENoApplyLegacyAuditPolicy", "audit_force_subcategory_policy", forceAudit => forceAudit == 1 ? "Yes" : "No");
        Set(s, raw, "DontDisplayLastUserName", "dont_display_last_username", noLastUser => noLastUser == 1 ? "Yes" : "No");
        Set(s, raw, "InactivityTimeoutSecs", "machine_inactivity_limit_seconds", inactivity => inactivity <= 0 ? NoInactivityLimitSentinel : inactivity);
        Set(s, raw, "RestrictAnonymousSAM", "restrict_anonymous_sam", restrictSam => restrictSam == 1 ? "Yes" : "No");
        Set(s, raw, "NoLMHash", "no_lm_hash", noLmHash => noLmHash == 1 ? "Yes" : "No");
        Set(s, raw, "LmCompatibilityLevel", "lan_manager_auth_level", lmLevel => lmLevel);
        Set(s, raw, "FilterAdministratorToken", "uac_admin_approval_builtin", filterAdmin => filterAdmin == 1 ? "Yes" : "No");

        return s;
    }

    private static void Set(
        Dictionary<string, object> s, IReadOnlyDictionary<string, RegistryRead> raw,
        string valueName, string signal, Func<int, object> map)
    {
        if (!raw.TryGetValue(valueName, out var read))
            return;
        if (read.State == RegistryReadState.Absent)
            s[signal] = ComplianceSignalValue.NotConfigured;
        else if (read.TryGetInt(out var v))
            s[signal] = map(v);
    }
}
