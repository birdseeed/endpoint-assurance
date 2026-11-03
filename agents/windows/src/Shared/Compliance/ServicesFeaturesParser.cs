namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-427 / PAT-405 T2 batch 4 — pure normalization of the CIS Windows 11 §18
/// services-&-features registry values into compliance signals (server migration
/// 0027). The Service reads the raw registry values (Windows-only) and passes
/// them here; this class is API-free and unit-testable off-box.
///
/// Emits "Yes"/"No" per control that was read and found present. PAT-1772: a
/// control the read found genuinely absent is "NotConfigured" — the agent no
/// longer decides what "left at default" scores as; the server-side per-rule
/// `treat_not_configured_as` does (previously a hardcoded per-control default
/// here, e.g. an absent SMBv1 driver read as compliant, an absent LLMNR policy
/// as non-compliant). Every server rule is a simple `eq 'Yes'`.
///
/// PAT-1767: a failed read, a value that is not a DWORD, or a value the caller
/// did not read omits the signal (Unknown to the server); it never takes the
/// NotConfigured branch.
/// </summary>
public static class ServicesFeaturesParser
{
    private const string NotConfigured = ComplianceSignalValue.NotConfigured;

    /// <summary>
    /// Registry reads keyed by the names used here.
    /// </summary>
    public static IReadOnlyDictionary<string, object> Evaluate(IReadOnlyDictionary<string, RegistryRead> raw)
    {
        var s = new Dictionary<string, object>();
        if (raw is null)
            return s;

        // SMBv1 driver: absent (driver not installed, or never configured) -> NotConfigured.
        Set(s, raw, "mrxsmb10_start", "smbv1_disabled", smb => smb == 4 ? "Yes" : "No");

        // LLMNR off: absent policy -> NotConfigured.
        Set(s, raw, "llmnr_enable_multicast", "llmnr_disabled", llmnr => llmnr == 0 ? "Yes" : "No");

        // Autoplay off: NoDriveTypeAutoRun must be 255; absent -> NotConfigured.
        Set(s, raw, "autoplay_no_drive_type", "autoplay_disabled", autoplay => autoplay == 255 ? "Yes" : "No");

        // AlwaysInstallElevated: only value 1 is the (insecure) enabled state;
        // absent -> NotConfigured.
        Set(s, raw, "always_install_elevated", "always_install_elevated_disabled", aie => aie == 1 ? "No" : "Yes");

        // Solicited Remote Assistance: fAllowToGetHelp must be 0; absent -> NotConfigured.
        Set(s, raw, "remote_assistance_allow", "remote_assistance_disabled", ra => ra == 0 ? "Yes" : "No");

        // WDigest cleartext: only value 1 caches plaintext creds; absent -> NotConfigured.
        Set(s, raw, "wdigest_use_logon_credential", "wdigest_cleartext_disabled", wd => wd == 1 ? "No" : "Yes");

        return s;
    }

    private static void Set(
        Dictionary<string, object> s, IReadOnlyDictionary<string, RegistryRead> raw,
        string name, string signal, Func<int, string> map)
    {
        if (!raw.TryGetValue(name, out var read))
            return;
        if (read.State == RegistryReadState.Absent)
            s[signal] = NotConfigured;
        else if (read.TryGetInt(out var v))
            s[signal] = map(v);
    }
}
