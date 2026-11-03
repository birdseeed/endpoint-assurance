namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-428 / PAT-405 T2 batch 5 — pure normalization of the CIS Windows 11
/// §18.9.47 Microsoft Defender Antivirus policy values into compliance signals
/// (server migration 0028). The Service reads the raw registry values
/// (Windows-only) and passes them here; this class is API-free and
/// unit-testable off-box.
///
/// Emits "Yes"/"No" per control that was read and found present. PAT-1772: a
/// control the read found genuinely absent is "NotConfigured" — the agent no
/// longer decides what "left at default" scores as; the server-side per-rule
/// `treat_not_configured_as` does (previously a hardcoded per-control default
/// here: controls that are on-by-default, such as behavior monitoring and
/// archive scanning, read as compliant when absent; controls that must be
/// explicitly enforced, such as cloud/MAPS, sample submission, PUA and
/// removable-drive scanning, read as non-compliant when absent). Every server
/// rule is a simple `eq 'Yes'`.
///
/// PAT-1767: a failed read, a value that is not a DWORD, or a value the caller
/// did not read omits the signal (Unknown to the server); it never takes the
/// NotConfigured branch.
/// </summary>
public static class DefenderPolicyParser
{
    private const string NotConfigured = ComplianceSignalValue.NotConfigured;

    public static IReadOnlyDictionary<string, object> Evaluate(IReadOnlyDictionary<string, RegistryRead> raw)
    {
        var s = new Dictionary<string, object>();
        if (raw is null)
            return s;

        // Cloud-delivered protection (MAPS): SpynetReporting 1 (basic) or 2 (advanced).
        // Absent -> NotConfigured.
        Set(s, raw, "spynet_reporting", "defender_cloud_protection", spynet => spynet != 0 ? "Yes" : "No");

        // Sample submission: 1 = send safe samples, 3 = send all (both compliant).
        // Absent -> NotConfigured.
        Set(s, raw, "submit_samples_consent", "defender_sample_submission", samples => samples == 1 || samples == 3 ? "Yes" : "No");

        // PUA protection: 1 = block. Absent -> NotConfigured.
        Set(s, raw, "pua_protection", "defender_pua_protection", pua => pua == 1 ? "Yes" : "No");

        // Behavior monitoring: DisableBehaviorMonitoring must be 0; absent -> NotConfigured.
        Set(s, raw, "disable_behavior_monitoring", "defender_behavior_monitoring", behav => behav == 0 ? "Yes" : "No");

        // Removable-drive scanning: DisableRemovableDriveScanning must be 0;
        // absent -> NotConfigured.
        Set(s, raw, "disable_removable_scanning", "defender_scan_removable_drives", removable => removable == 0 ? "Yes" : "No");

        // Archive scanning: DisableArchiveScanning must be 0; absent -> NotConfigured.
        Set(s, raw, "disable_archive_scanning", "defender_archive_scanning", archive => archive == 0 ? "Yes" : "No");

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
