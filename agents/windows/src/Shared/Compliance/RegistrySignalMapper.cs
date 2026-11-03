namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-1767: pure mapping from registry reads to the Windows compliance signals that
/// <c>ComplianceCollector</c> reads straight from HKLM. Every mapper keeps the three
/// states apart: an absent value is <see cref="ComplianceSignalValue.NotConfigured"/>,
/// a failed read or a value of an unusable type is
/// <see cref="ComplianceSignalValue.Unknown"/>, and a present value keeps the mapping
/// the signal already had. Where a signal reads more than one value, a failed read met
/// before a usable value is Unknown and never falls through to the next value.
/// </summary>
public static class RegistrySignalMapper
{
    private const string NotConfigured = ComplianceSignalValue.NotConfigured;
    private const string Unknown = ComplianceSignalValue.Unknown;

    /// <summary>
    /// Absent is NotConfigured; failed, non-DWORD, or a DWORD <paramref name="map"/>
    /// returns null for is Unknown.
    /// </summary>
    public static string MapDword(RegistryRead read, Func<int, string?> map) => read.State switch
    {
        RegistryReadState.Absent => NotConfigured,
        RegistryReadState.Present when read.TryGetInt(out var v) => map(v) ?? Unknown,
        _ => Unknown,
    };

    /// <summary>FirewallPolicy\&lt;Profile&gt; EnableFirewall: 1 enabled, anything else disabled.</summary>
    public static string Firewall(RegistryRead enableFirewall) =>
        MapDword(enableFirewall, v => v == 1 ? "enabled" : "disabled");

    /// <summary>Policies\System EnableLUA: 1 Yes, anything else No.</summary>
    public static string Uac(RegistryRead enableLua) =>
        MapDword(enableLua, v => v == 1 ? "Yes" : "No");

    /// <summary>Terminal Server fDenyTSConnections: 0 enabled, anything else disabled.</summary>
    public static string RemoteDesktop(RegistryRead denyTsConnections) =>
        MapDword(denyTsConnections, v => v == 0 ? "enabled" : "disabled");

    /// <summary>
    /// Real-Time Protection DisableRealtimeMonitoring: nonzero disabled, 0 enabled.
    /// PAT-1772: absent is NotConfigured, not the old hardcoded "enabled" default.
    /// </summary>
    public static string DefenderRealtime(RegistryRead disableRealtimeMonitoring) =>
        MapDword(disableRealtimeMonitoring, v => v != 0 ? "disabled" : "enabled");

    /// <summary>LanmanWorkstation RequireSecuritySignature: 1 Yes, anything else No.</summary>
    public static string SmbSigning(RegistryRead requireSecuritySignature) =>
        MapDword(requireSecuritySignature, v => v == 1 ? "Yes" : "No");

    /// <summary>Lsa\FIPSAlgorithmPolicy Enabled: 1 Yes, 0 No, any other value Unknown.</summary>
    public static string Fips(RegistryRead enabled) =>
        MapDword(enabled, v => v == 1 ? "Yes" : v == 0 ? "No" : null);

    /// <summary>SecureBoot\State UEFISecureBootEnabled: 1 Yes, 0 No, any other value Unknown.</summary>
    public static string SecureBoot(RegistryRead uefiSecureBootEnabled) =>
        MapDword(uefiSecureBootEnabled, v => v == 1 ? "Yes" : v == 0 ? "No" : null);

    /// <summary>
    /// mandatory_aslr_enabled (PAT-1770): the system-wide Exploit Protection setting
    /// ForceRelocateImages, read from <c>Session Manager\kernel\MitigationOptions</c>
    /// (REG_BINARY, 24 bytes when set). This is what <c>Set-ProcessMitigation -System</c>
    /// writes and <c>Get-ProcessMitigation -System</c> reports. It is not
    /// <c>Memory Management\MoveImages</c>, which is a separate setting and does not
    /// report ForceRelocateImages.
    /// <para>
    /// The value holds the system PROCESS_CREATION_MITIGATION_POLICY mask as a
    /// little-endian 64-bit integer. Microsoft defines
    /// PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON as 0x1 &lt;&lt; 8
    /// and _ALWAYS_OFF as 0x2 &lt;&lt; 8 (UpdateProcThreadAttribute, winbase.h), so the
    /// setting is the 2-bit field at bits 8-9: byte 1, bits 0-1. 0 defers to the
    /// default, 3 is reserved. The layout was verified on a Windows 11 device on
    /// 2026-09-15: value absent by default (ForceRelocateImages NOTSET),
    /// <c>-Enable ForceRelocateImages</c> sets byte 1 to 0x01 (ON), <c>-Disable</c>
    /// sets it to 0x02 (OFF). The other bits of byte 1 and every other byte belong to
    /// unrelated mitigations and are ignored.
    /// </para>
    /// Absent is NotConfigured; field 1 Yes, 2 No, 0 NotConfigured (explicitly
    /// deferred, the same meaning as unset), 3 Unknown. A failed read, a value that is
    /// not REG_BINARY, or one shorter than 2 bytes is Unknown.
    /// </summary>
    public static string MandatoryAslr(RegistryRead mitigationOptions)
    {
        switch (mitigationOptions.State)
        {
            case RegistryReadState.Absent:
                return NotConfigured;
            case RegistryReadState.Present when mitigationOptions.Value is byte[] { Length: >= 2 } bytes:
                return (bytes[1] & 0x03) switch
                {
                    1 => "Yes",
                    2 => "No",
                    0 => NotConfigured,
                    _ => Unknown,
                };
            default:
                return Unknown;
        }
    }

    /// <summary>SCHANNEL TLS 1.0/1.1 Client or Server Enabled: 0 Yes (disabled), anything else No.</summary>
    public static string TlsDisabled(RegistryRead enabled) =>
        MapDword(enabled, v => v == 0 ? "Yes" : "No");

    /// <summary>
    /// SCHANNEL TLS 1.2 Client or Server: No when Enabled=0 or DisabledByDefault=1,
    /// otherwise Yes. Neither value set is NotConfigured; a failed read of either, or
    /// either value of an unusable type, is Unknown.
    /// </summary>
    public static string TlsEnabled(RegistryRead enabled, RegistryRead disabledByDefault)
    {
        if (enabled.State == RegistryReadState.Failed || disabledByDefault.State == RegistryReadState.Failed)
            return Unknown;
        if (enabled.State == RegistryReadState.Absent && disabledByDefault.State == RegistryReadState.Absent)
            return NotConfigured;
        if (enabled.State == RegistryReadState.Present && !enabled.TryGetInt(out _))
            return Unknown;
        if (disabledByDefault.State == RegistryReadState.Present && !disabledByDefault.TryGetInt(out _))
            return Unknown;
        if (enabled.TryGetInt(out var e) && e == 0)
            return "No";
        if (disabledByDefault.TryGetInt(out var d) && d == 1)
            return "No";
        return "Yes";
    }

    /// <summary>
    /// auto_updates_enabled (PAT-1771, PAT-1780). Sources in precedence order, each read
    /// only when every source before it was read successfully and left the decision open:
    /// <list type="number">
    /// <item>Group Policy <c>Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate</c>:
    /// 1 is No; 0 (Automatic Updates enabled) or absent continues; anything else is Unknown.
    /// 0 is Group Policy's explicit enable: an AUOptions level below still decides, but
    /// when neither AUOptions source sets a level the result is Yes, not NotConfigured.</item>
    /// <item>Group Policy <c>Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions</c>
    /// (Group Policy "Configure Automatic Updates", or the same value written directly).</item>
    /// <item>MDM <c>Microsoft\PolicyManager\current\device\Update\AllowAutoUpdate</c>, the
    /// Policy CSP Update/AllowAutoUpdate value as applied (Intune update rings or settings
    /// catalog). Read only when Group Policy configures neither NoAutoUpdate (0 or 1) nor an
    /// AUOptions level (1 to 5).</item>
    /// <item>Local <c>CurrentVersion\WindowsUpdate\Auto Update\AUOptions</c>, the
    /// preference a local administrator sets when no policy applies.</item>
    /// </list>
    /// AUOptions levels, from Microsoft Learn "Manage additional Windows Update settings"
    /// (learn.microsoft.com/windows/deployment/update/waas-wu-settings, section
    /// "Configuring Automatic Updates by editing the registry", checked 2026-09-15):
    /// 1 automatic updates disabled, 2 notify before download, 3 download automatically
    /// and notify before install, 4 download automatically and install on a schedule,
    /// 5 local admin chooses the setting, 7 download automatically, notify before
    /// install and before restart (Windows Server 2016 and later). The same page says a
    /// policy value overrides the local administrator's preference. 1 and 2 download
    /// nothing unattended, so they are No; 3, 4 and 7 download automatically, so they
    /// are Yes. 0 is the Windows Update Agent's aunlNotConfigured and, like an absent
    /// value, moves on to the next source. Policy 5 hands the choice to the local
    /// administrator, so it resolves through the local AUOptions level; with no local
    /// level it is NotConfigured. The page defines 5 only as a choice the policy makes, so
    /// a local 5 is Unknown, as is any other undocumented value or a non-DWORD. Nothing set
    /// anywhere is NotConfigured. A failed read at any step is Unknown and never falls
    /// through to a later source.
    /// <para>
    /// PAT-1780, AllowAutoUpdate levels, from Microsoft Learn "Update Policy CSP"
    /// (learn.microsoft.com/windows/client-management/mdm/policy-csp-update, section
    /// AllowAutoUpdate, ms.date fetched 2026-09-15): 0 notify the user before
    /// downloading, 1 auto install then notify the user to schedule a restart, 2 auto
    /// install and restart (the CSP default), 3 auto install and restart at a specified
    /// time, 4 auto install and restart without end-user control, 5 turn off automatic
    /// updates. 0 and 5 install nothing without user action, so they are No; 1 to 4 install
    /// automatically, so they are Yes. Any other value or a non-DWORD is Unknown. The CSP
    /// default of 2 is not read from anywhere: an absent value means MDM set nothing, and
    /// the decision moves on to the local preference.
    /// </para>
    /// <para>
    /// Location: Microsoft Learn "Troubleshoot Update ring policies for Windows devices"
    /// (learn.microsoft.com/troubleshoot/mem/intune/device-protection/troubleshoot-update-rings,
    /// ms.date fetched 2026-09-15) says Intune writes applied update ring
    /// settings to <c>HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update</c>. The
    /// value is read alone; the <c>AllowAutoUpdate_ProviderSet</c> and
    /// <c>AllowAutoUpdate_WinningProvider</c> companions are not documented on Microsoft
    /// Learn and are not required. <c>PolicyManager\default\Update</c>, which Microsoft
    /// Learn "Configure Windows Update client policies" lists for other Update policies, is
    /// not read.
    /// </para>
    /// <para>
    /// Group Policy before MDM: the same troubleshooting page says "The ControlPolicyConflict
    /// CSP doesn't apply to the Update Policy CSP", so
    /// <c>ControlPolicyConflict\MDMWinsOverGP</c> does not change this order and is not
    /// read. The Update Policy CSP's IgnoreWindowsUpdateGroupPolicies ("When enabled, Group
    /// Policy settings for Windows Update are ignored and only MDM policy values are
    /// applied", Windows Insider Preview only) exists to let MDM override Group Policy, so
    /// without it Group Policy settings for Windows Update still apply. That Insider-only
    /// policy is not read. The ControlPolicyConflict CSP page
    /// (learn.microsoft.com/windows/client-management/mdm/policy-csp-controlpolicyconflict,
    /// ms.date 2025-03-12) warns that settings configured in both channels outside
    /// MDMWinsOverGP have no guaranteed winner, so the MDM value is only used here when
    /// Group Policy configures nothing, where there is no conflict to resolve.
    /// </para>
    /// </summary>
    public static string AutoUpdates(
        Func<RegistryRead> policyNoAutoUpdate,
        Func<RegistryRead> policyAuOptions,
        Func<RegistryRead> mdmAllowAutoUpdate,
        Func<RegistryRead> localAuOptions)
    {
        var noAuto = policyNoAutoUpdate();
        var explicitlyEnabled = false;
        switch (noAuto.State)
        {
            case RegistryReadState.Failed:
                return Unknown;
            case RegistryReadState.Present:
                if (!noAuto.TryGetInt(out var n) || n is not (0 or 1))
                    return Unknown;
                if (n == 1)
                    return "No";
                explicitlyEnabled = true;
                break;
        }

        var policy = AuOptionsLevel(policyAuOptions());
        if (policy is not (AuLevel.NotSet or AuLevel.LocalAdminChooses))
            return AuLevelSignal(policy);

        // Group Policy configured Automatic Updates (an explicit enable, or a level that
        // hands the choice to the local administrator), so MDM does not override it.
        if (!explicitlyEnabled && policy == AuLevel.NotSet)
        {
            var mdm = AllowAutoUpdateSignal(mdmAllowAutoUpdate());
            if (mdm is not null)
                return mdm;
        }

        var local = AuOptionsLevel(localAuOptions());
        if (local == AuLevel.LocalAdminChooses)
            return Unknown;
        // A failed or unusable read stays Unknown even under an explicit enable.
        return local == AuLevel.NotSet && explicitlyEnabled ? "Yes" : AuLevelSignal(local);
    }

    /// <summary>
    /// The PAT-1771 three-source form, for a device with no MDM source: identical to
    /// <see cref="AutoUpdates(Func{RegistryRead}, Func{RegistryRead}, Func{RegistryRead}, Func{RegistryRead})"/>
    /// with AllowAutoUpdate absent.
    /// </summary>
    public static string AutoUpdates(
        Func<RegistryRead> policyNoAutoUpdate,
        Func<RegistryRead> policyAuOptions,
        Func<RegistryRead> localAuOptions) =>
        AutoUpdates(policyNoAutoUpdate, policyAuOptions, () => RegistryRead.Absent, localAuOptions);

    /// <summary>Eager form of <see cref="AutoUpdates(Func{RegistryRead}, Func{RegistryRead}, Func{RegistryRead}, Func{RegistryRead})"/>.</summary>
    public static string AutoUpdates(
        RegistryRead policyNoAutoUpdate, RegistryRead policyAuOptions, RegistryRead mdmAllowAutoUpdate, RegistryRead localAuOptions) =>
        AutoUpdates(() => policyNoAutoUpdate, () => policyAuOptions, () => mdmAllowAutoUpdate, () => localAuOptions);

    /// <summary>Eager form of <see cref="AutoUpdates(Func{RegistryRead}, Func{RegistryRead}, Func{RegistryRead})"/>.</summary>
    public static string AutoUpdates(RegistryRead policyNoAutoUpdate, RegistryRead policyAuOptions, RegistryRead localAuOptions) =>
        AutoUpdates(() => policyNoAutoUpdate, () => policyAuOptions, () => localAuOptions);

    /// <summary>
    /// Update/AllowAutoUpdate: null when absent (MDM set nothing, continue); 0 and 5 No;
    /// 1 to 4 Yes; a failed read, a non-DWORD or any other value Unknown.
    /// </summary>
    private static string? AllowAutoUpdateSignal(RegistryRead read) => read.State switch
    {
        RegistryReadState.Absent => null,
        RegistryReadState.Present when read.TryGetInt(out var v) => v switch
        {
            0 or 5 => "No",
            1 or 2 or 3 or 4 => "Yes",
            _ => Unknown,
        },
        _ => Unknown,
    };

    private enum AuLevel { NotSet, Manual, Automatic, LocalAdminChooses, Invalid }

    private static AuLevel AuOptionsLevel(RegistryRead read) => read.State switch
    {
        RegistryReadState.Absent => AuLevel.NotSet,
        RegistryReadState.Present when read.TryGetInt(out var v) => v switch
        {
            0 => AuLevel.NotSet,
            1 or 2 => AuLevel.Manual,
            3 or 4 or 7 => AuLevel.Automatic,
            5 => AuLevel.LocalAdminChooses,
            _ => AuLevel.Invalid,
        },
        _ => AuLevel.Invalid,
    };

    private static string AuLevelSignal(AuLevel level) => level switch
    {
        AuLevel.Automatic => "Yes",
        AuLevel.Manual => "No",
        AuLevel.NotSet => NotConfigured,
        _ => Unknown,
    };

    /// <summary>
    /// laps_enrolled: Yes when modern LAPS BackupDirectory is above 0 or legacy
    /// AdmPwdEnabled is 1. With neither, a failed read or unusable value of either is
    /// Unknown. PAT-1772: two successful reads that both found the value genuinely
    /// absent are NotConfigured, not the old hardcoded "No"; a value that was read
    /// and found not to enable LAPS (present but 0, say) is still a real "No".
    /// </summary>
    public static string Laps(RegistryRead modernBackupDirectory, RegistryRead legacyAdmPwdEnabled)
    {
        if (modernBackupDirectory.TryGetInt(out var modern) && modern > 0)
            return "Yes";
        if (legacyAdmPwdEnabled.TryGetInt(out var legacy) && legacy == 1)
            return "Yes";
        if (!Usable(modernBackupDirectory) || !Usable(legacyAdmPwdEnabled))
            return Unknown;
        if (modernBackupDirectory.State == RegistryReadState.Absent &&
            legacyAdmPwdEnabled.State == RegistryReadState.Absent)
            return NotConfigured;
        return "No";
    }

    /// <summary>
    /// security_log_max_size_kb: the policy MaxSize (KB) wins, then the service MaxSize
    /// (bytes, sent as KB). Neither set is NotConfigured. A failed read or unusable value
    /// is Unknown and a failed policy read does not fall through.
    /// </summary>
    public static object SecurityLogMaxSizeKb(RegistryRead policyMaxSizeKb, RegistryRead serviceMaxSizeBytes)
    {
        if (policyMaxSizeKb.State != RegistryReadState.Absent)
            return policyMaxSizeKb.TryGetInt(out var kb) ? kb : Unknown;
        if (serviceMaxSizeBytes.State == RegistryReadState.Absent)
            return NotConfigured;
        return serviceMaxSizeBytes.TryGetInt(out var bytes) ? bytes / 1024 : Unknown;
    }

    /// <summary>
    /// One ASR rule: the Group Policy value wins, then the Defender configuration value.
    /// "1" (block) is Yes and any other value is No. Neither set is NotConfigured; a
    /// failed read met first is Unknown and does not fall through.
    /// </summary>
    public static string AsrRule(RegistryRead policyValue, RegistryRead configValue)
    {
        foreach (var read in new[] { policyValue, configValue })
        {
            switch (read.State)
            {
                case RegistryReadState.Failed:
                    return Unknown;
                case RegistryReadState.Present:
                    // An ASR rule value is an integer, stored as REG_SZ or
                    // REG_DWORD. Any other type or a non-numeric string is not
                    // evidence of the rule's state, so it reads as Unknown
                    // rather than a confident "No" (absence requires authority).
                    string? text = read.Value switch
                    {
                        int n => n.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        string str => str.Trim(),
                        _ => null,
                    };
                    if (!int.TryParse(text, System.Globalization.NumberStyles.None,
                            System.Globalization.CultureInfo.InvariantCulture, out var mode))
                        return Unknown;
                    return mode == 1 ? "Yes" : "No";
            }
        }
        return NotConfigured;
    }

    private static bool Usable(RegistryRead read) =>
        read.State == RegistryReadState.Absent || read.TryGetInt(out _);
}
