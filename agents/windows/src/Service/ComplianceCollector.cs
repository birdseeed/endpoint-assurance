using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;

namespace Patched.Service;

/// <summary>
/// Reads one value under a registry root. Returns <see cref="RegistryReadState.Absent"/>
/// when the key or value does not exist and <see cref="RegistryReadState.Failed"/> when
/// the read threw; it never throws.
/// </summary>
internal delegate RegistryRead RegistryValueReader(string keyPath, string valueName);

/// <summary>
/// Collects raw CIS Windows L1 compliance signals for the schema v3 inventory payload.
/// All reads are non-fatal. PAT-1767: a setting the read found absent emits
/// "NotConfigured" and a failed read emits "Unknown" (or omits the signal); the two are
/// never the same branch.
/// Raw signals — not pre-evaluated verdicts — are sent so the server evaluates per-tenant rules.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ComplianceCollector
{
    private readonly ILogger<ComplianceCollector> _log;
    private readonly RegistryValueReader _hklm;

    public ComplianceCollector(ILogger<ComplianceCollector> log)
        : this(log, hklm: null)
    {
    }

    /// <summary>
    /// Test seam: <paramref name="hklm"/> replaces the HKEY_LOCAL_MACHINE value reader.
    /// Production uses the public constructor, which reads the real registry.
    /// </summary>
    internal ComplianceCollector(ILogger<ComplianceCollector> log, RegistryValueReader? hklm)
    {
        _log = log;
        _hklm = hklm ?? ((keyPath, valueName) => ReadValue(Registry.LocalMachine, keyPath, valueName, _log));
    }

    /// <summary>
    /// Reads <paramref name="valueName"/> under <paramref name="root"/>\<paramref name="keyPath"/>
    /// read-only. A missing key or value is Absent; any exception is Failed.
    /// </summary>
    internal static RegistryRead ReadValue(RegistryKey root, string keyPath, string valueName, ILogger? log = null) =>
        RegistryRead.Capture(
            () =>
            {
                using var key = root.OpenSubKey(keyPath, writable: false);
                return key?.GetValue(valueName);
            },
            ex => log?.LogDebug(ex, "ComplianceCollector: registry read failed: {Key}\\{Value}", keyPath, valueName));

    public Dictionary<string, object> Collect()
    {
        var signals = new Dictionary<string, object>();

        AddBitlocker(signals);
        AddFirewall(signals);
        AddDefender(signals);
        AddUac(signals);
        AddAutoUpdates(signals);
        AddRemoteDesktop(signals);
        AddSmbSigning(signals);
        AddScreensaver(signals);
        AddMdmEnrolment(signals);
        AddAccountPolicy(signals);
        AddAuditPolicy(signals);
        AddSecurityOptions(signals);
        AddServicesFeatures(signals);
        AddDefenderPolicy(signals);
        AddFipsAndTls(signals);
        AddSecureBoot(signals);
        AddTpmReady(signals);
        AddDeviceGuard(signals);
        AddExploitProtection(signals);
        AddLaps(signals);
        AddEventLogSecurity(signals);
        AddDefenderSignatures(signals);
        AddAsrRules(signals);

        // local_admin_count is NOT set here. PAT-1974: it and the structured local_admins
        // roster have to come from one enumeration of the Administrators group, or the
        // count and the roster can disagree about what a single run saw. That read lives
        // in LocalAdminCollector and InventoryPoster.BuildPayloadAsync writes the signal
        // into this bag straight afterwards, the same way it folds one metering read into
        // both apps[] and metering_status. A second read here would be a second answer.

        return signals;
    }

    private void AddBitlocker(Dictionary<string, object> s)
    {
        // Win32_EncryptableVolume lives in root\CIMV2\Security\MicrosoftVolumeEncryption.
        // ProtectionStatus: 0=Off, 1=On, 2=Unknown
        try
        {
            var scope = new ManagementScope(
                @"\\.\root\CIMV2\Security\MicrosoftVolumeEncryption");
            scope.Connect();
            using var mos = new ManagementObjectSearcher(scope,
                new ObjectQuery(
                    "SELECT ProtectionStatus, EncryptionMethod FROM Win32_EncryptableVolume WHERE DriveLetter='C:'"));
            foreach (ManagementObject obj in mos.Get())
            {
                var status = Convert.ToInt32(obj["ProtectionStatus"]);
                var enc    = obj["EncryptionMethod"] != null ? Convert.ToInt32(obj["EncryptionMethod"]) : 0;
                s["bitlocker_os_drive"]      = status == 1 ? "On" : status == 2 ? "Unknown" : "Off";
                // 256-bit methods: AES-256+Diffuser (2), AES-256-CBC (4), XTS-AES-256 (7)
                s["bitlocker_cipher_256bit"] = status == 1 && (enc == 2 || enc == 4 || enc == 7) ? "Yes" : "No";
                return;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: BitLocker WMI query failed");
        }
        s["bitlocker_os_drive"]      = "Unknown";
        s["bitlocker_cipher_256bit"] = "Unknown";
    }

    internal void AddFirewall(Dictionary<string, object> s)
    {
        const string fw = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        s["windows_firewall_domain"]  = RegistrySignalMapper.Firewall(_hklm($@"{fw}\DomainProfile", "EnableFirewall"));
        s["windows_firewall_private"] = RegistrySignalMapper.Firewall(_hklm($@"{fw}\StandardProfile", "EnableFirewall"));
        s["windows_firewall_public"]  = RegistrySignalMapper.Firewall(_hklm($@"{fw}\PublicProfile", "EnableFirewall"));
    }

    // PAT-1772: key or value absent is NotConfigured, not a hardcoded "enabled" default.
    internal void AddDefender(Dictionary<string, object> s) =>
        s["defender_realtime"] = RegistrySignalMapper.DefenderRealtime(
            _hklm(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"));

    internal void AddUac(Dictionary<string, object> s) =>
        s["uac_enabled"] = RegistrySignalMapper.Uac(
            _hklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"));

    // PAT-1771, PAT-1780: Group Policy NoAutoUpdate, then Group Policy AUOptions, then
    // the MDM (Policy CSP Update/AllowAutoUpdate) value as applied under PolicyManager,
    // then the local AUOptions preference; precedence and level mapping live in
    // RegistrySignalMapper.AutoUpdates. The reads are passed lazily so a source is only
    // read when the mapper needs it, which keeps a failed read from falling through to a
    // later source.
    internal void AddAutoUpdates(Dictionary<string, object> s)
    {
        const string policyAu = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
        const string mdmUpdate = @"SOFTWARE\Microsoft\PolicyManager\current\device\Update";
        const string localAu = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";
        s["auto_updates_enabled"] = RegistrySignalMapper.AutoUpdates(
            () => _hklm(policyAu, "NoAutoUpdate"),
            () => _hklm(policyAu, "AUOptions"),
            () => _hklm(mdmUpdate, "AllowAutoUpdate"),
            () => _hklm(localAu, "AUOptions"));
    }

    internal void AddRemoteDesktop(Dictionary<string, object> s) =>
        s["remote_desktop_enabled"] = RegistrySignalMapper.RemoteDesktop(
            _hklm(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"));

    internal void AddSmbSigning(Dictionary<string, object> s) =>
        s["smb_signing_required"] = RegistrySignalMapper.SmbSigning(
            _hklm(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature"));

    // PAT-1747: Group Policy and Intune set the CIS 19.1.3.x screen saver settings as
    // User Configuration, which lands in the console user's
    // HKCU\Software\Policies\...\Control Panel\Desktop. As LocalSystem the Service
    // reaches it through HKEY_USERS\<console user SID>. Precedence (user policy, then
    // the user's own preference) and the Unknown rules live in
    // Patched.Shared.Compliance.ScreensaverPolicyResolver so they are unit-tested
    // off-box. HKLM policy is deliberately not read: these settings are User
    // Configuration only and Windows is not known to apply an HKLM value to a user
    // session, so it is not evidence (see the resolver). All reads are read-only; an
    // unloaded hive is never loaded.
    private void AddScreensaver(Dictionary<string, object> s)
    {
        ScreensaverSnapshot? snapshot = null;
        try
        {
            snapshot = ReadScreensaverSnapshot(Registry.Users, ConsoleSessionUser.Resolve(), _log);
        }
        catch (Exception ex)
        {
            // A null snapshot makes every screen saver signal Unknown.
            _log.LogDebug(ex, "ComplianceCollector: screensaver snapshot failed");
        }

        foreach (var kv in ScreensaverPolicyResolver.Evaluate(snapshot))
            s[kv.Key] = kv.Value;
    }

    /// <summary>
    /// Reads the console user's screen saver keys. The users root is a parameter so a
    /// Windows test can point it at a scratch key; production passes HKEY_USERS.
    /// </summary>
    internal static ScreensaverSnapshot ReadScreensaverSnapshot(
        RegistryKey usersRoot, ConsoleUserLookup consoleUser, ILogger? log = null)
    {
        if (consoleUser.Status == ConsoleUserLookupStatus.NoConsoleUser)
            return ScreensaverPolicyResolver.BuildSnapshot(ConsoleUserHive.NoConsoleUser, null, _ => DesktopKey.Failed);

        var sid = consoleUser.Sid;
        if (consoleUser.Status != ConsoleUserLookupStatus.Resolved || !IsPlausibleSid(sid))
            return ScreensaverPolicyResolver.BuildSnapshot(ConsoleUserHive.ReadFailed, null, _ => DesktopKey.Failed);

        RegistryKey? hive;
        try
        {
            hive = usersRoot.OpenSubKey(sid!, writable: false);
        }
        catch (Exception ex)
        {
            log?.LogDebug(ex, "ComplianceCollector: could not open console user hive");
            return ScreensaverPolicyResolver.BuildSnapshot(ConsoleUserHive.ReadFailed, null, _ => DesktopKey.Failed);
        }

        if (hive is null)
            return ScreensaverPolicyResolver.BuildSnapshot(ConsoleUserHive.NotLoaded, null, _ => DesktopKey.Failed);

        using (hive)
        {
            return ScreensaverPolicyResolver.BuildSnapshot(
                ConsoleUserHive.Available, sid, path => ReadUserDesktopKey(hive, sid!, path, log));
        }
    }

    /// <summary>
    /// Reads a key the resolver asked for by full path. Only paths inside
    /// HKEY_USERS\&lt;sid&gt;\ are served, from the already-open hive; any other path
    /// (HKLM included) is a failed read, so it can only ever produce "Unknown".
    /// </summary>
    internal static DesktopKey ReadUserDesktopKey(RegistryKey hive, string sid, string fullPath, ILogger? log = null)
    {
        var prefix = $@"{ScreensaverPolicyResolver.UsersHive}\{sid}\";
        if (!fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            log?.LogDebug("ComplianceCollector: screensaver read outside the console user hive refused: {Path}", fullPath);
            return DesktopKey.Failed;
        }

        var subPath = fullPath[prefix.Length..];
        try
        {
            using var key = hive.OpenSubKey(subPath, writable: false);
            if (key is null)
                return DesktopKey.Absent;
            return new DesktopKey(
                DesktopKeyState.Present,
                key.GetValue("ScreenSaveActive"),
                key.GetValue("ScreenSaverIsSecure"),
                key.GetValue("ScreenSaveTimeOut"),
                key.GetValue("SCRNSAVE.EXE"));
        }
        catch (Exception ex)
        {
            log?.LogDebug(ex, "ComplianceCollector: screensaver registry read failed for {Path}", fullPath);
            return DesktopKey.Failed;
        }
    }

    // A SID from GetTokenInformation is always "S-1-..."; anything else, or a value
    // that could name a nested key, is not used as an HKEY_USERS subkey name.
    private static bool IsPlausibleSid(string? sid) =>
        !string.IsNullOrEmpty(sid)
        && sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
        && sid.IndexOfAny(['\\', '/']) < 0;

    // PAT-1751: subkey presence is not enrollment. Windows creates Enrollments
    // subkeys (GUID keys, Context, and the built-in Local/Deploy/Cloud Authority
    // entries) on devices that were never enrolled. The decision lives in
    // Patched.Shared.Compliance.MdmEnrollmentParser so it is unit-tested off-box.
    // A missing Enrollments key is "No"; any read exception is "Unknown".
    private void AddMdmEnrolment(Dictionary<string, object> s)
    {
        const string path = @"SOFTWARE\Microsoft\Enrollments";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            var snapshot = new List<EnrollmentSubkey>();
            if (key is not null)
            {
                foreach (var name in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(name);
                    // Null here means the subkey was removed between enumeration
                    // and open; it no longer exists, so there is nothing to read.
                    if (sub is null)
                        continue;
                    snapshot.Add(new EnrollmentSubkey(
                        name,
                        MdmEnrollmentParser.ToText(sub.GetValue("ProviderID")),
                        MdmEnrollmentParser.ToInt(sub.GetValue("EnrollmentState")),
                        MdmEnrollmentParser.ToText(sub.GetValue("DiscoveryServiceFullURL"))));
                }
            }
            s["mdm_enrolled"] = MdmEnrollmentParser.Evaluate(snapshot);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: MDM enrollment registry read failed");
            s["mdm_enrolled"] = "Unknown";
        }
    }

    // CIS Win11 §1.1 Password Policy + §1.2 Account Lockout (PAT-406 / PAT-405 T2).
    // The legacy account-policy knobs are not in the registry; secedit /export is
    // the reliable SYSTEM-context source. Parsing is pure and lives in
    // Patched.Shared.Compliance.AccountPolicyParser so it is unit-tested off-box.
    private void AddAccountPolicy(Dictionary<string, object> s)
    {
        string? tmp = null;
        try
        {
            tmp = Path.Combine(Path.GetTempPath(), $"patched-secpol-{Guid.NewGuid():N}.cfg");

            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "secedit.exe",
                Arguments = $"/export /cfg \"{tmp}\" /areas SECURITYPOLICY",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (p is null)
                return;
            p.WaitForExit(15_000);

            if (!File.Exists(tmp))
                return;

            // secedit writes UTF-16; ReadAllText honours the BOM.
            var text = File.ReadAllText(tmp);
            foreach (var kv in AccountPolicyParser.Parse(text))
                s[kv.Key] = kv.Value;
        }
        catch (Exception ex)
        {
            // Non-fatal: omit signals → server treat_unknown_as='fail' applies.
            _log.LogDebug(ex, "ComplianceCollector: secedit account-policy export failed");
        }
        finally
        {
            try
            {
                if (tmp is not null && File.Exists(tmp))
                    File.Delete(tmp);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "ComplianceCollector: secedit temp cleanup failed");
            }
        }
    }

    // CIS Win11 §17 Advanced Audit Policy (PAT-423 / PAT-405 T2 batch 2).
    // auditpol /r emits per-subcategory CSV; parsing is pure and lives in
    // Patched.Shared.Compliance.AuditPolicyParser so it is unit-tested off-box.
    private void AddAuditPolicy(Dictionary<string, object> s)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/get /category:* /r",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (p is null)
                return;

            var csv = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15_000);

            foreach (var kv in AuditPolicyParser.Parse(csv))
                s[kv.Key] = kv.Value;
        }
        catch (Exception ex)
        {
            // Non-fatal: omit signals → server treat_unknown_as='fail' applies.
            _log.LogDebug(ex, "ComplianceCollector: auditpol audit-policy query failed");
        }
    }

    // CIS Win11 §2.3 Security Options (PAT-425 / PAT-405 T2 batch 3).
    // Reads the registry-backed security options; the pure Yes/No + clamp
    // normalization lives in Patched.Shared.Compliance.SecurityOptionsParser so
    // it is unit-tested off-box.
    internal void AddSecurityOptions(Dictionary<string, object> s)
    {
        try
        {
            const string policies = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            const string lsa      = @"SYSTEM\CurrentControlSet\Control\Lsa";

            var raw = new Dictionary<string, RegistryRead>
            {
                ["NoConnectedUser"]             = _hklm(policies, "NoConnectedUser"),
                ["DontDisplayLastUserName"]     = _hklm(policies, "DontDisplayLastUserName"),
                ["InactivityTimeoutSecs"]       = _hklm(policies, "InactivityTimeoutSecs"),
                ["FilterAdministratorToken"]    = _hklm(policies, "FilterAdministratorToken"),
                ["SCENoApplyLegacyAuditPolicy"] = _hklm(lsa, "SCENoApplyLegacyAuditPolicy"),
                ["RestrictAnonymousSAM"]        = _hklm(lsa, "RestrictAnonymousSAM"),
                ["NoLMHash"]                    = _hklm(lsa, "NoLMHash"),
                ["LmCompatibilityLevel"]        = _hklm(lsa, "LmCompatibilityLevel"),
            };

            foreach (var kv in SecurityOptionsParser.Evaluate(raw))
                s[kv.Key] = kv.Value;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: security-options registry read failed");
        }
    }

    // CIS Win11 §18 services & features (PAT-427 / PAT-405 T2 batch 4).
    internal void AddServicesFeatures(Dictionary<string, object> s)
    {
        try
        {
            var raw = new Dictionary<string, RegistryRead>
            {
                ["mrxsmb10_start"]               = _hklm(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"),
                ["llmnr_enable_multicast"]       = _hklm(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"),
                ["autoplay_no_drive_type"]       = _hklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"),
                ["always_install_elevated"]      = _hklm(@"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated"),
                ["remote_assistance_allow"]      = _hklm(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fAllowToGetHelp"),
                ["wdigest_use_logon_credential"] = _hklm(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
            };
            foreach (var kv in ServicesFeaturesParser.Evaluate(raw))
                s[kv.Key] = kv.Value;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: services-&-features registry read failed");
        }
    }

    // CIS Win11 §18.9.47 Microsoft Defender policy (PAT-428 / PAT-405 T2 batch 5).
    internal void AddDefenderPolicy(Dictionary<string, object> s)
    {
        try
        {
            const string def = @"SOFTWARE\Policies\Microsoft\Windows Defender";
            var raw = new Dictionary<string, RegistryRead>
            {
                ["spynet_reporting"]            = _hklm($@"{def}\Spynet", "SpynetReporting"),
                ["submit_samples_consent"]      = _hklm($@"{def}\Spynet", "SubmitSamplesConsent"),
                ["pua_protection"]              = _hklm(def, "PUAProtection"),
                ["disable_behavior_monitoring"] = _hklm($@"{def}\Real-Time Protection", "DisableBehaviorMonitoring"),
                ["disable_removable_scanning"]  = _hklm($@"{def}\Scan", "DisableRemovableDriveScanning"),
                ["disable_archive_scanning"]    = _hklm($@"{def}\Scan", "DisableArchiveScanning"),
            };
            foreach (var kv in DefenderPolicyParser.Evaluate(raw))
                s[kv.Key] = kv.Value;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: Defender-policy registry read failed");
        }
    }

    // ── NIST SP 800-53 Rev 5 expansion (PAT-590) ─────────────────────────────

    // IA-7, SC-8, SC-13 — FIPS and Schannel protocol enforcement.
    internal void AddFipsAndTls(Dictionary<string, object> s)
    {
        s["fips_mode_enabled"] = RegistrySignalMapper.Fips(
            _hklm(@"SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy", "Enabled"));

        const string schannel = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";
        s["tls10_client_disabled"] = RegistrySignalMapper.TlsDisabled(_hklm($@"{schannel}\TLS 1.0\Client", "Enabled"));
        s["tls10_server_disabled"] = RegistrySignalMapper.TlsDisabled(_hklm($@"{schannel}\TLS 1.0\Server", "Enabled"));
        s["tls11_client_disabled"] = RegistrySignalMapper.TlsDisabled(_hklm($@"{schannel}\TLS 1.1\Client", "Enabled"));
        s["tls11_server_disabled"] = RegistrySignalMapper.TlsDisabled(_hklm($@"{schannel}\TLS 1.1\Server", "Enabled"));
        s["tls12_client_enabled"]  = ReadTlsEnabled($@"{schannel}\TLS 1.2\Client");
        s["tls12_server_enabled"]  = ReadTlsEnabled($@"{schannel}\TLS 1.2\Server");
    }

    private string ReadTlsEnabled(string keyPath) =>
        RegistrySignalMapper.TlsEnabled(_hklm(keyPath, "Enabled"), _hklm(keyPath, "DisabledByDefault"));

    // SI-7 — Secure Boot via UEFI firmware state registry key.
    internal void AddSecureBoot(Dictionary<string, object> s) =>
        s["secure_boot_enabled"] = RegistrySignalMapper.SecureBoot(
            _hklm(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"));

    // SI-7 — TPM presence and activation via WMI Win32_Tpm.
    private void AddTpmReady(Dictionary<string, object> s)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftTpm");
            scope.Connect();
            using var mos = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT IsEnabled_InitialValue, IsActivated_InitialValue FROM Win32_Tpm"));
            foreach (ManagementObject obj in mos.Get())
            {
                var enabled   = obj["IsEnabled_InitialValue"]   is bool en && en;
                var activated = obj["IsActivated_InitialValue"] is bool ac && ac;
                s["tpm_ready"] = enabled && activated ? "Yes" : "No";
                return;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: TPM WMI query failed");
        }
        s["tpm_ready"] = "Unknown";
    }

    /// <summary>
    /// PAT-2263: the raw Win32_DeviceGuard HypervisorEnforcedCodeIntegrityStatus the last
    /// <see cref="Collect"/> read, so the kernel driver block can tell HVCI running (2) from
    /// configured (1) without a second query. <c>hvci_enabled</c> folds both into "Yes", which
    /// is right for the CIS signal but not for "does HVCI force the vulnerable driver
    /// blocklist", which only a running HVCI does. Failed until Collect has run.
    /// </summary>
    internal SourceRead LastHvciStatus { get; private set; } = SourceRead.Failed;

    // SC-39, SI-16, SC-41 — VBS, HVCI, Kernel DMA via Win32_DeviceGuard WMI.
    private void AddDeviceGuard(Dictionary<string, object> s)
    {
        LastHvciStatus = SourceRead.Failed;
        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\DeviceGuard");
            scope.Connect();
            using var mos = new ManagementObjectSearcher(scope,
                new ObjectQuery(
                    "SELECT VirtualizationBasedSecurityStatus, " +
                    "HypervisorEnforcedCodeIntegrityStatus, KernelDmaProtectionStatus " +
                    "FROM Win32_DeviceGuard"));
            foreach (ManagementObject obj in mos.Get())
            {
                var vbs  = obj["VirtualizationBasedSecurityStatus"]      != null ? Convert.ToInt32(obj["VirtualizationBasedSecurityStatus"])      : -1;
                var hvci = obj["HypervisorEnforcedCodeIntegrityStatus"]  != null ? Convert.ToInt32(obj["HypervisorEnforcedCodeIntegrityStatus"])  : -1;
                LastHvciStatus = obj["HypervisorEnforcedCodeIntegrityStatus"] is { } rawHvci
                    ? SourceRead.Present(rawHvci)
                    : SourceRead.Absent;
                var kdma = obj["KernelDmaProtectionStatus"]               != null ? Convert.ToInt32(obj["KernelDmaProtectionStatus"])               : -1;
                s["vbs_enabled"]           = vbs  == 2 ? "Yes" : vbs  >= 0 ? "No" : "Unknown";
                s["hvci_enabled"]          = hvci >= 1 ? "Yes" : hvci >= 0 ? "No" : "Unknown";
                s["kernel_dma_protection"] = kdma == 1 ? "Yes" : kdma >= 0 ? "No" : "Unknown";
                return;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: DeviceGuard WMI query failed");
        }
        s["vbs_enabled"]           = "Unknown";
        s["hvci_enabled"]          = "Unknown";
        s["kernel_dma_protection"] = "Unknown";
    }

    // SI-16: Mandatory ASLR (ForceRelocateImages), the system Exploit Protection
    // setting in Session Manager\kernel MitigationOptions (PAT-1770). Not MoveImages.
    internal void AddExploitProtection(Dictionary<string, object> s) =>
        s["mandatory_aslr_enabled"] = RegistrySignalMapper.MandatoryAslr(_hklm(
            @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
            "MitigationOptions"));

    // AC-2, IA-5 — Windows LAPS enrollment (modern built-in and legacy extension).
    // Modern LAPS (Win 11 22H2+): BackupDirectory 1=Azure AD, 2=AD. Legacy: AdmPwdEnabled=1.
    internal void AddLaps(Dictionary<string, object> s) =>
        s["laps_enrolled"] = RegistrySignalMapper.Laps(
            _hklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config", "BackupDirectory"),
            _hklm(@"SOFTWARE\Policies\Microsoft Services\AdmPwd", "AdmPwdEnabled"));

    // AU-11 — Security event log maximum size. GPO key stores KB; system key stores bytes.
    internal void AddEventLogSecurity(Dictionary<string, object> s) =>
        s["security_log_max_size_kb"] = RegistrySignalMapper.SecurityLogMaxSizeKb(
            _hklm(@"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", "MaxSize"),
            _hklm(@"SYSTEM\CurrentControlSet\Services\EventLog\Security", "MaxSize"));

    // SI-3 — Defender antivirus signature age via MSFT_MpComputerStatus WMI.
    private void AddDefenderSignatures(Dictionary<string, object> s)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
            scope.Connect();
            using var mos = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT AntivirusSignatureAge FROM MSFT_MpComputerStatus"));
            foreach (ManagementObject obj in mos.Get())
            {
                s["defender_definition_age_days"] = Convert.ToInt32(obj["AntivirusSignatureAge"]);
                return;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ComplianceCollector: Defender signature WMI query failed");
        }
        s["defender_definition_age_days"] = "Unknown";
    }

    // SI-3, CM-7 — ASR rule states (block mode = "Yes") via Defender registry.
    internal void AddAsrRules(Dictionary<string, object> s)
    {
        // Rule GUIDs: ransomware protection; PSExec+WMI process-creation block
        s["asr_ransomware_enabled"]       = ReadAsrRule("c1db55ab-c21a-4637-bb3f-a12568109d35");
        s["asr_psexec_wmi_block_enabled"] = ReadAsrRule("d1e49aac-8f56-4280-b9ba-993a6d77406c");
    }

    private string ReadAsrRule(string guid)
    {
        const string gpo = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
        const string cfg = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
        var policy = _hklm(gpo, guid);
        // The configuration value is only consulted when the policy read found nothing,
        // so a failed policy read cannot fall through to it.
        var config = policy.State == RegistryReadState.Absent ? _hklm(cfg, guid) : RegistryRead.Absent;
        return RegistrySignalMapper.AsrRule(policy, config);
    }
}
