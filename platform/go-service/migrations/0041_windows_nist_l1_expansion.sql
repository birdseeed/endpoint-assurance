-- patched.im — 0041_windows_nist_l1_expansion.sql
-- PAT-590: Windows NIST SP 800-53 Rev 5 expansion — 19 new T2 signals.
--
-- Driven by NIST SP 800-53 Rev 5 (Sept 2020) Moderate baseline gaps vs current
-- CIS L1 Windows coverage. All rules use platform='windows', collection_tier='T2'.
-- Windows agent v0.8.0 required for non-null signal values.
--
-- Groups:
--   IA-7, SC-8, SC-13  — FIPS mode + Schannel TLS 1.0/1.1 disabled + TLS 1.2 enabled (7 rules)
--   SC-28, SC-13        — BitLocker 256-bit cipher strength (1 rule)
--   SI-7                — Secure Boot + TPM ready (2 rules)
--   SC-39, SI-16, SC-41 — VBS, HVCI, Kernel DMA Protection (3 rules)
--   SI-16               — Mandatory ASLR system-wide (1 rule)
--   AC-2, IA-5          — LAPS enrolled (1 rule)
--   AU-11               — Security event log max size ≥ 192 MB (1 rule)
--   SI-3                — Defender definition age ≤ 1 day + 2 ASR rules (3 rules)
--
-- Note: password_min_length, password_complexity_enabled, password_max_age_days,
-- lan_manager_auth_level and smb_signing_required are already covered by existing
-- CIS L1 rules (migrations 0024, 0026, 0019).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0041_windows_nist_l1_expansion.sql
-- Note: 0040_macos_cis_l1_expansion.sql must have been applied first.

BEGIN;

-- ============================================================================
-- IA-7, SC-13 — FIPS 140-2 compliant cryptography mode
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_ia7_fips_mode_enabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'FIPS 140-2 compliant cryptography mode enabled',
    'NIST IA-7 / SC-13. Windows FIPS policy forces the OS to use only FIPS-approved cryptographic algorithms. Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled = 1.',
    'medium',
    'fips_mode_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-7', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SC-8, SC-13 — TLS 1.0 disabled (client + server)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc13_tls10_client_disabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TLS 1.0 disabled for Schannel client',
    'NIST SC-8 / SC-13. TLS 1.0 is deprecated (NIST SP 800-52 Rev 2). Schannel client subkey: HKLM\...\SCHANNEL\Protocols\TLS 1.0\Client\Enabled = 0. Unknown = OS default (disabled on Win11); treat as pass.',
    'high',
    'tls10_client_disabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-8', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc13_tls10_server_disabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TLS 1.0 disabled for Schannel server',
    'NIST SC-8 / SC-13. TLS 1.0 is deprecated (NIST SP 800-52 Rev 2). Schannel server subkey: HKLM\...\SCHANNEL\Protocols\TLS 1.0\Server\Enabled = 0. Unknown = OS default; treat as pass.',
    'high',
    'tls10_server_disabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-8', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SC-8, SC-13 — TLS 1.1 disabled (client + server)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc13_tls11_client_disabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TLS 1.1 disabled for Schannel client',
    'NIST SC-8 / SC-13. TLS 1.1 is deprecated (NIST SP 800-52 Rev 2). Schannel client subkey: HKLM\...\SCHANNEL\Protocols\TLS 1.1\Client\Enabled = 0. Unknown = OS default; treat as pass.',
    'high',
    'tls11_client_disabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-8', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc13_tls11_server_disabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TLS 1.1 disabled for Schannel server',
    'NIST SC-8 / SC-13. TLS 1.1 is deprecated (NIST SP 800-52 Rev 2). Schannel server subkey: HKLM\...\SCHANNEL\Protocols\TLS 1.1\Server\Enabled = 0. Unknown = OS default; treat as pass.',
    'high',
    'tls11_server_disabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-8', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SC-8, SC-13 — TLS 1.2 enabled (client + server)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc13_tls12_client_enabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TLS 1.2 enabled for Schannel client',
    'NIST SC-8 / SC-13. TLS 1.2 is the minimum acceptable protocol per NIST SP 800-52 Rev 2. Schannel client: Enabled=1 and DisabledByDefault!=1. Key absent = OS default (enabled); treat as pass.',
    'high',
    'tls12_client_enabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-8', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc13_tls12_server_enabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TLS 1.2 enabled for Schannel server',
    'NIST SC-8 / SC-13. TLS 1.2 minimum per NIST SP 800-52 Rev 2. Schannel server: Enabled=1 and DisabledByDefault!=1. Key absent = OS default (enabled); treat as pass.',
    'high',
    'tls12_server_enabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-8', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SC-28, SC-13 — BitLocker 256-bit cipher strength
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc28_bitlocker_cipher_256bit',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'BitLocker OS drive uses 256-bit encryption (AES-256-CBC or XTS-AES-256)',
    'NIST SC-28 / SC-13. NIST recommends AES-256 or XTS-AES-256 for full-disk encryption (EncryptionMethod 4 or 7 from Win32_EncryptableVolume). "No" when BitLocker is off or uses 128-bit cipher.',
    'high',
    'bitlocker_cipher_256bit', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-28', 'SC-13'], ARRAY['A.10.1.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SI-7 — Secure Boot + TPM
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_si7_secure_boot_enabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Secure Boot enabled (UEFI)',
    'NIST SI-7. UEFI Secure Boot validates boot-loader and OS-loader signatures, protecting the pre-OS environment against rootkits and bootkits. Registry: HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled = 1.',
    'high',
    'secure_boot_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-7'], ARRAY['A.14.2.6'], ARRAY['secure-configuration']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_si7_tpm_ready',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'TPM enabled and activated',
    'NIST SI-7. A functional TPM underpins BitLocker key sealing, Secure Boot attestation, and Windows Hello. Checks Win32_Tpm.IsEnabled_InitialValue and IsActivated_InitialValue via WMI root\CIMV2\Security\MicrosoftTpm.',
    'high',
    'tpm_ready', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-7'], ARRAY['A.14.2.6'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SC-39, SI-16, SC-41 — VBS, HVCI, Kernel DMA Protection
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc39_vbs_enabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Virtualization-Based Security (VBS) running',
    'NIST SC-39. VBS uses the hypervisor to create an isolated secure region of memory, protecting Credential Guard, HVCI, and other security features from kernel-level compromise. Win32_DeviceGuard.VirtualizationBasedSecurityStatus = 2 (running).',
    'high',
    'vbs_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-39'], ARRAY['A.14.2.6'], ARRAY['secure-configuration']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_si16_hvci_enabled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Hypervisor-Protected Code Integrity (HVCI) enabled',
    'NIST SI-16. HVCI (Memory Integrity) uses VBS to validate kernel code integrity at runtime, blocking unsigned kernel drivers and memory exploits. Win32_DeviceGuard.HypervisorEnforcedCodeIntegrityStatus >= 1.',
    'high',
    'hvci_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-16'], ARRAY['A.14.2.6'], ARRAY['secure-configuration']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_sc41_kernel_dma_protection',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Kernel DMA Protection enabled',
    'NIST SC-41. Kernel DMA Protection (Memory Access Protection) uses IOMMU to block malicious DMA attacks from hot-pluggable PCIe devices. Win32_DeviceGuard.KernelDmaProtectionStatus = 1. Cannot be disabled once on without BIOS reset.',
    'medium',
    'kernel_dma_protection', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SC-41'], ARRAY['A.14.2.6'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SI-16 — Mandatory ASLR (ForceRelocateImages)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_si16_mandatory_aslr',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Mandatory ASLR (ForceRelocateImages) enabled system-wide',
    'NIST SI-16. Mandatory ASLR forces address-space randomization for all images, including those that do not opt in via the /DYNAMICBASE linker flag. Controlled via Windows Exploit Protection (MoveImages registry DWORD non-zero). Unknown = not explicitly configured; treat as pass since Win11 has ASLR on by default.',
    'medium',
    'mandatory_aslr_enabled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-16'], ARRAY['A.12.6.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- AC-2, IA-5 — LAPS enrolled
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_ac2_laps_enrolled',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Windows LAPS configured for local administrator password management',
    'NIST AC-2 / IA-5. Windows LAPS rotates the local administrator password automatically, preventing lateral movement via shared credentials. Checks modern LAPS (BackupDirectory ≥ 1) and legacy LAPS (AdmPwdEnabled = 1). Unknown / absent = LAPS managed externally; treat as pass.',
    'high',
    'laps_enrolled', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-2', 'IA-5'], ARRAY['A.9.2.6'], ARRAY['access-control']
);

-- ============================================================================
-- AU-11 — Security event log maximum size
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_au11_security_log_max_size',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Security event log maximum size ≥ 192 MB',
    'NIST AU-11. A sufficiently large security log retains enough audit events to support incident investigation. 192 MB (196608 KB) matches the CIS L1 minimum. Reads GPO policy key (KB) or system key (bytes ÷ 1024).',
    'medium',
    'security_log_max_size_kb', 'gte', ARRAY['196608'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-11'], ARRAY['A.12.4.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- SI-3 — Defender definition age + ASR rules
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_si3_defender_definition_age',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'Defender antivirus signatures updated within the last 24 hours',
    'NIST SI-3. Stale antivirus signatures expose the endpoint to recently-discovered malware. Reads MSFT_MpComputerStatus.AntivirusSignatureAge (days) via WMI root\Microsoft\Windows\Defender. Age > 1 day = fail.',
    'high',
    'defender_definition_age_days', 'lte', ARRAY['1'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_si3_asr_ransomware',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'ASR rule: ransomware protection enabled (block mode)',
    'NIST SI-3. ASR rule c1db55ab-c21a-4637-bb3f-a12568109d35 — Use advanced protection against ransomware. Must be in block mode (value "1"). Reads from GPO path first, then Defender config registry.',
    'high',
    'asr_ransomware_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
);
--
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'nist_win_cm7_asr_psexec_wmi_block',
    'NIST SP 800-53 Rev 5', 'Rev 5 (2020)',
    'ASR rule: block process creation from PSExec and WMI (block mode)',
    'NIST CM-7. ASR rule d1e49aac-8f56-4280-b9ba-993a6d77406c — Block process creations originating from PSExec and WMI commands. Blocks a common lateral-movement technique. Must be in block mode (value "1").',
    'high',
    'asr_psexec_wmi_block_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['CM-7'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0041_windows_nist_l1_expansion');

COMMIT;
