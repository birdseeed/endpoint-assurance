-- patched.im — 0019_windows_cis_l1_rules.sql
-- PAT-337: seed server-side CIS Windows 11 L1 rule pack.
--
-- Two steps:
--   1. Add `platform` column to compliance_rules (NULL default → backfill to 'macos').
--   2. Insert 13 T1 Windows rules keyed to the signals emitted by
--      ComplianceCollector.cs (patched-agent-win v0.2.0).
--
-- Evaluator behaviour: the Go extractor passes `platform` from the raw payload
-- into its rule-load query. Rules with `platform = 'windows'` are only loaded
-- for Windows payloads; 'macos' rules for macOS payloads.
--
-- CIS reference: CIS Microsoft Windows 11 Benchmark v2.0.0 (L1 controls).
-- NIST = SP 800-53 r5. ISO = 27001:2022 Annex A. CE = Cyber Essentials.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0019_windows_cis_l1_rules.sql

BEGIN;

-- ============================================================================
-- STEP 1: Add platform column, backfill existing rules as 'macos'
-- ============================================================================

-- platform column was added by 0009_windows_schema_compat.sql; guard is
-- needed so this migration is idempotent when applied from scratch.
ALTER TABLE compliance_rules
    ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'macos'
        CHECK (platform IN ('macos', 'windows', 'cross-platform'));

COMMENT ON COLUMN compliance_rules.platform IS
    'Target OS platform for this rule. Evaluator only loads rules matching the payload platform.';

-- All 52 existing rows were macOS-only; default covers them. Explicit UPDATE
-- for auditability.
UPDATE compliance_rules SET platform = 'macos';

-- Drop the column default — platform must be specified on all future INSERTs.
ALTER TABLE compliance_rules ALTER COLUMN platform DROP DEFAULT;

-- ============================================================================
-- STEP 2: Seed CIS Windows 11 L1 rule pack (13 T1 rules)
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

-- §18.10.11 — BitLocker Drive Encryption
(
    'cis_win_18_10_11_bitlocker_os_drive',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable BitLocker on the OS drive',
    'BitLocker full-disk encryption protects data at rest if the device is lost or stolen. ProtectionStatus=1 (On) via WMI Win32_EncryptableVolume for C:.',
    'critical',
    'bitlocker_os_drive', 'eq', ARRAY['On'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SC-28','SC-28(1)'], ARRAY['A.8.24','A.10.1.1'], ARRAY['secure-configuration']
),

-- §9.1.1 — Domain profile firewall
(
    'cis_win_9_1_1_firewall_domain',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Windows Defender Firewall: Domain profile',
    'CIS §9.1.1. Domain profile must be active. Disabling any firewall profile removes host-based inbound filtering for that network context.',
    'high',
    'windows_firewall_domain', 'eq', ARRAY['enabled'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SC-7'], ARRAY['A.13.1.1'], ARRAY['firewalls']
),

-- §9.2.1 — Private profile firewall
(
    'cis_win_9_2_1_firewall_private',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Windows Defender Firewall: Private profile',
    'CIS §9.2.1. Private profile must be active. Protects the device on home/office networks outside the domain context.',
    'high',
    'windows_firewall_private', 'eq', ARRAY['enabled'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SC-7'], ARRAY['A.13.1.1'], ARRAY['firewalls']
),

-- §9.3.1 — Public profile firewall
(
    'cis_win_9_3_1_firewall_public',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Windows Defender Firewall: Public profile',
    'CIS §9.3.1. Public profile must be active. Most critical — devices on hotel/café networks rely on the public profile for inbound filtering.',
    'high',
    'windows_firewall_public', 'eq', ARRAY['enabled'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SC-7'], ARRAY['A.13.1.1'], ARRAY['firewalls']
),

-- §18.9.45 — Microsoft Defender Antivirus real-time protection
(
    'cis_win_18_9_45_defender_realtime',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Microsoft Defender real-time protection',
    'CIS §18.9.45. DisableRealtimeMonitoring must not be set. Real-time scanning is the primary host-based anti-malware control; disabling it leaves the device unprotected against commodity threats.',
    'critical',
    'defender_realtime', 'eq', ARRAY['enabled'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SI-3','SI-3(1)'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
),

-- §2.3.17.1 — User Account Control (UAC)
(
    'cis_win_2_3_17_1_uac_enabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable User Account Control (UAC)',
    'CIS §2.3.17.1. EnableLUA must be 1. UAC is the primary privilege-separation mechanism on Windows; disabling it allows any process running as standard user to perform privileged operations silently.',
    'high',
    'uac_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['AC-6','CM-7'], ARRAY['A.9.4.4'], ARRAY['user-access-control']
),

-- §18.9.102 — Automatic updates
(
    'cis_win_18_9_102_auto_updates',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable automatic Windows updates',
    'CIS §18.9.102. NoAutoUpdate GPO must be absent or 0; AU options ≥ 3. Unpatched Windows devices are the primary vector for ransomware lateral movement in SME estates.',
    'high',
    'auto_updates_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['security-update-management']
),

-- §18.10.56.2.2 — Remote Desktop disabled
(
    'cis_win_18_10_56_2_rdp_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Disable Remote Desktop (RDP)',
    'CIS §18.10.56.2.2. fDenyTSConnections should be 1 (RDP disabled) on managed endpoints. RDP brute-forcing is a leading initial-access vector; disable unless a specific business need exists.',
    'medium',
    'remote_desktop_enabled', 'eq', ARRAY['disabled'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['AC-17','CM-7'], ARRAY['A.9.1.2'], ARRAY['secure-configuration']
),

-- §2.3.8.1 — SMB client signing required
(
    'cis_win_2_3_8_1_smb_signing',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Require SMB client packet signing',
    'CIS §2.3.8.1. RequireSecuritySignature for LanmanWorkstation must be 1. Without signing, SMB relay attacks (NTLM relay) allow credential theft on any shared LAN or VPN.',
    'medium',
    'smb_signing_required', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['SC-8','SC-8(1)'], ARRAY['A.13.2.1'], ARRAY['secure-configuration']
),

-- §19.1.3.2 — Screensaver enabled
(
    'cis_win_19_1_3_2_screensaver_enabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable screen saver',
    'CIS §19.1.3.2. ScreenSaveActive policy must be 1. Prerequisite for screensaver timeout and password controls; a disabled screensaver means the device never locks on inactivity.',
    'medium',
    'screensaver_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['AC-11'], ARRAY['A.11.2.8'], NULL
),

-- §19.1.3.3 — Screensaver password required
(
    'cis_win_19_1_3_3_screensaver_password',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Require password to unlock from screen saver',
    'CIS §19.1.3.3. ScreenSaverIsSecure policy must be 1. Stops casual physical-access leaks when the device is left unattended in a shared space.',
    'medium',
    'screensaver_password_required', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['AC-11'], ARRAY['A.11.2.8'], NULL
),

-- §19.1.3.4 — Screensaver timeout ≤ 900s
(
    'cis_win_19_1_3_4_screensaver_timeout',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Screen saver timeout ≤ 900 seconds (15 minutes)',
    'CIS §19.1.3.4. ScreenSaveTimeOut policy must be ≤ 900. A 15-minute cap balances usability against unattended-access risk; longer timeouts are common misconfigurations in SME deployments.',
    'medium',
    'screensaver_timeout_seconds', 'lte', ARRAY['900'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    ARRAY['AC-11'], ARRAY['A.11.2.8'], NULL
),

-- Patched baseline — MDM enrolment
(
    'patched_win_mdm_enrolled',
    'patched.im baseline', 'v1',
    'Device is MDM-enrolled (Windows)',
    'HKLM\SOFTWARE\Microsoft\Enrollments must contain at least one subkey. MDM enrolment is the prerequisite for all policy push (BitLocker, firewall, UAC, updates). Not a CIS control but flagged on all auditor questionnaires.',
    'medium',
    'mdm_enrolled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T1', 'none', false,
    'windows',
    NULL, NULL, NULL
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0019_windows_cis_l1_rules');

COMMIT;
