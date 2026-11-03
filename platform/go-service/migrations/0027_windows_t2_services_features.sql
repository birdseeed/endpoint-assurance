-- patched.im — 0027_windows_t2_services_features.sql
-- PAT-405 (parity epic PAT-404, ADR-0007): Windows CIS L1 T2 — batch 4.
--
-- CIS Microsoft Windows 11 Benchmark v2.0.0, §18 Administrative Templates —
-- services & features hardening. The Windows analog of the macOS §2.3 sharing /
-- §4 network-services T2 controls (disable unwanted services). 6 rules, all T2,
-- platform='windows'.
--
-- COLLECTOR CONTRACT (defined here; implemented in PAT-427): the collector
-- (ComplianceCollector.AddServicesFeatures + Patched.Shared.Compliance.
-- ServicesFeaturesParser) reads the registry and ALWAYS emits 'Yes'/'No' per
-- control (per-control absent-semantics are encoded in the parser — e.g. an
-- absent SMBv1 driver means SMBv1 is not installed = compliant = 'Yes', while an
-- absent LLMNR policy means the insecure default applies = 'No'). Every rule is
-- therefore a simple `eq 'Yes'`.
--
--   signal_key                          registry (HKLM)                         absent→
--   smbv1_disabled                      ...\Services\mrxsmb10\Start ==4          Yes
--   llmnr_disabled                      ...\DNSClient\EnableMulticast ==0        No
--   autoplay_disabled                   ...\Explorer\NoDriveTypeAutoRun ==255    No
--   always_install_elevated_disabled    ...\Installer\AlwaysInstallElevated !=1  Yes
--   remote_assistance_disabled          ...\Terminal Services\fAllowToGetHelp ==0 No
--   wdigest_cleartext_disabled          ...\WDigest\UseLogonCredential !=1        Yes
--
-- §18 sub-section decimals are best-effort against CIS Win11 v2.0.0; reconcile
-- against the benchmark PDF before customer enablement (the authoritative
-- identity of each control is its registry value, given above).
--
-- pii_observed: policy/feature configuration metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0027_windows_t2_services_features.sql
-- Note: 0019_windows_cis_l1_rules.sql must have been applied first (platform column).

BEGIN;

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES

-- §18.4.x — Disable SMBv1 client driver
(
    'cis_win_18_4_3_smbv1_client_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Disable the SMBv1 client driver',
    'CIS §18.4 (MS Security Guide). The SMBv1 client driver (mrxsmb10) must be Disabled (Start=4) or not installed. SMBv1 is unauthenticated and was the vector for WannaCry/NotPetya; modern Windows works entirely over SMBv2/3.',
    'high',
    'smbv1_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['CM-7','SC-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),

-- §18.6.x — Turn off multicast name resolution (LLMNR)
(
    'cis_win_18_6_4_1_llmnr_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Turn off multicast name resolution (LLMNR)',
    'CIS §18.6.4.1. EnableMulticast must be 0. LLMNR is routinely abused (Responder) to capture NetNTLM hashes on a LAN; it has no role in a properly DNS-served network.',
    'high',
    'llmnr_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['CM-7','SC-20'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),

-- §18.9.8.x — Turn off Autoplay
(
    'cis_win_18_9_8_2_autoplay_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Turn off Autoplay on all drives',
    'CIS §18.9.8.2. NoDriveTypeAutoRun must be 255 (0xFF) so Autoplay is disabled on all drive types — a long-standing vector for USB-borne malware auto-execution.',
    'medium',
    'autoplay_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['CM-7','SI-3'], ARRAY['A.8.7'], ARRAY['malware-protection']
),

-- §18.9.x — Windows Installer: Always install with elevated privileges = Disabled
(
    'cis_win_18_9_85_1_always_install_elevated_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Disable "Always install with elevated privileges"',
    'CIS §18.9 (Windows Installer). AlwaysInstallElevated must not be 1. When enabled, any user can run an MSI as SYSTEM — a trivial local privilege-escalation primitive.',
    'high',
    'always_install_elevated_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-6','CM-7'], ARRAY['A.8.2'], ARRAY['user-access-control']
),

-- §18.8.x — Configure Solicited Remote Assistance = Disabled
(
    'cis_win_18_8_36_1_remote_assistance_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Disable Solicited Remote Assistance',
    'CIS §18.8 (Remote Assistance). fAllowToGetHelp must be 0. Solicited Remote Assistance lets a remote helper take control of the session; on managed endpoints it is an unnecessary remote-access surface.',
    'medium',
    'remote_assistance_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-17','CM-7'], ARRAY['A.6.7'], ARRAY['secure-configuration']
),

-- §18.3.x — MS Security Guide: WDigest Authentication = Disabled
(
    'cis_win_18_3_7_wdigest_cleartext_disabled',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Disable WDigest cleartext credential caching',
    'CIS §18.3 (MS Security Guide). UseLogonCredential must not be 1. When enabled, WDigest caches plaintext credentials in LSASS, which Mimikatz-class tools harvest directly.',
    'high',
    'wdigest_cleartext_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','SC-28'], ARRAY['A.8.24'], ARRAY['secure-configuration']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0027_windows_t2_services_features');

COMMIT;
