-- patched.im — 0028_windows_t2_defender_policy.sql
-- PAT-405 (parity epic PAT-404, ADR-0007): Windows CIS L1 T2 — batch 5 (final).
--
-- CIS Microsoft Windows 11 Benchmark v2.0.0, §18.9.47 Microsoft Defender
-- Antivirus policy detail. The Windows analog of the macOS §1 software-update
-- detail + XProtect/Gatekeeper data-update T2 controls (the "keep the built-in
-- protection fully switched on" group). 6 rules, all T2, platform='windows'.
--
-- This batch brings Windows to 52 rules — parity with the macOS set.
--
-- COLLECTOR CONTRACT (defined here; implemented in PAT-428): the collector
-- (ComplianceCollector.AddDefenderPolicy + Patched.Shared.Compliance.
-- DefenderPolicyParser) reads HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
-- and ALWAYS emits 'Yes'/'No' per control. Per-control absent-semantics: where
-- the secure state is the on-by-default behaviour (behavior monitoring, archive
-- scanning) absent → 'Yes'; where the control must be explicitly enforced
-- (cloud/MAPS, sample submission, PUA, removable-drive scanning) absent → 'No'
-- (a compliance baseline treats "not enforced by policy" as non-compliant).
-- Every rule is therefore a simple `eq 'Yes'`.
--
--   signal_key                       value (Windows Defender policy)        absent→
--   defender_cloud_protection        Spynet\SpynetReporting != 0            No
--   defender_sample_submission       Spynet\SubmitSamplesConsent in {1,3}  No
--   defender_pua_protection          PUAProtection == 1                    No
--   defender_behavior_monitoring     Real-Time Protection\DisableBehaviorMonitoring == 0  Yes
--   defender_scan_removable_drives   Scan\DisableRemovableDriveScanning == 0             No
--   defender_archive_scanning        Scan\DisableArchiveScanning == 0                    Yes
--
-- §18.9.47 sub-section decimals are best-effort against CIS Win11 v2.0.0;
-- reconcile against the benchmark PDF before customer enablement (authoritative
-- identity = the registry value, given above).
--
-- pii_observed: AV policy configuration metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0028_windows_t2_defender_policy.sql
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

-- §18.9.47 — Cloud-delivered protection (MAPS)
(
    'cis_win_18_9_47_4_1_defender_cloud_protection',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Microsoft Defender cloud-delivered protection',
    'CIS §18.9.47 (MAPS). SpynetReporting must be enabled (1 Basic / 2 Advanced). Cloud-delivered protection gives near-real-time detection of new threats that local signatures have not yet caught.',
    'high',
    'defender_cloud_protection', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3','SI-3(1)'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
),

-- §18.9.47 — Send file samples (safe samples)
(
    'cis_win_18_9_47_4_2_defender_sample_submission',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Send safe file samples to Microsoft Defender cloud',
    'CIS §18.9.47. SubmitSamplesConsent must send samples automatically (1 = send safe samples, 3 = send all) so cloud protection can analyse novel files. Never-send (2) and prompt (0) defeat cloud-delivered protection.',
    'medium',
    'defender_sample_submission', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
),

-- §18.9.47 — Potentially Unwanted Application protection
(
    'cis_win_18_9_47_8_defender_pua_protection',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Defender Potentially Unwanted Application (PUA) protection',
    'CIS §18.9.47. PUAProtection must be 1 (block). PUA protection stops adware, bundleware, and coin-miners that fall outside classic malware definitions but degrade and endanger endpoints.',
    'medium',
    'defender_pua_protection', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
),

-- §18.9.47 — Behavior monitoring
(
    'cis_win_18_9_47_9_defender_behavior_monitoring',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable Defender behavior monitoring',
    'CIS §18.9.47. DisableBehaviorMonitoring must not be set. Behavior monitoring catches fileless and living-off-the-land attacks that signature scanning alone misses.',
    'high',
    'defender_behavior_monitoring', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3','SI-4'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
),

-- §18.9.47 — Scan removable drives
(
    'cis_win_18_9_47_12_defender_scan_removable_drives',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Scan removable drives during full scans',
    'CIS §18.9.47. DisableRemovableDriveScanning must not be set, so USB sticks and external drives — a common malware-delivery vector — are scanned.',
    'medium',
    'defender_scan_removable_drives', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3'], ARRAY['A.8.7'], ARRAY['malware-protection']
),

-- §18.9.47 — Scan archive files
(
    'cis_win_18_9_47_11_defender_archive_scanning',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Scan archive files',
    'CIS §18.9.47. DisableArchiveScanning must not be set, so malware nested inside .zip/.rar/.7z archives is detected rather than waved through.',
    'medium',
    'defender_archive_scanning', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['SI-3'], ARRAY['A.12.2.1'], ARRAY['malware-protection']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0028_windows_t2_defender_policy');

COMMIT;
