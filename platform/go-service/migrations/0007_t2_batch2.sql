-- patched.im — 0007_t2_batch2.sql
-- ADR-0001 action item 5, batch 2: 8 T2 compliance rules.
--
-- Three groups (8 rules total, all T2):
--
--   §2.3 — Sharing cluster (4 rules)
--     launchctl/cupsctl/mdmclient checks. Zero existing-signal reuse.
--     Collector must be on v0.5.0 for non-null values.
--
--   §4   — Network services (2 rules)
--     launchctl checks for httpd and nfsd. Same collector version.
--
--   §5   — Access control (2 rules)
--     amfi_enabled (nvram boot-args) and root_disabled (dscl UserShell).
--
-- mSCP severity gaps: amfi_enabled has no severity in mSCP sonoma_rev5.
-- Defaulting to 'medium' per CIS_L1_GAP.md §severity-gaps note. Revisit
-- against the official CIS benchmark PDF before enabling for customers.
--
-- pii_observed: all batch 2 signals are system-configuration metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0007_t2_batch2.sql
-- Note: 0005_tenant_rules.sql must have been applied first.

BEGIN;

-- ============================================================================
-- §2.3 — Sharing cluster
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_3_3_2_smbd_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable SMB File Sharing',
    'CIS §2.3.3.2. The SMB file sharing daemon (com.apple.smbd) must not be running. Detected via launchctl print-disabled: "=> false" means the service is enabled (fail). Absent or "=> true" means disabled (pass).',
    'medium',
    'smbd_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_3_3_3_printer_sharing_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Printer Sharing',
    'CIS §2.3.3.3. Printer sharing must be disabled. Detected via cupsctl: _share_printers=0 means sharing is off (pass). If cupsctl returns _share_printers=1, sharing is enabled (fail).',
    'medium',
    'printer_sharing_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_3_3_5_remote_management_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Remote Management (Apple Remote Desktop)',
    'CIS §2.3.3.5. Apple Remote Desktop / Remote Management must be disabled. Detected via mdmclient QuerySecurityInfo: RemoteDesktopEnabled = 0 means off (pass). Defaults to pass (disabled) if mdmclient returns no output.',
    'medium',
    'remote_management_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7', 'AC-17'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_3_3_7_internet_sharing_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Internet Sharing',
    'CIS §2.3.3.7. Internet Sharing must be disabled. Detected via launchctl print-disabled: com.apple.InternetSharing "=> false" means the service is enabled (fail).',
    'medium',
    'internet_sharing_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §4 — Network services
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_4_2_httpd_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Built-in Web Server (Apache httpd)',
    'CIS §4.2. The built-in Apache web server (org.apache.httpd) must not be running. Detected via launchctl print-disabled: "=> false" means enabled (fail).',
    'medium',
    'httpd_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),
(
    'cis_macos_4_3_nfsd_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Network File System Service (NFS)',
    'CIS §4.3. The NFS server daemon (com.apple.nfsd) must not be running. Detected via launchctl print-disabled: "=> false" means enabled (fail).',
    'medium',
    'nfsd_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §5 — Access control
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_5_1_3_amfi_enabled',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Apple Mobile File Integrity (AMFI)',
    'CIS §5.1.3. AMFI must not be disabled via NVRAM boot-args. Collector checks nvram -p for amfi_get_out_of_my_way=1; if found, AMFI is disabled (fail). Severity defaulted to medium — mSCP sonoma_rev5 has no severity for this control.',
    'medium', -- mSCP severity gap; default medium per CIS_L1_GAP.md
    'amfi_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['SI-7'], ARRAY['A.8.7'], ARRAY['malware-protection']
),
(
    'cis_macos_5_6_root_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Root Login',
    'CIS §5.6. The root account shell must be /usr/bin/false, preventing interactive login. Collector reads dscl . -read /Users/root UserShell; any shell other than /usr/bin/false is a fail. Defaults to pass (disabled) if the root record is absent.',
    'medium',
    'root_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AC-6'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0007_t2_batch2');

COMMIT;
