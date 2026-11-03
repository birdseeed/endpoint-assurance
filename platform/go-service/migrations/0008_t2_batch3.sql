-- patched.im — 0008_t2_batch3.sql
-- ADR-0001 action item 5, batch 3: 17 T2 compliance rules.
--
-- Five groups (17 rules total, all T2):
--
--   §2.10 — Screensaver (1 rule)
--     Reuses existing screensaver_delay_seconds signal (now emits null when
--     the plist is absent, so treat_unknown_as='fail' applies correctly).
--     Collector must be on v0.6.0 for the null-sentinel fix.
--
--   §2.9  — Power management (2 rules)
--     pmset -g custom checks for powernap and womp.
--     Collector must be on v0.6.0 for non-null values.
--
--   §3.5  — Audit record permissions (12 rules)
--     Three sub-groups: audit_control file (4), log folder (4), log files (4).
--     All check ACL absent, owned by root, group wheel, mode restriction.
--     Absent audit_control → null signal → treat_unknown_as='fail'.
--     Collector must be on v0.6.0 for non-null values.
--
--   §5.4/5.5 — Sudo (2 rules)
--     sudo -V timeout (lte 0 minutes) and timestamp type (eq 'tty').
--     Absent sudo -V output → null signal → treat_unknown_as='fail'.
--     Collector must be on v0.6.0 for non-null values.
--
-- pii_observed: all batch 3 signals are system-configuration metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0008_t2_batch3.sql
-- Note: 0007_t2_batch2.sql must have been applied first.

BEGIN;

-- ============================================================================
-- §2.10 — Screensaver timeout
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
    'cis_macos_2_10_1_screensaver_timeout',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Screen Saver Activates Within 20 Minutes',
    'CIS §2.10.1. The screen saver must engage after at most 1200 seconds (20 minutes) of inactivity. Collector reads askForPasswordDelay from the ByHost com.apple.screensaver plist. Absent key (plist never customised) emits null — treat_unknown_as=''fail'' applies.',
    'medium',
    'screensaver_delay_seconds', 'lte', ARRAY['1200'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AC-11'], ARRAY['A.8.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.9 — Power management
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
    'cis_macos_2_9_2_power_nap_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Power Nap',
    'CIS §2.9.2. Power Nap allows the Mac to receive network updates while asleep, expanding the attack surface. Collector sums powernap across all pmset profiles; sum of 0 means disabled (pass).',
    'low',
    'power_nap_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_9_3_wake_on_network_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Wake for Network Access',
    'CIS §2.9.3. Wake for network access (womp) allows the Mac to be woken remotely, expanding the attack surface. Collector sums womp across all pmset profiles; sum of 0 means disabled (pass).',
    'low',
    'wake_on_network_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §3.5 — Audit control file permissions
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
    'cis_macos_3_5_audit_control_no_acl',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure /etc/security/audit_control Has No ACL',
    'CIS §3.5. /etc/security/audit_control must not have an ACL. Collector checks ls -le output for ACL entries (indented lines starting with a digit).',
    'medium',
    'audit_control_no_acl', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_control_owner',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure /etc/security/audit_control Is Owned by Root',
    'CIS §3.5. /etc/security/audit_control must be owned by uid 0 (root). Collector uses stat -f %u.',
    'medium',
    'audit_control_owner', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_control_group',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure /etc/security/audit_control Is Group-Owned by Wheel',
    'CIS §3.5. /etc/security/audit_control must be group-owned by gid 0 (wheel). Collector uses stat -f %g.',
    'medium',
    'audit_control_group', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_control_mode',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure /etc/security/audit_control Has Mode 440 or More Restrictive',
    'CIS §3.5. /etc/security/audit_control must have octal permissions of 440 or more restrictive (no write or execute bits). Collector uses stat -f %A (octal as decimal string; ordering is preserved for 000-777 range).',
    'medium',
    'audit_control_mode', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §3.5 — Audit log folder permissions
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
    'cis_macos_3_5_audit_folder_no_acl',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Folder Has No ACL',
    'CIS §3.5. The audit log directory (from audit_control dir: line) must not have an ACL. Collector uses ls -led.',
    'medium',
    'audit_folder_no_acl', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_folder_owner',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Folder Is Owned by Root',
    'CIS §3.5. The audit log directory must be owned by uid 0 (root). Collector uses stat -f %u.',
    'medium',
    'audit_folder_owner', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_folder_group',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Folder Is Group-Owned by Wheel',
    'CIS §3.5. The audit log directory must be group-owned by gid 0 (wheel). Collector uses stat -f %g.',
    'medium',
    'audit_folder_group', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_folder_mode',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Folder Has Mode 700 or More Restrictive',
    'CIS §3.5. The audit log directory must have octal permissions of 700 or more restrictive. Collector uses stat -f %A.',
    'medium',
    'audit_folder_mode', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §3.5 — Audit log file permissions
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
    'cis_macos_3_5_audit_logs_no_acl',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Files Have No ACL',
    'CIS §3.5. No audit log file in the audit directory may have an ACL. Collector checks ls -le output of the audit directory for ACL entries.',
    'medium',
    'audit_logs_no_acl', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_logs_owner',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Files Are Owned by Root',
    'CIS §3.5. All audit log files must be owned by root. Collector uses find -maxdepth 1 -type f ! -user root.',
    'medium',
    'audit_logs_owner', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_logs_group',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Files Are Group-Owned by Wheel',
    'CIS §3.5. All audit log files must be group-owned by wheel. Collector uses find -maxdepth 1 -type f ! -group wheel.',
    'medium',
    'audit_logs_group', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),
(
    'cis_macos_3_5_audit_logs_mode',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Audit Log Files Have Mode 440 or More Restrictive',
    'CIS §3.5. All audit log files must have octal permissions of 440 or more restrictive. Collector uses find -perm /0337 (mask: owner-write, owner-exec, group-write, group-exec, all-other bits).',
    'medium',
    'audit_logs_mode', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AU-9'], ARRAY['A.8.15'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §5.4/5.5 — sudo configuration
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
    'cis_macos_5_4_sudo_timeout',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure sudo Timeout Is Set to Zero',
    'CIS §5.4. sudo must be configured with a timestamp timeout of 0 minutes, requiring re-authentication for every sudo invocation. Collector reads Authentication timestamp timeout from sudo -V output.',
    'medium',
    'sudo_timeout_minutes', 'lte', ARRAY['0'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AC-6'], ARRAY['A.8.5'], ARRAY['access-control']
),
(
    'cis_macos_5_5_sudo_timestamp_type',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure sudo Uses Per-TTY Timestamps',
    'CIS §5.5. sudo must use per-TTY timestamp records (tty type) to prevent credential re-use across terminal sessions. Collector reads Type of authentication timestamp record from sudo -V output.',
    'medium',
    'sudo_timestamp_type', 'eq', ARRAY['tty'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AC-6'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0008_t2_batch3');

COMMIT;
