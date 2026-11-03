-- patched.im — 0006_t2_batch1.sql
-- ADR-0001 action item 5, batch 1: first 10 T2 compliance rules.
--
-- Two groups (10 rules total, all T2):
--
--   §5.2 — Password policy (5 rules)
--     Parsed from existing password_policy_raw; zero new shell cost.
--     Collector must be on v0.4.0 (schema_version 3) to emit these signals;
--     pre-upgrade devices will emit null → treat_unknown_as = 'fail'.
--
--   §1   — Software update enforcement (5 rules)
--     New signals from updates.sh (com.apple.SoftwareUpdate prefs).
--     Same note: v0.4.0 collector required for non-null values.
--
-- mSCP severity gaps: mSCP sonoma_rev5 marks no severity for the §1 controls.
-- Defaulting to 'medium' per CIS_L1_GAP.md §severity-gaps note. Revisit
-- against the official CIS benchmark PDF before enabling for customers.
--
-- pii_observed: all batch 1 signals are system policy metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0006_t2_batch1.sql
-- Note: 0005_tenant_rules.sql must have been applied first.

BEGIN;

-- ============================================================================
-- §5.2 — Password policy (parsed from password_policy_raw)
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
    'cis_macos_5_2_1a_lockout_threshold',
    'CIS Apple macOS', 'v2.1.0',
    'Limit failed login attempts (lockout threshold ≤ 5)',
    'CIS §5.2.1. The account must lock after no more than 5 consecutive failed authentication attempts. Signal is parsed from password_policy_raw XML; null signal means no MDM policy is configured (fail).',
    'medium',
    'pwpolicy_lockout_threshold', 'lte', ARRAY['5'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AC-7'], ARRAY['A.9.4.2'], ARRAY['secure-configuration']
),
(
    'cis_macos_5_2_1b_lockout_reset_minutes',
    'CIS Apple macOS', 'v2.1.0',
    'Set account lockout observation window (≥ 15 minutes)',
    'CIS §5.2.1. After the lockout threshold is reached the observation window must be at least 15 minutes (autoEnableInSeconds ÷ 60). Signal is parsed from password_policy_raw XML.',
    'medium',
    'pwpolicy_lockout_reset_minutes', 'gte', ARRAY['15'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['AC-7'], ARRAY['A.9.4.2'], ARRAY['secure-configuration']
),
(
    'cis_macos_5_2_2_min_length',
    'CIS Apple macOS', 'v2.1.0',
    'Require minimum password length of 15 characters',
    'CIS §5.2.2. The password policy must require at least 15 characters (policyAttributeMinimumLength). Signal is parsed from password_policy_raw XML.',
    'medium',
    'pwpolicy_min_length', 'gte', ARRAY['15'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['IA-5'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),
(
    'cis_macos_5_2_7_max_age_days',
    'CIS Apple macOS', 'v2.1.0',
    'Restrict maximum password lifetime to 365 days',
    'CIS §5.2.7. Passwords must expire after no more than 365 days (policyAttributeExpiresEveryNDays). Aligns with NIST SP-800-63b. Signal is parsed from password_policy_raw XML.',
    'medium',
    'pwpolicy_max_age_days', 'lte', ARRAY['365'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['IA-5'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),
(
    'cis_macos_5_2_8_history_depth',
    'CIS Apple macOS', 'v2.1.0',
    'Prohibit password reuse (history ≥ 15 generations)',
    'CIS §5.2.8. The password policy must remember at least the last 15 passwords (policyAttributePasswordHistoryDepth). Signal is parsed from password_policy_raw XML.',
    'medium',
    'pwpolicy_history_depth', 'gte', ARRAY['15'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['IA-5'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §1 — Software update enforcement (com.apple.SoftwareUpdate prefs)
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
    'cis_macos_1_2_update_check_auto',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce automatic check for software updates',
    'CIS §1.2. macOS must be configured to automatically check for software updates (AutomaticCheckEnabled). Severity defaulted to medium — mSCP sonoma_rev5 has no severity for this control; revisit against CIS benchmark PDF before enabling for customers.',
    'medium', -- mSCP severity gap; default medium per CIS_L1_GAP.md
    'update_check_auto', 'eq', ARRAY['On'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['patch-management']
),
(
    'cis_macos_1_3_update_download_auto',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce automatic download of software updates',
    'CIS §1.3. macOS must automatically download available software updates (AutomaticDownload). Severity defaulted to medium.',
    'medium', -- mSCP severity gap
    'update_download_auto', 'eq', ARRAY['On'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['patch-management']
),
(
    'cis_macos_1_5_app_updates_auto',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce automatic installation of App Store updates',
    'CIS §1.5. macOS must automatically install available App Store updates (AutomaticallyInstallAppUpdates). Severity defaulted to medium.',
    'medium', -- mSCP severity gap
    'app_updates_auto_install', 'eq', ARRAY['On'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['patch-management']
),
(
    'cis_macos_1_6a_xprotect_data_auto',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce automatic XProtect and Gatekeeper data updates',
    'CIS §1.6. macOS must automatically install XProtect and Gatekeeper security data updates (ConfigDataInstall).',
    'medium',
    'xprotect_data_auto_update', 'eq', ARRAY['On'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['SI-2', 'SI-3'], ARRAY['A.12.6.1'], ARRAY['malware-protection', 'patch-management']
),
(
    'cis_macos_1_6b_critical_updates_auto',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce automatic installation of critical security updates',
    'CIS §1.6. macOS must automatically install critical security updates and system data files (CriticalUpdateInstall). Severity defaulted to medium.',
    'medium', -- mSCP severity gap
    'critical_updates_auto_install', 'eq', ARRAY['On'],
    NULL, 'fail',
    'T2', 'none', false,
    ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['patch-management']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0006_t2_batch1');

COMMIT;
