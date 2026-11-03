-- patched.im — 0024_windows_t2_account_policy.sql
-- PAT-405 (parity epic PAT-404, ADR-0007): Windows CIS L1 T2 — batch 1.
--
-- CIS Microsoft Windows 11 Benchmark v2.0.0, §1.1 Password Policy + §1.2
-- Account Lockout Policy. The Windows analog of the macOS §5.2 password-policy
-- T2 pack (migration 0006). 9 rules, all T2, platform='windows'.
--
-- COLLECTOR CONTRACT (this migration DEFINES it; collector implements it):
-- These signal_keys must be emitted by ComplianceCollector.cs in the paired
-- collector bump, sourced from `secedit /export /cfg <tmp>` (or `net accounts`):
--
--   secedit field             -> signal_key                         -> type
--   PasswordHistorySize       -> password_history_count             -> int
--   MaximumPasswordAge        -> password_max_age_days               -> int*
--   MinimumPasswordAge        -> password_min_age_days               -> int
--   MinimumPasswordLength     -> password_min_length                 -> int
--   PasswordComplexity        -> password_complexity_enabled         -> Yes/No
--   ClearTextPassword         -> password_reversible_encryption_disabled -> Yes/No
--   LockoutDuration           -> account_lockout_duration_minutes    -> int
--   LockoutBadCount           -> account_lockout_threshold           -> int**
--   ResetLockoutCount         -> account_lockout_reset_minutes       -> int
--
--   *  MaximumPasswordAge: 0 = "never expires" = fail. Collector CLAMPS 0 -> 99999
--      so the `lte 365` rule fails correctly with a single comparator.
--   ** LockoutBadCount: 0 = "never lock out" = fail. Collector CLAMPS 0 -> 999
--      so the `lte 5` rule fails correctly.
--
-- Until the collector emits these, signals are null -> treat_unknown_as='fail'
-- (same convention as every macOS T2 batch).
--
-- pii_observed: all signals are account-policy metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0024_windows_t2_account_policy.sql
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

-- §1.1.1 — Enforce password history
(
    'cis_win_1_1_1_password_history',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enforce password history (≥ 24 remembered)',
    'CIS §1.1.1. The system must remember at least 24 previous passwords (PasswordHistorySize), preventing reuse. Sourced from secedit /export.',
    'medium',
    'password_history_count', 'gte', ARRAY['24'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','IA-5(1)'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),

-- §1.1.2 — Maximum password age
(
    'cis_win_1_1_2_password_max_age',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Restrict maximum password age (1–365 days)',
    'CIS §1.1.2. Passwords must expire after no more than 365 days (MaximumPasswordAge). A value of 0 means "never expires" — the collector clamps 0 to 99999 so this control fails. Sourced from secedit /export.',
    'medium',
    'password_max_age_days', 'lte', ARRAY['365'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','IA-5(1)'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),

-- §1.1.3 — Minimum password age
(
    'cis_win_1_1_3_password_min_age',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enforce minimum password age (≥ 1 day)',
    'CIS §1.1.3. Passwords must be at least 1 day old before they can be changed (MinimumPasswordAge), stopping users cycling through the history to reuse a password. Sourced from secedit /export.',
    'low',
    'password_min_age_days', 'gte', ARRAY['1'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','IA-5(1)'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),

-- §1.1.4 — Minimum password length
(
    'cis_win_1_1_4_password_min_length',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Require minimum password length of 14 characters',
    'CIS §1.1.4. The password policy must require at least 14 characters (MinimumPasswordLength). Sourced from secedit /export.',
    'medium',
    'password_min_length', 'gte', ARRAY['14'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','IA-5(1)'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),

-- §1.1.5 — Password complexity
(
    'cis_win_1_1_5_password_complexity',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Enable password complexity requirements',
    'CIS §1.1.5. Passwords must meet complexity requirements (PasswordComplexity = 1): mixed case, digits, symbols, and no username substring. Collector emits Yes/No.',
    'medium',
    'password_complexity_enabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','IA-5(1)'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),

-- §1.1.7 — Store passwords using reversible encryption
(
    'cis_win_1_1_7_reversible_encryption',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Disable reversible password encryption',
    'CIS §1.1.7. Reversible password encryption (ClearTextPassword) must be disabled — storing recoverable passwords is equivalent to storing plaintext. Collector emits Yes when disabled (compliant).',
    'high',
    'password_reversible_encryption_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','SC-28'], ARRAY['A.9.4.3'], ARRAY['secure-configuration']
),

-- §1.2.1 — Account lockout duration
(
    'cis_win_1_2_1_lockout_duration',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Set account lockout duration (≥ 15 minutes)',
    'CIS §1.2.1. A locked account must stay locked for at least 15 minutes (LockoutDuration), slowing online password guessing. Sourced from secedit /export.',
    'medium',
    'account_lockout_duration_minutes', 'gte', ARRAY['15'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-7'], ARRAY['A.9.4.2'], ARRAY['secure-configuration']
),

-- §1.2.2 — Account lockout threshold
(
    'cis_win_1_2_2_lockout_threshold',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Set account lockout threshold (1–5 attempts)',
    'CIS §1.2.2. The account must lock after no more than 5 failed attempts (LockoutBadCount). A value of 0 means "never lock out" — the collector clamps 0 to 999 so this control fails. Sourced from secedit /export.',
    'medium',
    'account_lockout_threshold', 'lte', ARRAY['5'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-7'], ARRAY['A.9.4.2'], ARRAY['secure-configuration']
),

-- §1.2.4 — Reset account lockout counter
(
    'cis_win_1_2_4_lockout_reset',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Set reset-lockout-counter window (≥ 15 minutes)',
    'CIS §1.2.4. The failed-attempt counter must only reset after at least 15 minutes (ResetLockoutCount), so an attacker cannot reset it cheaply. Sourced from secedit /export.',
    'medium',
    'account_lockout_reset_minutes', 'gte', ARRAY['15'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-7'], ARRAY['A.9.4.2'], ARRAY['secure-configuration']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0024_windows_t2_account_policy');

COMMIT;
