-- patched.im — 0024_windows_t2_account_policy_rollback.sql
-- Rolls back 0024: removes the 9 Windows T2 account/password-policy rules.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0024_windows_t2_account_policy_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE rule_key IN (
    'cis_win_1_1_1_password_history',
    'cis_win_1_1_2_password_max_age',
    'cis_win_1_1_3_password_min_age',
    'cis_win_1_1_4_password_min_length',
    'cis_win_1_1_5_password_complexity',
    'cis_win_1_1_7_reversible_encryption',
    'cis_win_1_2_1_lockout_duration',
    'cis_win_1_2_2_lockout_threshold',
    'cis_win_1_2_4_lockout_reset'
);

DELETE FROM schema_migrations WHERE version = '0024_windows_t2_account_policy';

COMMIT;
