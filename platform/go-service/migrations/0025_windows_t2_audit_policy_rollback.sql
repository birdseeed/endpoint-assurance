-- patched.im — 0025_windows_t2_audit_policy_rollback.sql
-- Rolls back 0025: removes the 10 Windows T2 advanced-audit-policy rules.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0025_windows_t2_audit_policy_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE rule_key IN (
    'cis_win_17_1_1_audit_credential_validation',
    'cis_win_17_2_3_audit_user_account_management',
    'cis_win_17_2_2_audit_security_group_management',
    'cis_win_17_3_2_audit_process_creation',
    'cis_win_17_5_4_audit_logon',
    'cis_win_17_5_1_audit_account_lockout',
    'cis_win_17_7_1_audit_policy_change',
    'cis_win_17_8_1_audit_sensitive_privilege_use',
    'cis_win_17_9_5_audit_system_integrity',
    'cis_win_17_9_3_audit_security_state_change'
);

DELETE FROM schema_migrations WHERE version = '0025_windows_t2_audit_policy';

COMMIT;
