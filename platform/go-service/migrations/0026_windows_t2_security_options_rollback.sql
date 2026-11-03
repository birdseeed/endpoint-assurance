-- patched.im — 0026_windows_t2_security_options_rollback.sql
-- Rolls back 0026: removes the 8 Windows T2 security-options rules.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0026_windows_t2_security_options_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE rule_key IN (
    'cis_win_2_3_1_1_block_microsoft_accounts',
    'cis_win_2_3_2_1_force_audit_subcategory',
    'cis_win_2_3_7_2_no_last_username',
    'cis_win_2_3_7_3_inactivity_limit',
    'cis_win_2_3_10_2_restrict_anonymous_sam',
    'cis_win_2_3_11_1_no_lm_hash',
    'cis_win_2_3_11_7_lm_auth_level',
    'cis_win_2_3_17_4_uac_admin_approval_builtin'
);

DELETE FROM schema_migrations WHERE version = '0026_windows_t2_security_options';

COMMIT;
