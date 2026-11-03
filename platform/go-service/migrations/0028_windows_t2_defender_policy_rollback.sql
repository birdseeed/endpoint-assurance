-- patched.im — 0028_windows_t2_defender_policy_rollback.sql
-- Rolls back 0028: removes the 6 Windows T2 Defender-policy rules.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0028_windows_t2_defender_policy_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE rule_key IN (
    'cis_win_18_9_47_4_1_defender_cloud_protection',
    'cis_win_18_9_47_4_2_defender_sample_submission',
    'cis_win_18_9_47_8_defender_pua_protection',
    'cis_win_18_9_47_9_defender_behavior_monitoring',
    'cis_win_18_9_47_12_defender_scan_removable_drives',
    'cis_win_18_9_47_11_defender_archive_scanning'
);

DELETE FROM schema_migrations WHERE version = '0028_windows_t2_defender_policy';

COMMIT;
