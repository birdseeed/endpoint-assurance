-- patched.im — 0136_notconfigured_windows_defaults_rollback.sql
-- Reverses 0136_notconfigured_windows_defaults.sql (PAT-1772, server half).
--
-- Restores treat_not_configured_as to NULL for the 14 rows this migration
-- touched — the value every one of them held before 0136 (the column was
-- added NULL by 0131_treat_not_configured_as.sql and none of these 14
-- rule_keys was set by any migration between 0131 and 0136; verified against
-- 0019/0027/0028/0041 and every migration after them). NULL, not a guess:
-- confirmed for each row rather than assumed as the blanket default.

BEGIN;

UPDATE compliance_rules
SET treat_not_configured_as = NULL
WHERE rule_key IN (
    'cis_win_18_9_45_defender_realtime',
    'nist_win_ac2_laps_enrolled',
    'cis_win_18_4_3_smbv1_client_disabled',
    'cis_win_18_6_4_1_llmnr_disabled',
    'cis_win_18_9_8_2_autoplay_disabled',
    'cis_win_18_9_85_1_always_install_elevated_disabled',
    'cis_win_18_8_36_1_remote_assistance_disabled',
    'cis_win_18_3_7_wdigest_cleartext_disabled',
    'cis_win_18_9_47_4_1_defender_cloud_protection',
    'cis_win_18_9_47_4_2_defender_sample_submission',
    'cis_win_18_9_47_8_defender_pua_protection',
    'cis_win_18_9_47_9_defender_behavior_monitoring',
    'cis_win_18_9_47_12_defender_scan_removable_drives',
    'cis_win_18_9_47_11_defender_archive_scanning'
);

DELETE FROM schema_migrations WHERE version = '0136_notconfigured_windows_defaults';

COMMIT;
