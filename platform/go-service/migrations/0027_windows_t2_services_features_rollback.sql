-- patched.im — 0027_windows_t2_services_features_rollback.sql
-- Rolls back 0027: removes the 6 Windows T2 services-&-features rules.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0027_windows_t2_services_features_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE rule_key IN (
    'cis_win_18_4_3_smbv1_client_disabled',
    'cis_win_18_6_4_1_llmnr_disabled',
    'cis_win_18_9_8_2_autoplay_disabled',
    'cis_win_18_9_85_1_always_install_elevated_disabled',
    'cis_win_18_8_36_1_remote_assistance_disabled',
    'cis_win_18_3_7_wdigest_cleartext_disabled'
);

DELETE FROM schema_migrations WHERE version = '0027_windows_t2_services_features';

COMMIT;
