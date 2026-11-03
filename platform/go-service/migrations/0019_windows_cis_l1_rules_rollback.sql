-- patched.im — 0019_windows_cis_l1_rules_rollback.sql
-- Rolls back 0019: removes Windows rules and drops the platform column.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0019_windows_cis_l1_rules_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE platform = 'windows';

ALTER TABLE compliance_rules DROP COLUMN platform;

DELETE FROM schema_migrations WHERE version = '0019_windows_cis_l1_rules';

COMMIT;
