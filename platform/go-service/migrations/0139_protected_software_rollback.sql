-- patched.im — 0139_protected_software_rollback.sql
-- Rollback for 0139_protected_software.sql (PAT-1801).
--
-- Drops all three tables in dependency order. This is a clean rollback —
-- nothing outside these three tables reads or writes them yet (this
-- migration and its enforcement code are additive), so there is no lossy
-- data-reconciliation step required, unlike e.g. 0138's tier-collapse
-- rollback.
--
-- Apply ONLY to undo 0139_protected_software.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0139_protected_software_rollback.sql

BEGIN;

DROP TABLE IF EXISTS protected_software_changes;
DROP TABLE IF EXISTS protected_software_overrides;
DROP TABLE IF EXISTS protected_software;

DELETE FROM schema_migrations WHERE version = '0139_protected_software';

COMMIT;
