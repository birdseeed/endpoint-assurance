-- patched.im — 0140_device_lifecycle_rollback.sql
-- Rollback for 0140_device_lifecycle.sql (PAT-1595).
--
-- Drops both tables. This is a clean rollback — nothing outside these two
-- tables reads or writes them yet (this migration and the handlers built on
-- it are additive), so there is no lossy data-reconciliation step required.
--
-- Apply ONLY to undo 0140_device_lifecycle.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0140_device_lifecycle_rollback.sql

BEGIN;

DROP TABLE IF EXISTS device_lifecycle_thresholds;
DROP TABLE IF EXISTS device_upload_lists;

DELETE FROM schema_migrations WHERE version = '0140_device_lifecycle';

COMMIT;
