-- Rollback for 0020_device_apps_metering
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0020_device_apps_metering_rollback.sql

BEGIN;

DROP INDEX IF EXISTS idx_device_apps_last_used_at;

ALTER TABLE devices DROP COLUMN IF EXISTS metering_status;
ALTER TABLE device_apps DROP COLUMN IF EXISTS launch_count;
ALTER TABLE device_apps DROP COLUMN IF EXISTS last_used_at;

DELETE FROM schema_migrations WHERE version = '0020_device_apps_metering';

COMMIT;
