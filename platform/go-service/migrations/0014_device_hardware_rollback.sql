-- patched.im — 0014_device_hardware_rollback.sql
-- Rolls back 0014_device_hardware.sql: drops device_disk, device_storage_volume,
-- and device_hardware (in FK dependency order) and removes the bookmark.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0014_device_hardware_rollback.sql

BEGIN;

DROP TABLE IF EXISTS device_disk;
DROP TABLE IF EXISTS device_storage_volume;
DROP TABLE IF EXISTS device_hardware;

DELETE FROM schema_migrations WHERE version = '0014_device_hardware';

COMMIT;
