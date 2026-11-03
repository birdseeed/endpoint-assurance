-- Rollback 0040_device_revocations
BEGIN;
DROP TABLE IF EXISTS device_revocations;
DELETE FROM schema_migrations WHERE version = '0040_device_revocations';
COMMIT;
