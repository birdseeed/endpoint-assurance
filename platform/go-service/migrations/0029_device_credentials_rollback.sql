-- Rollback: 0029_device_credentials
DROP INDEX IF EXISTS tenant_credentials_device_active_idx;
ALTER TABLE tenant_credentials DROP COLUMN IF EXISTS device_id;
DELETE FROM schema_migrations WHERE version = '0029_device_credentials';
