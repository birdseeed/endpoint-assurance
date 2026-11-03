-- Rollback for 0017_tenant_credentials.sql
BEGIN;
DROP TABLE IF EXISTS tenant_credentials;
DELETE FROM schema_migrations WHERE version = '0017';
COMMIT;
