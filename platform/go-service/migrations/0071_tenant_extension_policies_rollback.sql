-- Rollback for 0071_tenant_extension_policies
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0071_tenant_extension_policies_rollback.sql

BEGIN;

DROP TABLE IF EXISTS tenant_extension_policies;

DELETE FROM schema_migrations WHERE version = '0071_tenant_extension_policies';

COMMIT;
