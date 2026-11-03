-- patched.im — 0036_tenant_new_apps_rollback.sql
-- Rollback for 0036_tenant_new_apps.sql (PAT-167).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0036_tenant_new_apps_rollback.sql
BEGIN;

DROP TABLE IF EXISTS tenant_new_apps CASCADE;

DELETE FROM schema_migrations WHERE version = '0036_tenant_new_apps';

COMMIT;
