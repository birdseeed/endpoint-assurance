-- patched.im — 0032_tenant_app_policies_rollback.sql
-- Rolls back 0032_tenant_app_policies.sql (PAT-470).
BEGIN;
DROP TABLE IF EXISTS tenant_app_policies CASCADE;
DELETE FROM schema_migrations WHERE version = '0032_tenant_app_policies';
COMMIT;
