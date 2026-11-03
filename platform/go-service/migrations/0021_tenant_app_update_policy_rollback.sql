-- patched.im — 0021_tenant_app_update_policy_rollback.sql
-- Rolls back migration 0021_tenant_app_update_policy.sql (PAT-364).

BEGIN;

DROP TABLE IF EXISTS tenant_app_policy_changes;
DROP TABLE IF EXISTS tenant_app_update_policies;

ALTER TABLE tenants DROP COLUMN IF EXISTS app_updates_default_enabled;

DELETE FROM schema_migrations WHERE version = '0021_tenant_app_update_policy';

COMMIT;
