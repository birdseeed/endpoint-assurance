BEGIN;
DELETE FROM schema_migrations WHERE version = '0023_software_allowlist';
DROP TABLE IF EXISTS tenant_allowlist_changes;
ALTER TABLE tenants DROP COLUMN IF EXISTS allowlist_default_deny;
DROP TABLE IF EXISTS tenant_allowlists;
DROP TABLE IF EXISTS allowlist_baseline_apps;
COMMIT;
