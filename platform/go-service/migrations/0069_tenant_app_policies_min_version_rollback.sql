-- Rollback for 0069_tenant_app_policies_min_version (PAT-723).

BEGIN;

ALTER TABLE tenant_app_policies DROP COLUMN IF EXISTS min_version;

DELETE FROM schema_migrations WHERE version = '0069_tenant_app_policies_min_version';

COMMIT;
