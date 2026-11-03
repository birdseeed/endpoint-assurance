-- Roll back PAT-1562's tenant_kind classification column.
BEGIN;

ALTER TABLE tenants DROP COLUMN IF EXISTS tenant_kind;

DELETE FROM schema_migrations
WHERE version = '0119_tenant_kind';

COMMIT;
