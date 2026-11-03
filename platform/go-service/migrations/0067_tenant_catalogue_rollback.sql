-- Rollback for 0067_tenant_catalogue (PAT-659 / PAT-660).

BEGIN;

DROP INDEX IF EXISTS tenant_catalogue_tenant_id;
DROP TABLE IF EXISTS tenant_catalogue;

DELETE FROM schema_migrations WHERE version = '0067_tenant_catalogue';

COMMIT;
