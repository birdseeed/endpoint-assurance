-- Roll back PAT-1538's tenant execution-policy authorization table.
BEGIN;

DROP TABLE IF EXISTS tenant_app_execution_policies;

DELETE FROM schema_migrations
WHERE version = '0117_tenant_app_execution_policies';

COMMIT;
