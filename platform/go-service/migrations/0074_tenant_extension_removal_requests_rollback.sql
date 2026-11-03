-- Rollback for 0074_tenant_extension_removal_requests (PAT-832, part of PAT-773).

BEGIN;

DROP INDEX IF EXISTS idx_tenant_extension_removal_requests_active_uq;
DROP INDEX IF EXISTS idx_tenant_extension_removal_requests_pending;
DROP TABLE IF EXISTS tenant_extension_removal_requests;

DELETE FROM schema_migrations WHERE version = '0074_tenant_extension_removal_requests';

COMMIT;
