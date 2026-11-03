-- patched.im — 0055_tenant_webhooks_rollback.sql
-- Undo 0055_tenant_webhooks.sql

BEGIN;

DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS tenant_webhooks;

DELETE FROM schema_migrations WHERE version = '0055_tenant_webhooks';

COMMIT;
