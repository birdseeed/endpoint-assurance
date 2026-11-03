-- Rollback for 0075_tenant_email_domains.sql
BEGIN;

DROP TABLE IF EXISTS tenant_email_domains;

DELETE FROM schema_migrations WHERE version = '0075_tenant_email_domains';

COMMIT;
