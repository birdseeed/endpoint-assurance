-- Rollback for 0178_tenant_extension_policies_safari
--
-- Only safe if no row has browser='safari' at rollback time; otherwise the
-- ADD CONSTRAINT below fails on the existing data, which is the correct
-- outcome (never silently drop rows to make a rollback pass).
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0178_tenant_extension_policies_safari_rollback.sql

BEGIN;

ALTER TABLE tenant_extension_policies
    DROP CONSTRAINT tenant_extension_policies_browser_check,
    ADD CONSTRAINT tenant_extension_policies_browser_check
        CHECK (browser IN ('chrome', 'edge', 'firefox', 'any'));

DELETE FROM schema_migrations WHERE version = '0178_tenant_extension_policies_safari';

COMMIT;
