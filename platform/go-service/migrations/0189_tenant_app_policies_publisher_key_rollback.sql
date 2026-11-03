-- Rollback for 0189_tenant_app_policies_publisher_key (PAT-2121)
--
-- Roll the API binary back first: it writes publisher_key on every approval
-- and would fail those writes if the column went first.
--
-- Dropping the column loses every recorded Windows publisher key. No policy
-- decision changes: every row keeps its policy, and new software urgency
-- falls back to PAT-2116's reading, where a Windows product tops out at
-- medium. A key is re-derived from evidence the next time a product is set to
-- approved after 0189 is re-applied.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0189_tenant_app_policies_publisher_key_rollback.sql

BEGIN;

ALTER TABLE tenant_app_policies
    DROP CONSTRAINT IF EXISTS tenant_app_policies_publisher_key_valid,
    DROP COLUMN IF EXISTS publisher_key;

DELETE FROM schema_migrations WHERE version = '0189_tenant_app_policies_publisher_key';

COMMIT;
