-- Rollback for 0201_app_policy_source (PAT-2091)
--
-- Roll the API binary back first: it names the source column on every
-- application policy write and read, and would fail if the column went first.
--
-- Dropping the column restores the pre-PAT-2091 resolution: a more specific
-- portal row can again outrank an operator's mandatory row. No policy
-- decision is lost.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0201_app_policy_source_rollback.sql

BEGIN;

ALTER TABLE tenant_app_policies
    DROP CONSTRAINT IF EXISTS tenant_app_policies_source_check,
    DROP COLUMN IF EXISTS source;

DELETE FROM schema_migrations WHERE version = '0201_app_policy_source';

COMMIT;
