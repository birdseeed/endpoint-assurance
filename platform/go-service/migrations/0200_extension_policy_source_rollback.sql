-- Rollback for 0200_extension_policy_source (PAT-2089)
--
-- Roll the API binary back first: it names the source column on every
-- extension policy write and would fail those writes if the column went first.
--
-- Dropping the column restores the pre-PAT-2089 behaviour: every unapproved
-- row, the customer's included, feeds the signed extension blocklist on an
-- App Control tenant. No policy decision is lost.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0200_extension_policy_source_rollback.sql

BEGIN;

ALTER TABLE tenant_extension_policies
    DROP CONSTRAINT IF EXISTS tenant_extension_policies_source_check,
    DROP COLUMN IF EXISTS source;

DELETE FROM schema_migrations WHERE version = '0200_extension_policy_source';

COMMIT;
