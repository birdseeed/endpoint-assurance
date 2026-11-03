-- Rollback for 0182_software_approval_decisions (PAT-2007)
--
-- Roll the API binary back first: the PAT-2007 portal handlers write and
-- read this table.
--
-- Dropping the table loses the customer decision history. The decisions
-- themselves stay in tenant_app_policies and tenant_extension_policies, but
-- who made them, when, from what previous state and why cannot be rebuilt.
-- Export it first:
--   psql ... -c "\copy software_approval_decisions TO 'software_approval_decisions.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0182_software_approval_decisions_rollback.sql

BEGIN;

DROP TABLE IF EXISTS software_approval_decisions;
DROP FUNCTION IF EXISTS reject_software_approval_decisions_mutation();
DROP FUNCTION IF EXISTS reject_software_approval_decisions_truncate();

DELETE FROM schema_migrations WHERE version = '0182_software_approval_decisions';

COMMIT;
