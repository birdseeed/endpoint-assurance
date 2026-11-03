-- migrate:statement-by-statement
-- Rollback for 0167_tooling_index_and_validate (PAT-2021). Drops the index
-- without blocking writes (outside a transaction, like its build). The
-- constraints stay validated: 0166's rollback replaces them.
DROP INDEX CONCURRENTLY IF EXISTS software_installations_kind_value_present_idx;

BEGIN;

DELETE FROM schema_migrations WHERE version = '0167_tooling_index_and_validate';

COMMIT;
