-- Rollback for 0173_schema_drift_reconcile_findings (PAT-2053).
--
-- Removes only the bookkeeping row. The index, default and NOT NULL 0173
-- ensures all belong to 0025's own shape, so undoing them would break a
-- migrations-built database and re-open the drift on prod. None of them
-- changes behaviour a previous binary depends on.
--
-- If the index genuinely has to go on prod, drop it by hand as the patched
-- role; do not add that to this file.

BEGIN;

DELETE FROM schema_migrations WHERE version = '0173_schema_drift_reconcile_findings';

COMMIT;
