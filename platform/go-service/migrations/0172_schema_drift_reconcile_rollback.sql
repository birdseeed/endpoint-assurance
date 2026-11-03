-- Rollback for 0172_schema_drift_reconcile (PAT-2053).
--
-- Removes only the bookkeeping row. Every object 0172 touches belongs to the
-- migrations' own shape (0025's indexes, defaults and NOT NULLs, 0019's
-- dropped default), so undoing them would break a migrations-built database
-- and re-open the drift on prod. Nothing in 0172 changes behaviour a previous
-- binary depends on: the indexes are read-side only, and the NOT NULL and
-- default changes match what CI has always run against.
--
-- If the forward migration must genuinely be reversed on prod (for example
-- the GIN build proved too heavy), drop the specific index by hand as the
-- patched role; do not add that to this file.

BEGIN;

DELETE FROM schema_migrations WHERE version = '0172_schema_drift_reconcile';

COMMIT;
