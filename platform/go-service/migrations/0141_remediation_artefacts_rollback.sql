-- patched.im — 0141_remediation_artefacts_rollback.sql
-- Rollback for 0141_remediation_artefacts.sql (PAT-1549).
--
-- Clean rollback: nothing outside this table reads or writes it yet (purely
-- additive migration + handlers), so there is no lossy reconciliation step.
--
-- Apply ONLY to undo 0141_remediation_artefacts.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0141_remediation_artefacts_rollback.sql

BEGIN;

DROP TABLE IF EXISTS remediation_artefacts;

DELETE FROM schema_migrations WHERE version = '0141_remediation_artefacts';

COMMIT;
