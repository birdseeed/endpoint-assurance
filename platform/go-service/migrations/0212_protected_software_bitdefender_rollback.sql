-- Reverses 0212_protected_software_bitdefender.sql (PAT-2234).
-- Any tenant override of the row is removed with it (ON DELETE CASCADE on
-- protected_software_overrides.baseline_id). Bitdefender devices return to
-- "unrecognised" in EDR coverage; tenant-scoped Bitdefender rows are kept.
BEGIN;

DELETE FROM protected_software
WHERE tenant_id IS NULL
  AND team_id = 'GUNFMW623Y'
  AND added_by = 'PAT-2234 baseline seed';

DELETE FROM schema_migrations WHERE version = '0212_protected_software_bitdefender';

COMMIT;
