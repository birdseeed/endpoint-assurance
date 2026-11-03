-- Rollback for 0185_software_observation_signing_status (PAT-2112)
--
-- Roll the extractor binary back first: it writes these columns.
--
-- Dropping them loses every stored signing_status and notarization_status.
-- The rest of each observation is untouched, and new software urgency falls
-- back to its pre-PAT-2112 reading (signed_by "Unknown" is signing unknown,
-- notarisation not confirmed).
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0185_software_observation_signing_status_rollback.sql

BEGIN;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signing_status_valid,
    DROP CONSTRAINT IF EXISTS software_observations_notarization_status_valid,
    DROP COLUMN IF EXISTS observed_signing_status,
    DROP COLUMN IF EXISTS observed_notarization_status;

DELETE FROM schema_migrations WHERE version = '0185_software_observation_signing_status';

COMMIT;
