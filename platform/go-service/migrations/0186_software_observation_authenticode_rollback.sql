-- Rollback for 0186_software_observation_authenticode (PAT-2113)
--
-- Roll the extractor binary back first: it writes these columns.
--
-- Dropping them loses every stored Windows signature_state and signer. The
-- rest of each observation is untouched, and new software urgency falls back
-- to its pre-PAT-2113 reading (every Windows product authenticode_not_collected).
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0186_software_observation_authenticode_rollback.sql

BEGIN;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signature_state_valid,
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_signer_valid,
    DROP COLUMN IF EXISTS observed_signature_state,
    DROP COLUMN IF EXISTS observed_authenticode_signer;

DELETE FROM schema_migrations WHERE version = '0186_software_observation_authenticode';

COMMIT;
