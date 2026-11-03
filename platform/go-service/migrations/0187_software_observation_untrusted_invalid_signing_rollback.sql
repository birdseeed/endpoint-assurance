-- Rollback for 0187_software_observation_untrusted_invalid_signing (PAT-2117)
--
-- Roll the extractor binary back first: it is what would start writing
-- 'untrusted'/'invalid' again if this ran ahead of the binary rollback.
--
-- Restores 0185's original CHECK (signed|adhoc|unsigned|error). Any row
-- already carrying 'untrusted' or 'invalid' would violate that narrower
-- constraint, so this maps those two values to NULL first -- the same "not
-- reported" reading 0185 already gives every value outside its own enum.
-- That loses the distinction between an untrusted/invalid installation and
-- one never assessed for signing at all; the rest of each observation
-- (signer, team_id, notarization_status, everything else) is untouched.
--
-- software_observations is immutable evidence: 0111's
-- trg_software_observations_reject_update trigger rejects UPDATE on every
-- row, including by the owning role. This rollback needs exactly one bounded
-- UPDATE (the two values this migration's forward direction introduced, and
-- nothing else), so it disables that one trigger, runs that one UPDATE, and
-- re-enables the trigger, all inside this migration's own transaction --
-- immutability is never open to any statement outside this block.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0187_software_observation_untrusted_invalid_signing_rollback.sql

BEGIN;

ALTER TABLE software_observations DISABLE TRIGGER trg_software_observations_reject_update;

UPDATE software_observations
SET observed_signing_status = NULL
WHERE observed_signing_status IN ('untrusted', 'invalid');

ALTER TABLE software_observations ENABLE TRIGGER trg_software_observations_reject_update;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signing_status_valid,
    ADD CONSTRAINT software_observations_signing_status_valid
        CHECK (observed_signing_status IS NULL
               OR observed_signing_status IN ('signed', 'adhoc', 'unsigned', 'error'));

DELETE FROM schema_migrations WHERE version = '0187_software_observation_untrusted_invalid_signing';

COMMIT;
