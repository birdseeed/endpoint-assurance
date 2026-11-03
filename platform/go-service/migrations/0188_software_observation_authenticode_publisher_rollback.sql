-- Rollback for 0188_software_observation_authenticode_publisher (PAT-2116)
--
-- Roll the extractor binary back first: it writes these columns and would
-- start writing 'unsigned' again if this ran ahead of the binary rollback.
--
-- Dropping the five columns loses every stored Windows signer thumbprint,
-- issuer, root thumbprint, root kind and executable resolution. The rest of
-- each observation is untouched, and new software urgency falls back to its
-- PAT-2113 reading (a valid signature with one agreed signer is trusted).
--
-- Restores 0186's original signature_state CHECK (valid|invalid|unknown). A
-- row already carrying 'unsigned' would violate that narrower constraint, so
-- this maps it to NULL first -- the "not reported" reading 0186 already gives
-- every value outside its own enum. That loses the distinction between an
-- unsigned installation and one never assessed.
--
-- software_observations is immutable evidence: 0111's
-- trg_software_observations_reject_update trigger rejects UPDATE on every
-- row, including by the owning role. This rollback needs exactly one bounded
-- UPDATE (the one value this migration's forward direction introduced, and
-- nothing else), so it disables that one trigger, runs that one UPDATE, and
-- re-enables the trigger, all inside this migration's own transaction --
-- immutability is never open to any statement outside this block (as 0187).
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0188_software_observation_authenticode_publisher_rollback.sql

BEGIN;

ALTER TABLE software_observations DISABLE TRIGGER trg_software_observations_reject_update;

UPDATE software_observations
SET observed_signature_state = NULL
WHERE observed_signature_state = 'unsigned';

ALTER TABLE software_observations ENABLE TRIGGER trg_software_observations_reject_update;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_signer_thumbprint_valid,
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_issuer_valid,
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_root_thumbprint_valid,
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_root_kind_valid,
    DROP CONSTRAINT IF EXISTS software_observations_executable_resolution_valid,
    DROP COLUMN IF EXISTS observed_authenticode_signer_thumbprint,
    DROP COLUMN IF EXISTS observed_authenticode_issuer,
    DROP COLUMN IF EXISTS observed_authenticode_root_thumbprint,
    DROP COLUMN IF EXISTS observed_authenticode_root_kind,
    DROP COLUMN IF EXISTS observed_executable_resolution;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signature_state_valid,
    ADD CONSTRAINT software_observations_signature_state_valid
        CHECK (observed_signature_state IS NULL
               OR observed_signature_state IN ('valid', 'invalid', 'unknown'));

COMMENT ON COLUMN software_observations.observed_signature_state IS
    'PAT-2113. Windows apps[].installation_evidence.signature_state: valid, invalid (digest mismatch) or unknown (anything else, including no signature). NULL = not reported (macOS, older agent, app outside the reviewed evidence targets, or an unrecognised value).';

DELETE FROM schema_migrations WHERE version = '0188_software_observation_authenticode_publisher';

COMMIT;
