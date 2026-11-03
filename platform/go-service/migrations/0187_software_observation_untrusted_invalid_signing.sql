-- patched.im - 0187_software_observation_untrusted_invalid_signing.sql
-- PAT-2117: two more macOS signing_status values the updater's collector now
-- sends, beside PAT-2112's signed|adhoc|unsigned|error:
--
--   untrusted  the signature validates against the code, but its certificate
--              chain does not anchor to Apple -- typically a self-signed
--              certificate whose Subject CN copies the "Developer ID
--              Application: ..." naming convention to look legitimate. The
--              collector reports notarization_status "not_notarized" for
--              these.
--   invalid    the signature does not validate against the code at all
--              (tampered, or broken after signing). The collector reports
--              notarization_status "unknown" for these.
--
-- 0185's CHECK constraint only allowed signed|adhoc|unsigned|error, so a
-- report carrying either new value would be stored as NULL (not the enum's
-- job to refuse it -- see PAYLOAD_SCHEMA.md) until this migration lands, and
-- new software urgency (PAT-2093) could not read them. Widen it the same way
-- 0185 widened it from nothing: drop and re-add, additive, no column change,
-- no backfill of existing rows (every existing row is NULL or one of the
-- four original values, both already satisfy the wider CHECK).
--
-- Lock: ACCESS EXCLUSIVE on software_observations for the constraint swap
-- only -- milliseconds plus the CHECK validation scan of existing rows,
-- which all already satisfy the wider (superset) constraint. Deploy before
-- the updater build that starts sending these two values.

BEGIN;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signing_status_valid,
    ADD CONSTRAINT software_observations_signing_status_valid
        CHECK (observed_signing_status IS NULL
               OR observed_signing_status IN ('signed', 'adhoc', 'unsigned', 'error', 'untrusted', 'invalid'));

COMMENT ON COLUMN software_observations.observed_signing_status IS
    'PAT-2112/PAT-2117. macOS apps[].signing_status: signed, adhoc, unsigned, error, untrusted or invalid. NULL = not reported (older agent, Windows, Homebrew, or an unrecognised value).';

INSERT INTO schema_migrations (version) VALUES ('0187_software_observation_untrusted_invalid_signing')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
