-- patched.im - 0185_software_observation_signing_status.sql
-- PAT-2112: the macOS collector's explicit signing and notarisation evidence.
--
-- Two nullable columns on software_observations, the immutable per-report
-- evidence PAT-2093's new software urgency reads:
--
--   observed_signing_status       signed | adhoc | unsigned | error, from the
--                                 collector's apps[].signing_status. Before
--                                 PAT-2112 "unsigned", "ad hoc" and
--                                 "codesign failed" all arrived as the same
--                                 signed_by "Unknown".
--   observed_notarization_status  notarized | not_notarized | unknown, from
--                                 apps[].notarization_status (Gatekeeper's
--                                 assessment, falling back to the stapled
--                                 ticket).
--
-- NULL means the report did not carry the field: every row before this
-- migration, every Windows row, every Homebrew and tooling row, and any value
-- outside the enum (the extractor stores NULL rather than refusing the
-- report). NULL is never read as unsigned or not notarised.
--
-- Additive only. No existing column, constraint or row changes, and nothing
-- is backfilled: an old observation has no such evidence to recover. ADD
-- COLUMN with no default is a catalogue-only change (no table rewrite), and
-- the table's UPDATE/TRUNCATE-rejecting triggers do not fire on DDL.
-- Lock: ACCESS EXCLUSIVE on software_observations for the two ALTERs only,
-- milliseconds, blocking the extractor's observation inserts for that time.
-- Deploy before the binaries.

BEGIN;

ALTER TABLE software_observations
    ADD COLUMN IF NOT EXISTS observed_signing_status TEXT,
    ADD COLUMN IF NOT EXISTS observed_notarization_status TEXT;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signing_status_valid,
    ADD CONSTRAINT software_observations_signing_status_valid
        CHECK (observed_signing_status IS NULL
               OR observed_signing_status IN ('signed', 'adhoc', 'unsigned', 'error')),
    DROP CONSTRAINT IF EXISTS software_observations_notarization_status_valid,
    ADD CONSTRAINT software_observations_notarization_status_valid
        CHECK (observed_notarization_status IS NULL
               OR observed_notarization_status IN ('notarized', 'not_notarized', 'unknown'));

COMMENT ON COLUMN software_observations.observed_signing_status IS
    'PAT-2112. macOS apps[].signing_status: signed, adhoc, unsigned or error. NULL = not reported (older agent, Windows, Homebrew, or an unrecognised value).';
COMMENT ON COLUMN software_observations.observed_notarization_status IS
    'PAT-2112. macOS apps[].notarization_status: notarized, not_notarized or unknown. NULL = not reported. Only notarized confirms notarisation.';

INSERT INTO schema_migrations (version) VALUES ('0185_software_observation_signing_status')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
