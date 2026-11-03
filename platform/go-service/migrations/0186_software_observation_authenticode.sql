-- patched.im - 0186_software_observation_authenticode.sql
-- PAT-2113: the Windows agent's per-installation Authenticode evidence.
--
-- Two nullable columns on software_observations, the immutable per-report
-- evidence PAT-2093's new software urgency reads:
--
--   observed_signature_state    valid | invalid | unknown, from the Windows
--                               agent's apps[].installation_evidence
--                               .signature_state. valid = WinVerifyTrust
--                               accepted the reviewed executable (embedded
--                               signature, or a SHA-256 catalog membership)
--                               against the device's trust store, offline,
--                               with no revocation check. invalid = only a
--                               digest mismatch (the file changed after it was
--                               signed). unknown = everything else, including
--                               no signature found and an untrusted chain: the
--                               agent never reports "unsigned".
--   observed_authenticode_signer  the leaf signer certificate's Subject DN, as
--                               the agent reads it for a valid signature. It
--                               is stored only beside valid. No issuer or
--                               thumbprint is sent, so it names a publisher but
--                               does not pin one the way an Apple Team ID does.
--
-- NULL means the report did not carry the evidence: every row before this
-- migration, every macOS row, every Windows app outside the reviewed evidence
-- targets (today all of them: the published target set is empty), and any
-- value outside the enum (the extractor stores NULL rather than refusing the
-- report). NULL is never read as unsigned or as trusted.
--
-- Additive only. No existing column, constraint or row changes, and nothing
-- is backfilled: an old observation has no such evidence to recover. ADD
-- COLUMN with no default is a catalogue-only change (no table rewrite), the
-- CHECK constraints validate against an all-NULL column, and the table's
-- UPDATE/TRUNCATE-rejecting triggers do not fire on DDL.
-- Lock: ACCESS EXCLUSIVE on software_observations for the ALTERs only,
-- milliseconds plus the CHECK validation scan, blocking the extractor's
-- observation inserts for that time. Deploy before the binaries.

BEGIN;

ALTER TABLE software_observations
    ADD COLUMN IF NOT EXISTS observed_signature_state TEXT,
    ADD COLUMN IF NOT EXISTS observed_authenticode_signer TEXT;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signature_state_valid,
    ADD CONSTRAINT software_observations_signature_state_valid
        CHECK (observed_signature_state IS NULL
               OR observed_signature_state IN ('valid', 'invalid', 'unknown')),
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_signer_valid,
    ADD CONSTRAINT software_observations_authenticode_signer_valid
        CHECK (observed_authenticode_signer IS NULL
               OR (observed_signature_state = 'valid'
                   AND char_length(observed_authenticode_signer) BETWEEN 1 AND 512));

COMMENT ON COLUMN software_observations.observed_signature_state IS
    'PAT-2113. Windows apps[].installation_evidence.signature_state: valid, invalid (digest mismatch) or unknown (anything else, including no signature). NULL = not reported (macOS, older agent, app outside the reviewed evidence targets, or an unrecognised value).';
COMMENT ON COLUMN software_observations.observed_authenticode_signer IS
    'PAT-2113. Windows apps[].installation_evidence.signer: leaf Authenticode signer Subject DN, stored only when observed_signature_state is valid. No issuer or thumbprint: a publisher name, not a pinned identity.';

INSERT INTO schema_migrations (version) VALUES ('0186_software_observation_authenticode')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
