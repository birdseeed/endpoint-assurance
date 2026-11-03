-- patched.im - 0188_software_observation_authenticode_publisher.sql
-- PAT-2116: the Windows agent (updater #668) now reports Authenticode evidence
-- for every installed app, not only reviewed targets, and adds to PAT-2113's
-- apps[].installation_evidence:
--
--   signature_state "unsigned"  a conservative, proven verdict: no embedded
--                               signature (exactly TRUST_E_NOSIGNATURE) and a
--                               clean SHA-256 and SHA-1 catalog miss against a
--                               catalog database shown to be working. 0186's
--                               CHECK only allowed valid|invalid|unknown, so
--                               the extractor stored it as NULL until now.
--   signer_thumbprint           beside valid only: SHA-256 over the leaf
--                               certificate's DER, lowercase hex.
--   issuer                      beside valid only: the leaf's Issuer DN.
--   root_thumbprint             beside valid only: SHA-256 of the last
--                               certificate in WinVerifyTrust's own provider
--                               chain (the trust anchor the verdict rests on).
--   root_kind                   beside valid only: microsoft (one of four
--                               hard-coded Microsoft roots), public (a
--                               self-issued root in the registry AuthRoot
--                               store, where Microsoft Trusted Root Program
--                               roots land) or enterprise (anything else,
--                               including an unreadable chain).
--   executable_resolution       how the agent tied the executable to the app
--                               row: reviewed_target, display_icon or
--                               install_location_single_exe. Absent when no
--                               executable was resolved (the reason is in the
--                               row's errors) and from older agents. Stored as
--                               a bounded code, not an enum, so a new method
--                               needs no migration: it is diagnostic, never
--                               read as trust.
--
-- The four publisher columns are allowed only beside observed_signature_state
-- 'valid', like 0186's observed_authenticode_signer. NULL means not reported:
-- every existing row, every macOS row, an older agent, or a value the
-- extractor could not accept (it stores NULL rather than refusing the report).
--
-- Additive only. No existing column or row changes and nothing is backfilled:
-- observations are immutable per-report evidence and an old report carried
-- none of this. The signature_state CHECK is widened (a superset, so every
-- existing row still satisfies it). ADD COLUMN with no default is a
-- catalogue-only change (no table rewrite), the new CHECKs validate against
-- all-NULL columns, and the table's UPDATE/TRUNCATE-rejecting triggers do
-- not fire on DDL.
-- Lock: ACCESS EXCLUSIVE on software_observations for the ALTERs only,
-- milliseconds plus one CHECK validation scan, blocking the extractor's
-- observation inserts for that time (as 0186). Deploy before the binaries.

BEGIN;

ALTER TABLE software_observations
    ADD COLUMN IF NOT EXISTS observed_authenticode_signer_thumbprint TEXT,
    ADD COLUMN IF NOT EXISTS observed_authenticode_issuer TEXT,
    ADD COLUMN IF NOT EXISTS observed_authenticode_root_thumbprint TEXT,
    ADD COLUMN IF NOT EXISTS observed_authenticode_root_kind TEXT,
    ADD COLUMN IF NOT EXISTS observed_executable_resolution TEXT;

ALTER TABLE software_observations
    DROP CONSTRAINT IF EXISTS software_observations_signature_state_valid,
    ADD CONSTRAINT software_observations_signature_state_valid
        CHECK (observed_signature_state IS NULL
               OR observed_signature_state IN ('valid', 'invalid', 'unsigned', 'unknown')),
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_signer_thumbprint_valid,
    ADD CONSTRAINT software_observations_authenticode_signer_thumbprint_valid
        CHECK (observed_authenticode_signer_thumbprint IS NULL
               OR (observed_signature_state = 'valid'
                   AND observed_authenticode_signer_thumbprint ~ '^[0-9a-f]{64}$')),
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_issuer_valid,
    ADD CONSTRAINT software_observations_authenticode_issuer_valid
        CHECK (observed_authenticode_issuer IS NULL
               OR (observed_signature_state = 'valid'
                   AND char_length(observed_authenticode_issuer) BETWEEN 1 AND 512)),
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_root_thumbprint_valid,
    ADD CONSTRAINT software_observations_authenticode_root_thumbprint_valid
        CHECK (observed_authenticode_root_thumbprint IS NULL
               OR (observed_signature_state = 'valid'
                   AND observed_authenticode_root_thumbprint ~ '^[0-9a-f]{64}$')),
    DROP CONSTRAINT IF EXISTS software_observations_authenticode_root_kind_valid,
    ADD CONSTRAINT software_observations_authenticode_root_kind_valid
        CHECK (observed_authenticode_root_kind IS NULL
               OR (observed_signature_state = 'valid'
                   AND observed_authenticode_root_kind IN ('microsoft', 'public', 'enterprise'))),
    DROP CONSTRAINT IF EXISTS software_observations_executable_resolution_valid,
    ADD CONSTRAINT software_observations_executable_resolution_valid
        CHECK (observed_executable_resolution IS NULL
               OR observed_executable_resolution ~ '^[a-z][a-z0-9_]{0,63}$');

COMMENT ON COLUMN software_observations.observed_signature_state IS
    'PAT-2113/PAT-2116. Windows apps[].installation_evidence.signature_state: valid, invalid (digest mismatch), unsigned (no embedded signature and a proven clean catalog miss) or unknown (anything else). NULL = not reported (macOS, older agent, or an unrecognised value).';
COMMENT ON COLUMN software_observations.observed_authenticode_signer_thumbprint IS
    'PAT-2116. Windows installation_evidence.signer_thumbprint: leaf certificate SHA-256, lowercase hex. Only beside valid. Stored for audit; renews with the certificate, so it is not a publisher key.';
COMMENT ON COLUMN software_observations.observed_authenticode_issuer IS
    'PAT-2116. Windows installation_evidence.issuer: leaf certificate Issuer DN. Only beside valid.';
COMMENT ON COLUMN software_observations.observed_authenticode_root_thumbprint IS
    'PAT-2116. Windows installation_evidence.root_thumbprint: SHA-256 of the trust anchor in WinVerifyTrust''s provider chain, lowercase hex. Only beside valid.';
COMMENT ON COLUMN software_observations.observed_authenticode_root_kind IS
    'PAT-2116. Windows installation_evidence.root_kind: microsoft, public (registry AuthRoot store) or enterprise (anything else; never independently verifiable). Only beside valid. NULL beside valid = an agent older than updater #668.';
COMMENT ON COLUMN software_observations.observed_executable_resolution IS
    'PAT-2116. Windows installation_evidence.executable_resolution: how the executable was tied to the app row (reviewed_target, display_icon, install_location_single_exe). Diagnostic only; never read as trust. NULL = not resolved, or an older agent.';

INSERT INTO schema_migrations (version) VALUES ('0188_software_observation_authenticode_publisher')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
