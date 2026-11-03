-- patched.im — 0131_treat_not_configured_as.sql
-- PAT-1767: three-state compliance signal contract (server half).
--
-- Every compliance signal value in the /v1/inventory payload is now exactly
-- one of: a real value (unchanged); the exact string "NotConfigured" (the
-- read succeeded and the setting is genuinely absent — no policy key, no
-- managed pref, no registry value); or null / the exact string "Unknown"
-- (the read itself failed). Today both agents conflate "absent" and "failed"
-- into null/"Unknown", so a rule's single treat_unknown_as has to pick one
-- outcome for both. This migration adds the second knob so a rule can treat
-- them differently once the agents start emitting "NotConfigured" (updater
-- PAT-1767, both platforms, rolling out after this server change).
--
-- treat_not_configured_as is nullable and defaults to nothing: a NULL value
-- means "use this rule's treat_unknown_as", so every existing rule's outcome
-- is unchanged until someone deliberately sets it. The evaluator
-- (internal/evaluator/evaluator.go) applies that fallback in exactly one
-- place.
--
-- Deliberate exception (the only outcome change in this migration): the six
-- Windows NIST Schannel TLS rules and nist_win_si16_mandatory_aslr
-- (migrations/0041) were seeded with treat_unknown_as = 'pass' on the theory
-- that "we don't know" means "OS default is in effect, which is compliant".
-- That conflates two different things: a genuinely absent registry value
-- (OS default — pass is the right call) and a read that threw (we have no
-- idea what the OS default even is here — pass is a false positive). Split
-- them:
--   - treat_not_configured_as = 'pass'   (absent = OS default, matches the
--     original 'Unknown = OS default; treat as pass' rule comments)
--   - treat_unknown_as        = 'fail'   (closest non-pass outcome the
--     evaluator supports for "could not read it"; there is no
--     unknown/not_evaluated/error option in the treat_unknown_as domain —
--     see the CHECK constraint on this column — so 'fail' is what's left)
--
-- The Windows agent does not yet distinguish "absent" from "read threw" for
-- these seven signals — it sends the literal string "Unknown" for both,
-- exactly as before this migration. The evaluator does not special-case
-- "Unknown" (it is a real observed value that falls through to the
-- comparator, same as ever), so these seven rules will simply read as
-- not-pass ("Unknown" != "Yes" under the eq comparator) on any un-upgraded
-- agent, same as they effectively already did — treat_unknown_as='pass' only
-- ever applied to a genuinely MISSING signal_key (an agent old enough to not
-- send the key at all), not to a present "Unknown" value. Once the Windows
-- agent is upgraded to send "NotConfigured" for the truly-absent case, these
-- seven rules will correctly pass on OS default and fail on a real read
-- failure.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0131_treat_not_configured_as.sql

BEGIN;

-- ============================================================================
-- 1. New column
-- ============================================================================

ALTER TABLE compliance_rules
    ADD COLUMN treat_not_configured_as TEXT NULL
        CHECK (treat_not_configured_as IN ('pass', 'fail', 'not_applicable'));

COMMENT ON COLUMN compliance_rules.treat_not_configured_as IS
    'Status to emit when the signal is the exact string "NotConfigured" (read '
    'succeeded, setting genuinely absent). NULL means "use treat_unknown_as" '
    '(PAT-1767) — the evaluator applies this fallback in one place. Same '
    'value domain as treat_unknown_as.';

-- ============================================================================
-- 2. Deliberate exception: split the 6 TLS rules + mandatory ASLR
-- ============================================================================

UPDATE compliance_rules
SET treat_not_configured_as = 'pass',
    treat_unknown_as = 'fail'
WHERE rule_key IN (
    'nist_win_sc13_tls10_client_disabled',
    'nist_win_sc13_tls10_server_disabled',
    'nist_win_sc13_tls11_client_disabled',
    'nist_win_sc13_tls11_server_disabled',
    'nist_win_sc13_tls12_client_enabled',
    'nist_win_sc13_tls12_server_enabled',
    'nist_win_si16_mandatory_aslr'
)
  AND benchmark = 'NIST SP 800-53 Rev 5'
  AND treat_unknown_as = 'pass';

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0131_treat_not_configured_as')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
