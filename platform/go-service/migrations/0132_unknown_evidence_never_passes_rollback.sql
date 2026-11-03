-- patched.im — 0132_unknown_evidence_never_passes_rollback.sql
-- Reverses 0132_unknown_evidence_never_passes.sql.
--
-- Restores the two rules to their pre-0132 state: treat_unknown_as = 'pass',
-- treat_not_configured_as = NULL. Safe to run at any time: the column
-- carries no data that isn't reconstructible from the rule pack, and no
-- other table references it by foreign key. Guarded by the exact post-0132
-- values so this is a no-op if a hand-edit already changed either row.

BEGIN;

UPDATE compliance_rules
SET treat_unknown_as = 'pass'
WHERE rule_key = 'nist_win_ac2_laps_enrolled'
  AND benchmark = 'NIST SP 800-53 Rev 5'
  AND treat_unknown_as = 'fail'
  AND treat_not_configured_as IS NULL;

UPDATE compliance_rules
SET treat_not_configured_as = NULL,
    treat_unknown_as = 'pass'
WHERE rule_key = 'cis_macos_2_3_4_2_time_machine_encrypted'
  AND benchmark = 'CIS Apple macOS'
  AND treat_unknown_as = 'fail'
  AND treat_not_configured_as = 'pass';

DELETE FROM schema_migrations WHERE version = '0132_unknown_evidence_never_passes';

COMMIT;
