-- patched.im — 0131_treat_not_configured_as_rollback.sql
-- Reverses 0131_treat_not_configured_as.sql (PAT-1767).
--
-- Restores the 7 Windows rules to treat_unknown_as = 'pass' (their pre-0131
-- value) and drops the treat_not_configured_as column. Safe to run at any
-- time: the column carries no data that isn't reconstructible from the rule
-- pack, and no other table references it by foreign key.

BEGIN;

UPDATE compliance_rules
SET treat_unknown_as = 'pass'
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
  AND treat_not_configured_as = 'pass'
  AND treat_unknown_as = 'fail';

ALTER TABLE compliance_rules DROP COLUMN IF EXISTS treat_not_configured_as;

DELETE FROM schema_migrations WHERE version = '0131_treat_not_configured_as';

COMMIT;
