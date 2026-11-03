-- patched.im — 0134_auto_updates_pass_on_os_default_rollback.sql
-- Reverses 0134_auto_updates_pass_on_os_default.sql (PAT-1780).
--
-- Restores cis_win_18_9_102_auto_updates to its pre-0134 state:
-- treat_not_configured_as = NULL (falls back to treat_unknown_as = 'fail',
-- unchanged throughout) and the 0019-seeded description. Safe to run at any
-- time; this rule carries no other migration-owned state.

BEGIN;

UPDATE compliance_rules
SET treat_not_configured_as = NULL,
    description = 'CIS §18.9.102. NoAutoUpdate GPO must be absent or 0; AU options ≥ 3. Unpatched Windows devices are the primary vector for ransomware lateral movement in SME estates.'
WHERE rule_key = 'cis_win_18_9_102_auto_updates'
  AND benchmark = 'CIS Microsoft Windows 11'
  AND treat_unknown_as = 'fail'
  AND treat_not_configured_as = 'pass';

DELETE FROM schema_migrations WHERE version = '0134_auto_updates_pass_on_os_default';

COMMIT;
