-- patched.im — 0133_mandatory_aslr_fail_closed_rollback.sql
-- Reverses 0133_mandatory_aslr_fail_closed.sql (PAT-1770).
--
-- Restores nist_win_si16_mandatory_aslr to its post-0131, pre-0133 state:
-- treat_not_configured_as = 'pass' and the 0041-seeded title/description
-- (the ones that named MoveImages and justified pass via "Win11 has ASLR on
-- by default"). Safe to run at any time; this rule carries no other
-- migration-owned state.

BEGIN;

UPDATE compliance_rules
SET treat_not_configured_as = 'pass',
    title = 'Mandatory ASLR (ForceRelocateImages) enabled system-wide',
    description = 'NIST SI-16. Mandatory ASLR forces address-space randomization for all images, including those that do not opt in via the /DYNAMICBASE linker flag. Controlled via Windows Exploit Protection (MoveImages registry DWORD non-zero). Unknown = not explicitly configured; treat as pass since Win11 has ASLR on by default.'
WHERE rule_key = 'nist_win_si16_mandatory_aslr'
  AND benchmark = 'NIST SP 800-53 Rev 5'
  AND treat_not_configured_as = 'fail'
  AND treat_unknown_as = 'fail';

DELETE FROM schema_migrations WHERE version = '0133_mandatory_aslr_fail_closed';

COMMIT;
