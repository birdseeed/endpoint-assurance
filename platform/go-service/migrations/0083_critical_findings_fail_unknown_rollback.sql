-- patched.im — 0083_critical_findings_fail_unknown_rollback.sql
-- Reverses 0083_critical_findings_fail_unknown.sql (PAT-913, Option B).
--
-- Restores the four findings-based rules to treat_unknown_as = 'pass'. Note this
-- reinstates the fail-open behaviour: an unattested agent will again silently
-- pass a critical full-disk-encryption control. Only roll back alongside a
-- revert of the buildSignalsMap change, otherwise attested-clean devices still
-- pass (they carry a positive "Pass" signal from controls_assessed) but
-- unattested devices revert to a false pass.

BEGIN;

UPDATE compliance_rules
SET treat_unknown_as = 'pass'
WHERE rule_key IN (
    'patched_macos_disk_encryption_off',
    'patched_win_disk_encryption_off',
    'patched_macos_removable_storage_unencrypted',
    'patched_win_removable_storage_unencrypted'
)
  AND treat_unknown_as = 'fail';

DELETE FROM schema_migrations WHERE version = '0083_critical_findings_fail_unknown';

COMMIT;
