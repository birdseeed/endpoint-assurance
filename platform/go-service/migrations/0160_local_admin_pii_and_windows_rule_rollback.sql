-- Rollback for PAT-1974 (0160_local_admin_pii_and_windows_rule.sql).
--
-- Deletes the seeded Windows rule and restores the macOS rule's prior
-- pii_observed text. Restoring the OLD text is a deliberate exception to
-- "rollback undoes forward, nothing more": the whole point of 0160 was that
-- the old text was already wrong before this migration ran, so leaving the
-- corrected text in place post-rollback would silently keep this
-- migration's documentation change live while removing its rule seed. A
-- rollback here is expected to mean "we are reverting this ticket", not
-- "keep half of it".
--
-- Deleting the Windows rule row is safe: no compliance_evaluations or
-- tenant_rules rows can reference a T1 rule_key that was only ever seeded in
-- the migration this rolls back (T1 rules need no tenant_rules row, and
-- compliance_evaluations rows are derived/re-extractable, same posture as
-- every other rollback in this migration series).

BEGIN;

DELETE FROM compliance_rules WHERE rule_key = 'cis_win_5_8_local_admin_count';

UPDATE compliance_rules
SET pii_observed = 'Reports the count of local admin group members (excluding root). Does not report account names — count only.'
WHERE signal_key = 'local_admin_count' AND platform = 'macos';

DELETE FROM schema_migrations WHERE version = '0160_local_admin_pii_and_windows_rule';

COMMIT;
