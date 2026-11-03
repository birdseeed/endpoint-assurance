-- Reverses 0174_compliance_rules_parity.sql.
--
-- Deletes only the rows this migration inserted, identified by the trailing
-- '[PAT-2059/0174 backfill]' marker this migration wrote into `description`
-- (compliance_rules has no dedicated provenance/notes column -- see 0169's
-- identical `notes` marker on app_cpe_mappings for the same problem). A
-- database where 0033 already seeded these four rule_keys keeps its original
-- rows untouched: 0174's insert was skipped there by ON CONFLICT DO NOTHING,
-- so those rows were never marked and this rollback matches none of them.
--
-- If any compliance_evaluations row already references one of these rules,
-- the DELETE fails closed on the compliance_evaluations.rule_id foreign key
-- (no ON DELETE clause in 0003) rather than silently discarding evaluation
-- history. Resolve that -- typically by leaving 0174 applied -- before
-- retrying this rollback.

BEGIN;

DELETE FROM compliance_rules
WHERE rule_key IN (
    'patched_macos_disk_encryption_off',
    'patched_win_disk_encryption_off',
    'patched_macos_removable_storage_unencrypted',
    'patched_win_removable_storage_unencrypted'
)
  AND description LIKE '%[PAT-2059/0174 backfill]';

DELETE FROM schema_migrations WHERE version = '0174_compliance_rules_parity';

COMMIT;
