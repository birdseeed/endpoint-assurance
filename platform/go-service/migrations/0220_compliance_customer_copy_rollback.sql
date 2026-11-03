-- Restore only descriptions that 0220 captured and cleaned. Run this before
-- 0174's rollback so that migration can recognise its own inserted rules.
-- UUID, identity and exact-description guards preserve recreated rules and edits.
BEGIN;

DO $$
BEGIN
    IF to_regclass('public._migration_0220_compliance_copy_backup') IS NOT NULL THEN
        UPDATE compliance_rules AS rule
        SET description = backup.original_description
        FROM _migration_0220_compliance_copy_backup AS backup
        WHERE rule.id = backup.rule_id
          AND rule.rule_key = backup.rule_key
          AND rule.benchmark = backup.benchmark
          AND rule.benchmark_version = backup.benchmark_version
          AND rule.description = backup.customer_description
          AND EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0220_compliance_customer_copy');

        -- Only this migration's private rollback records are removed.
        DROP TABLE _migration_0220_compliance_copy_backup;
    END IF;
END;
$$;

DELETE FROM schema_migrations WHERE version = '0220_compliance_customer_copy';

COMMIT;
