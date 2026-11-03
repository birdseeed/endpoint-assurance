-- patched.im - 0082_report_records_schedule_slot_rollback.sql
-- Reverses 0082_report_records_schedule_slot.sql.
BEGIN;

DROP INDEX IF EXISTS idx_report_records_schedule_slot;

ALTER TABLE report_records
    DROP COLUMN IF EXISTS schedule_slot;

DELETE FROM schema_migrations WHERE version = '0082_report_records_schedule_slot';

COMMIT;
