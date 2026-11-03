-- Roll back PAT-1847 report typing. This is intentionally loss-aware: it
-- refuses while a tenant has more than one schedule or any typed report
-- evidence exists, because either case would discard customer data.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT tenant_id FROM portal_report_schedules
        GROUP BY tenant_id HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0148 while tenants have multiple report schedules';
    END IF;
    IF EXISTS (
        SELECT 1 FROM report_records
        WHERE report_type <> 'executive-summary'
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0148 while typed report evidence exists';
    END IF;
END;
$$;

DROP INDEX IF EXISTS idx_portal_report_schedules_due_type;
DROP INDEX IF EXISTS idx_report_records_portal_schedule_slot;
CREATE INDEX IF NOT EXISTS idx_report_records_schedule_slot
    ON report_records (tenant_id, schedule_slot)
    WHERE schedule_slot IS NOT NULL;

ALTER TABLE portal_report_schedules DROP CONSTRAINT IF EXISTS portal_report_schedules_pkey;
ALTER TABLE portal_report_schedules ADD PRIMARY KEY (tenant_id);
ALTER TABLE portal_report_schedules DROP COLUMN IF EXISTS report_type;
ALTER TABLE report_records DROP COLUMN IF EXISTS report_type;

DELETE FROM schema_migrations WHERE version = '0148_report_type_registry';

COMMIT;
