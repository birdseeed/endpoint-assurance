-- 0148: persist report type on immutable report evidence and make customer
-- schedules independent per tenant and report type (PAT-1847).
--
-- Defaults are retained for zero-downtime compatibility with an older API
-- binary during rollout. Existing rows and the former singleton customer
-- schedule are therefore backfilled as executive-summary without UPDATEs,
-- which also avoids tripping the issued-report immutability trigger.

BEGIN;

ALTER TABLE report_records
    ADD COLUMN IF NOT EXISTS report_type TEXT NOT NULL DEFAULT 'executive-summary';

ALTER TABLE report_records
    DROP CONSTRAINT IF EXISTS report_records_report_type_valid;
ALTER TABLE report_records
    ADD CONSTRAINT report_records_report_type_valid CHECK (report_type IN (
        'executive-summary', 'cis-compliance', 'cve-report', 'patch-status',
        'stale-endpoints', 'cert-expiry', 'software-inventory',
        'app-policy-drift', 'browser-extensions', 'edr-coverage',
        'device-health', 'encryption-posture', 'local-admin',
        'device-compliance'
    ));

ALTER TABLE portal_report_schedules
    ADD COLUMN IF NOT EXISTS report_type TEXT NOT NULL DEFAULT 'executive-summary';

ALTER TABLE portal_report_schedules
    DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules
    ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
        'executive-summary', 'cis-compliance', 'cve-report', 'patch-status',
        'stale-endpoints', 'cert-expiry', 'edr-coverage',
        'encryption-posture', 'local-admin'
    ));

ALTER TABLE portal_report_schedules
    DROP CONSTRAINT IF EXISTS portal_report_schedules_pkey;
ALTER TABLE portal_report_schedules
    ADD PRIMARY KEY (tenant_id, report_type);

DROP INDEX IF EXISTS idx_report_records_schedule_slot;
CREATE UNIQUE INDEX idx_report_records_portal_schedule_slot
    ON report_records (tenant_id, report_type, schedule_slot)
    WHERE source = 'portal' AND schedule_slot IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_report_schedules_due_type
    ON portal_report_schedules (next_run_at, report_type)
    WHERE enabled;

COMMENT ON COLUMN report_records.report_type IS
    'Stable registry type of the immutable report evidence. Existing records are executive-summary.';
COMMENT ON COLUMN portal_report_schedules.report_type IS
    'Customer-facing report registry type. One schedule exists per tenant and type.';

INSERT INTO schema_migrations (version) VALUES ('0148_report_type_registry')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
