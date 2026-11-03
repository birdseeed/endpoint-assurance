-- Rollback for 0183_software_governance_alerts (PAT-2009)
--
-- Roll the API and extractor binaries back first: both write these tables.
-- The rollback refuses while any report or schedule of a PAT-2009 report type
-- exists, because restoring the 0148 report type constraints would reject
-- those rows.
--
-- Dropping them loses the alert history, the per-tenant notification
-- settings (a tenant that turned the unapproved alert off gets it back on at
-- the default) and the recorded weekly trend, which cannot be rebuilt.
-- Webhook deliveries already enqueued in webhook_deliveries (0055) are not
-- touched and will still be sent. Export first if the history matters:
--   psql ... -c "\copy software_unapproved_alerts TO 'software_unapproved_alerts.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0183_software_governance_alerts_rollback.sql

BEGIN;

-- Refuse rather than discard issued report evidence or customer schedules of
-- the PAT-2009 report types (the 0148 rollback takes the same position).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM report_records
               WHERE report_type IN ('new-software', 'software-drift', 'approved-software')) THEN
        RAISE EXCEPTION 'cannot roll back 0183 while PAT-2009 report evidence exists';
    END IF;
    IF EXISTS (SELECT 1 FROM portal_report_schedules
               WHERE report_type IN ('new-software', 'software-drift', 'approved-software')) THEN
        RAISE EXCEPTION 'cannot roll back 0183 while PAT-2009 report schedules exist';
    END IF;
END;
$$;

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
    DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules
    ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
        'executive-summary', 'cis-compliance', 'cve-report', 'patch-status',
        'stale-endpoints', 'cert-expiry', 'edr-coverage',
        'encryption-posture', 'local-admin'
    ));

DROP TABLE IF EXISTS software_governance_weekly;
DROP TABLE IF EXISTS software_unapproved_alerted_devices;
DROP TABLE IF EXISTS software_unapproved_alerts;
DROP TABLE IF EXISTS software_unapproved_episodes;
DROP TABLE IF EXISTS tenant_software_notification_settings;

DELETE FROM schema_migrations WHERE version = '0183_software_governance_alerts';

COMMIT;
