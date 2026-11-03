-- 0215: allow the cyber insurance evidence pack as a report type (PAT-2258).
-- The report registry (internal/report/registry.go) gains insurance-evidence;
-- report_records and portal_report_schedules constrain report_type to the
-- registry's types, so both lists are restated from 0210 plus the new type.
-- No data changes.
BEGIN;

ALTER TABLE report_records DROP CONSTRAINT IF EXISTS report_records_report_type_valid;
ALTER TABLE report_records ADD CONSTRAINT report_records_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'software-inventory','app-policy-drift','browser-extensions','edr-coverage','device-health',
    'encryption-posture','local-admin','device-compliance','new-software','software-drift',
    'approved-software','ai-tooling-evidence','insurance-evidence'
));
ALTER TABLE portal_report_schedules DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'edr-coverage','encryption-posture','local-admin','new-software','software-drift','approved-software',
    'ai-tooling-evidence','insurance-evidence'
));

INSERT INTO schema_migrations(version) VALUES ('0215_insurance_evidence_report_type')
ON CONFLICT(version) DO NOTHING;
COMMIT;
