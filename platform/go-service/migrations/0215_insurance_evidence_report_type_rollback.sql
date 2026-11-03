-- Roll the API binary back first. Issued insurance evidence reports and their
-- schedules are refused because the restored 0210 constraints cannot
-- represent them; export and remove them deliberately before rolling back.
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM report_records WHERE report_type='insurance-evidence') THEN
        RAISE EXCEPTION 'cannot roll back 0215 while insurance evidence reports exist';
    END IF;
    IF EXISTS (SELECT 1 FROM portal_report_schedules WHERE report_type='insurance-evidence') THEN
        RAISE EXCEPTION 'cannot roll back 0215 while insurance evidence schedules exist';
    END IF;
END $$;

ALTER TABLE report_records DROP CONSTRAINT IF EXISTS report_records_report_type_valid;
ALTER TABLE report_records ADD CONSTRAINT report_records_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'software-inventory','app-policy-drift','browser-extensions','edr-coverage','device-health',
    'encryption-posture','local-admin','device-compliance','new-software','software-drift',
    'approved-software','ai-tooling-evidence'
));
ALTER TABLE portal_report_schedules DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'edr-coverage','encryption-posture','local-admin','new-software','software-drift','approved-software',
    'ai-tooling-evidence'
));

DELETE FROM schema_migrations WHERE version='0215_insurance_evidence_report_type';
COMMIT;
