-- patched.im — rollback for 0143_device_dispositions.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_device_lifecycle_findings_append_only_truncate ON device_lifecycle_findings;
DROP TRIGGER IF EXISTS trg_device_lifecycle_findings_append_only ON device_lifecycle_findings;
DROP FUNCTION IF EXISTS reject_device_lifecycle_findings_truncate();
DROP FUNCTION IF EXISTS reject_device_lifecycle_findings_mutation();
DROP TABLE IF EXISTS device_lifecycle_findings;

DROP TRIGGER IF EXISTS trg_device_dispositions_append_only_truncate ON device_dispositions;
DROP TRIGGER IF EXISTS trg_device_dispositions_append_only ON device_dispositions;
DROP FUNCTION IF EXISTS reject_device_dispositions_truncate();
DROP FUNCTION IF EXISTS guard_device_dispositions_mutation();
DROP TABLE IF EXISTS device_dispositions;

DELETE FROM schema_migrations WHERE version = '0143_device_dispositions';

COMMIT;
