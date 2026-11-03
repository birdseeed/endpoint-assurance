-- patched.im — 0031_device_report_digests_rollback.sql
-- Rolls back 0031_device_report_digests.sql (PAT-473).
BEGIN;
DROP TABLE IF EXISTS device_report_digests CASCADE;
DELETE FROM schema_migrations WHERE version = '0031_device_report_digests';
COMMIT;
