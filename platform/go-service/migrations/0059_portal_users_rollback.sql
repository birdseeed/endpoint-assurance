-- Rollback for 0059_portal_users.sql
BEGIN;

DROP INDEX IF EXISTS idx_report_records_source;
ALTER TABLE report_records DROP COLUMN IF EXISTS source;

DROP TABLE IF EXISTS portal_access_log;
DROP TABLE IF EXISTS portal_users;

DELETE FROM schema_migrations WHERE version = '0059_portal_users';

COMMIT;
