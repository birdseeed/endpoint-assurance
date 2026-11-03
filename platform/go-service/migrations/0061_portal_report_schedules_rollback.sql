-- Rollback for 0061_portal_report_schedules (PAT-703).

BEGIN;

DROP TABLE IF EXISTS portal_report_schedules;

DELETE FROM schema_migrations WHERE version = '0061_portal_report_schedules';

COMMIT;
