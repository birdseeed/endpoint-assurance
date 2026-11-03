BEGIN;

DROP TABLE IF EXISTS report_download_tokens;
DROP TABLE IF EXISTS report_records;
DROP TABLE IF EXISTS report_schedules;
DROP TABLE IF EXISTS delivery_contacts;

DELETE FROM schema_migrations WHERE version = '0052_report_delivery';

COMMIT;
