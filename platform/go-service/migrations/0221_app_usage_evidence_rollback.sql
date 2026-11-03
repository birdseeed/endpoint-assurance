-- Roll back binaries first. These columns are derived from immutable raw payloads.
BEGIN;
ALTER TABLE device_apps DROP COLUMN IF EXISTS usage_evidence_complete;
ALTER TABLE device_apps DROP COLUMN IF EXISTS usage_evidence_at;
ALTER TABLE device_apps DROP COLUMN IF EXISTS usage_evidence;
ALTER TABLE devices DROP COLUMN IF EXISTS metering_record_count;
ALTER TABLE devices DROP COLUMN IF EXISTS metering_user_hive_count;
DELETE FROM schema_migrations WHERE version = '0221_app_usage_evidence';
COMMIT;
