BEGIN;
DROP TABLE IF EXISTS app_usage_daily;
ALTER TABLE tenants DROP COLUMN IF EXISTS usage_tracking_enabled;
DELETE FROM schema_migrations WHERE version = '0051_app_usage_daily';
COMMIT;
