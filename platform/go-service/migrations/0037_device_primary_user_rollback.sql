-- patched.im — 0037_device_primary_user_rollback.sql
-- Rolls back 0037_device_primary_user.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0037_device_primary_user_rollback.sql

BEGIN;

ALTER TABLE devices
  DROP COLUMN IF EXISTS primary_user_account,
  DROP COLUMN IF EXISTS primary_user_display,
  DROP COLUMN IF EXISTS primary_user_last_seen_at,
  DROP COLUMN IF EXISTS primary_user_source;

DELETE FROM schema_migrations WHERE version = '0037_device_primary_user';

COMMIT;
