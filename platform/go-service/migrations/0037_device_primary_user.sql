-- patched.im — 0037_device_primary_user.sql
-- Adds primary-user attribution columns to the devices table (PAT-116).
-- These are populated by the extractor from the primary_user block in the
-- inventory payload. All columns are nullable — existing devices retain NULL
-- until the next collection cycle from an updated agent.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0037_device_primary_user.sql
--
-- Rollback: 0037_device_primary_user_rollback.sql

BEGIN;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS primary_user_account     TEXT,
  ADD COLUMN IF NOT EXISTS primary_user_display     TEXT,
  ADD COLUMN IF NOT EXISTS primary_user_last_seen_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS primary_user_source      TEXT;

INSERT INTO schema_migrations (version) VALUES ('0037_device_primary_user');

COMMIT;
