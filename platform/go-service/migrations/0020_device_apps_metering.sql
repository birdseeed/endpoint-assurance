-- patched.im — 0020_device_apps_metering.sql
-- Software metering: per-app usage signals collected from macOS Spotlight
-- metadata (kMDItemLastUsedDate / kMDItemUseCount). Additive, nullable columns;
-- NULL means "no recorded usage" — never launched, or metering unavailable on
-- the endpoint (e.g. Spotlight indexing disabled). See ADR-0005.
--
-- launch_count is the LIFETIME cumulative launch count, not a windowed figure.
-- Windowed activity must be derived server-side by diffing successive readings.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0020_device_apps_metering.sql

BEGIN;

ALTER TABLE device_apps ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE device_apps ADD COLUMN IF NOT EXISTS launch_count INTEGER;

-- Per-device metering provenance: tells whether a NULL app usage value means
-- "genuinely never launched" or "no data collected". Values emitted by the
-- agent: 'ok' (reliable read) | 'spotlight_disabled' | 'no_user_session'.
-- NULL = agent didn't report it (older/non-macOS agent). Only 'ok' permits
-- reading a NULL last_used_at as evidence of non-use.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS metering_status TEXT;

-- "Apps not used since X" / "installed but unused" is the primary metering
-- query; index last_used_at so those scans stay cheap as device_apps grows.
CREATE INDEX IF NOT EXISTS idx_device_apps_last_used_at
    ON device_apps(last_used_at);

INSERT INTO schema_migrations (version) VALUES ('0020_device_apps_metering');

COMMIT;
