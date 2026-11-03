-- PAT-343: consent-gated software usage tracking.
-- app_usage_daily: per-device, per-app daily summaries, 30-day rolling window.
-- Only populated when tenants.usage_tracking_enabled = true.
-- Retention: 90 days; prune job to be added separately.
--
-- Rollback: migrations/0051_app_usage_daily_rollback.sql

BEGIN;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS usage_tracking_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tenants.usage_tracking_enabled IS
    'When true, agents include app_usage[] in the inventory payload; the platform upserts daily summaries into app_usage_daily. Default false — privacy-safe. Set via PUT /admin/tenants/{tenantID}/usage-tracking.';

CREATE TABLE IF NOT EXISTS app_usage_daily (
    id                BIGSERIAL    PRIMARY KEY,
    tenant_id         UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID         NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    bundle_id_or_name TEXT         NOT NULL,
    platform          TEXT         NOT NULL CHECK (platform IN ('macos', 'windows')),
    date              DATE         NOT NULL,
    last_used_at      TIMESTAMPTZ,
    launch_count_today INT,
    CONSTRAINT app_usage_daily_unique UNIQUE (tenant_id, device_id, bundle_id_or_name, platform, date)
);

CREATE INDEX IF NOT EXISTS idx_app_usage_daily_tenant_date
    ON app_usage_daily(tenant_id, date DESC);

CREATE INDEX IF NOT EXISTS idx_app_usage_daily_device
    ON app_usage_daily(device_id);

COMMENT ON TABLE app_usage_daily IS
    'PAT-343: per-device, per-app daily usage summaries. One row per (tenant, device, app, date). Retained 90 days. Only populated when tenants.usage_tracking_enabled = true.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app_usage_daily TO patched;
GRANT USAGE, SELECT ON SEQUENCE app_usage_daily_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0051_app_usage_daily');

COMMIT;
