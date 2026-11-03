-- 0063: tenant health signal columns (PAT-676, platform half only).
--
-- These columns support the dashboard-login tracking and compliance-score
-- trending signals that the internal health-signals recompute routine updates
-- nightly.
--
--   last_dashboard_login_at     — last time any portal user for this tenant
--                                 successfully authenticated (set by
--                                 PUT /admin/tenant/{id}/signal on :8081).
--   dashboard_logins_last_30d   — rolling 30-day login count; reset to 0 each
--                                 time the recompute routine runs its 30-day
--                                 window. The signal endpoint increments this
--                                 directly; the recompute routine resets it once
--                                 per 30-day cycle.
--   compliance_score_30d_ago    — compliance_score_current snapshot taken 30
--                                 days earlier; NULL until the first 30-day
--                                 recompute cycle completes.
--   compliance_score_current    — latest computed compliance score (integer
--                                 percentage 0–100); NULL until the first
--                                 recompute run.
--   days_since_last_ingest      — computed by the nightly recompute: days since
--                                 MAX(device.last_seen) for this tenant. NULL
--                                 when no devices have ever reported.
--   ingest_stale                — true when days_since_last_ingest > 14; the
--                                 dashboard uses this as a red-flag indicator.

BEGIN;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS last_dashboard_login_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dashboard_logins_last_30d   INT         NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS compliance_score_30d_ago    INT,
    ADD COLUMN IF NOT EXISTS compliance_score_current    INT,
    ADD COLUMN IF NOT EXISTS days_since_last_ingest      INT,
    ADD COLUMN IF NOT EXISTS ingest_stale                BOOLEAN     NOT NULL DEFAULT false;

INSERT INTO schema_migrations (version) VALUES ('0063_tenant_health_signals')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
