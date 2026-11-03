-- 0065: tenant health score columns (PAT-677).
--
-- Adds the computed health-score columns and the payment_failed signal that
-- feeds the health-score weighting model.
--
--   health_score             — weighted health score 0–100; NULL until the
--                              first nightly recompute run.
--   health_bucket            — human-readable tier: "healthy" | "watch" |
--                              "at_risk"; NULL until first recompute.
--   health_score_computed_at — timestamp of the most recent score computation,
--                              for freshness tracking and alerting (PAT-678).
--   payment_failed           — true when Stripe billing status is past_due or
--                              suspended; fed into the health-score model as a
--                              −15 penalty.  Updated externally (Stripe webhook
--                              or admin endpoint; PAT-679).
--
-- Weighting model (v1 — see internal/healthsignals/score.go for the canonical
-- implementation):
--
--   health_score = 100
--     − 30  × ingest_stale
--     − 20  × (dashboard_logins_last_30d == 0)   [skipped for "report" tier]
--     − 0.5 × max(0, compliance_score_30d_ago − compliance_score_current)
--     − 15  × payment_failed
--     − 10  × (days_since_last_ingest > 7)
--     + 10  × (compliance_score_current > 80)
--   CLAMP [0, 100]
--
--   Buckets:
--     75–100 → "healthy"
--     50–74  → "watch"
--     0–49   → "at_risk"

BEGIN;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS health_score             INT
        CHECK (health_score BETWEEN 0 AND 100),
    ADD COLUMN IF NOT EXISTS health_bucket            TEXT
        CHECK (health_bucket IN ('healthy', 'watch', 'at_risk')),
    ADD COLUMN IF NOT EXISTS health_score_computed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS payment_failed           BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN tenants.health_score IS
    'Weighted health score 0–100 (PAT-677). NULL until first nightly recompute.';
COMMENT ON COLUMN tenants.health_bucket IS
    '"healthy" (≥75), "watch" (50–74), or "at_risk" (<50). NULL until first run.';
COMMENT ON COLUMN tenants.health_score_computed_at IS
    'Timestamp of the most recent health-score computation (PAT-677).';
COMMENT ON COLUMN tenants.payment_failed IS
    'True when Stripe billing is past_due or suspended. Feeds −15 health-score penalty.';

INSERT INTO schema_migrations (version) VALUES ('0065_tenant_health_score')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
