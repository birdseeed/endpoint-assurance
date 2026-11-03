-- Rollback for 0063_tenant_health_signals (PAT-676).

BEGIN;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS last_dashboard_login_at,
    DROP COLUMN IF EXISTS dashboard_logins_last_30d,
    DROP COLUMN IF EXISTS compliance_score_30d_ago,
    DROP COLUMN IF EXISTS compliance_score_current,
    DROP COLUMN IF EXISTS days_since_last_ingest,
    DROP COLUMN IF EXISTS ingest_stale;

DELETE FROM schema_migrations WHERE version = '0063_tenant_health_signals';

COMMIT;
