-- Rollback for 0065_tenant_health_score.

BEGIN;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS health_score,
    DROP COLUMN IF EXISTS health_bucket,
    DROP COLUMN IF EXISTS health_score_computed_at,
    DROP COLUMN IF EXISTS payment_failed;

DELETE FROM schema_migrations WHERE version = '0065_tenant_health_score';

COMMIT;
