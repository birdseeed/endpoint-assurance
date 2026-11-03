-- Rollback for 0064_tenant_trial (PAT-668).

BEGIN;

DROP INDEX IF EXISTS idx_tenants_trial_email;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS is_trial,
    DROP COLUMN IF EXISTS trial_expires_at,
    DROP COLUMN IF EXISTS trial_email,
    DROP COLUMN IF EXISTS trial_device_cap;

DELETE FROM schema_migrations WHERE version = '0064_tenant_trial';

COMMIT;
