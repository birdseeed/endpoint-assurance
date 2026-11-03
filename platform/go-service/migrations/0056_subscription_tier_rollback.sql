-- PAT-397 rollback: drop subscription_tier column and audit table.
--
-- Apply ONLY to undo 0056_subscription_tier.sql.
-- Safe when no rows exist in tenant_tier_changes; data loss if they do.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0056_subscription_tier_rollback.sql

BEGIN;

DROP TABLE IF EXISTS tenant_tier_changes;

ALTER TABLE tenants
  DROP COLUMN IF EXISTS subscription_tier;

DELETE FROM schema_migrations WHERE version = '0056_subscription_tier';

COMMIT;
