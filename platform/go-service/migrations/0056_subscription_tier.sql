-- PAT-397: Admin single tier-switch endpoint — subscription_tier column + audit log.
--
-- Adds `subscription_tier` to `tenants` as the commercial source of truth for
-- a tenant's product tier (Report / Patch / Full Endpoint Management).
--
-- This is distinct from:
--   tenants.tier                SMALLINT 1/2/3  — CIS collection tier (which rules are evaluated)
--   agent_config.body.tier      TEXT            — agent behavioural mode ("report_deploy"/"patch")
--
-- Values: 'report' | 'patch' | 'full_endpoint'
--
-- Also adds `tenant_tier_changes` — an append-only audit log for every tier
-- transition, mirroring the pattern used by tenant_rule_changes (0005) and
-- tenant_platform_changes (0010).
--
-- Rollback: migrations/0056_subscription_tier_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0056_subscription_tier.sql
-- Note: all prior migrations must have been applied first.

BEGIN;

ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS subscription_tier TEXT NOT NULL DEFAULT 'report'
    CONSTRAINT tenants_subscription_tier_check
    CHECK (subscription_tier IN ('report', 'patch', 'full_endpoint'));

COMMENT ON COLUMN tenants.subscription_tier IS
  'Commercial product tier: report | patch | full_endpoint. Source of truth for billing and feature entitlement. '
  'Distinct from tenants.tier (CIS collection tier) and agent_config.body.tier (agent behavioural mode). '
  'Written only by PUT /admin/tenant-tier/{tenantID} — never by hand.';

-- Audit log for subscription_tier changes. One row per transition.
-- Mirrors the pattern in tenant_rule_changes (0005) and tenant_platform_changes (0010).
CREATE TABLE tenant_tier_changes (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_tier   TEXT,        -- NULL when the tenant is first assigned a tier via this endpoint
    to_tier     TEXT         NOT NULL CHECK (to_tier IN ('report', 'patch', 'full_endpoint')),
    changed_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    changed_by  TEXT         NOT NULL DEFAULT 'system'
);

CREATE INDEX idx_tenant_tier_changes_tenant
    ON tenant_tier_changes(tenant_id, changed_at DESC);

COMMENT ON TABLE tenant_tier_changes IS
  'Append-only audit log of every subscription_tier transition. '
  'Written atomically by PUT /admin/tenant-tier/{tenantID} alongside the tenants UPDATE.';

-- Backfill subscription_tier from the existing tenants.tier column:
--   1 (Report)                → 'report'
--   2 (Patch+Deploy)          → 'patch'
--   3 (Full Endpoint Mgmt)    → 'full_endpoint'
UPDATE tenants
SET subscription_tier = CASE tier
    WHEN 2 THEN 'patch'
    WHEN 3 THEN 'full_endpoint'
    ELSE       'report'
END;

GRANT SELECT, INSERT ON TABLE tenant_tier_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_tier_changes_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0056_subscription_tier');

COMMIT;
