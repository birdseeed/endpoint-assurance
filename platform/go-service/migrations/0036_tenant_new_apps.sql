-- patched.im — 0036_tenant_new_apps.sql
-- PAT-167: new-app discovery surface — platform Stage 1.
--
-- When the extractor ingests an app that has no matching tenant_app_policies row
-- (using the same team_id > bundle_id > name precedence as fetchAppPolicy), it
-- writes a row here so admins can make an approve / remove / defer decision.
--
-- decision values:
--   approve          — known-good; agent may keep it.
--   approve_no_patch — approved but not managed through Patched Patch (e.g. IT-provisioned).
--   remove           — should be removed; surfaces as unapproved drift.
--   defer            — snooze for 90 days (defer_until set to now()+90d); auto-flips
--                      to approve_no_patch by the rolloverDeferredNewApps sweep.
--   NULL             — undecided (pending admin action).
--
-- suggested_action is populated server-side by joining app_catalog_entries on
-- verified_signer (signer-first) at ingest time — 'approve' for catalog-signed
-- entries, 'defer' for unknowns.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0036_tenant_new_apps.sql
BEGIN;

-- DEPLOY ORDERING: safe to apply anytime; no existing table depends on this one.

CREATE TABLE tenant_new_apps (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_identity         TEXT         NOT NULL,  -- mandatoryKey() string: team:<id> | bundle:<id> | name:<name>
    name                 TEXT         NOT NULL,
    publisher_signature  TEXT,                   -- Team ID (macOS) or Authenticode signer (Windows)
    platform             TEXT         NOT NULL CHECK (platform IN ('macos', 'windows')),
    first_seen           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    host_count           INT          NOT NULL DEFAULT 1,
    decision             TEXT         CHECK (decision IN ('approve', 'approve_no_patch', 'remove', 'defer')),
    suggested_action     TEXT,                   -- from app_catalog_entries join at ingest time
    decided_by           TEXT,
    decided_at           TIMESTAMPTZ,
    defer_until          TIMESTAMPTZ,            -- set to now()+90d when decision = 'defer'
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- One row per (tenant, app identity) — re-ingests update host_count + updated_at.
CREATE UNIQUE INDEX tenant_new_apps_tenant_identity_uniq
    ON tenant_new_apps (tenant_id, app_identity);

-- Fast lookup of pending rows per tenant (dashboard badge + admin list default).
CREATE INDEX tenant_new_apps_pending_idx
    ON tenant_new_apps (tenant_id)
    WHERE decision IS NULL;

-- Rollover sweep: find defer rows whose snooze has expired.
CREATE INDEX tenant_new_apps_defer_until_idx
    ON tenant_new_apps (defer_until)
    WHERE decision = 'defer';

-- Grant app user access (PAT-579: was missing, causing permission denied on /admin/tenants/overview).
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_new_apps TO patched;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0036_tenant_new_apps');

COMMIT;
