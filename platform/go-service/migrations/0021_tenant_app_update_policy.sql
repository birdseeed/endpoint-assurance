-- patched.im — 0021_tenant_app_update_policy.sql
-- PAT-364: per-tenant app-update policy store (read/write).
--
-- The store the dashboard's "Installed Apps & Updates" screen writes to and the
-- Patched Updater reads (PAT-365). It answers one question per app: should the
-- updater keep this app up to date on this tenant's fleet? Two levers:
--
--   1. tenants.app_updates_default_enabled — fleet-wide default. Applies to every
--      app that has no explicit override row. DEFAULT true = update everything until
--      an operator opts an app out.
--
--   2. tenant_app_update_policies — one row per (tenant, platform, app). Present =
--      explicit override of the fleet default for that app. Absent = inherit the
--      fleet default.
--
--   3. tenant_app_policy_changes — append-only audit log of every mutation
--      (default flips and per-app toggles), mirroring tenant_rule_changes (0005)
--      and tenant_platform_changes (0010).
--
-- Platform-neutral by design. `identifier` is the same value device_apps stores:
-- bundle id on macOS, MSI product code / registry uninstall key on Windows.
-- The updater maps that identity onto its engine's key space (Installomator label
-- on macOS, winget/choco id on Windows) — that mapping is the updater's job, not
-- the store's. We carry name/publisher only so the dashboard can render a readable
-- row without re-joining device_apps.
--
-- ⚠️  This is the first admin write that drives agent behaviour on customer
-- endpoints (PAT-66 security-review gate applies before first customer ship).
--
-- ⚠️  DEPLOY ORDERING: apply this migration BEFORE deploying the binary that
-- uses it. The admin endpoints read tenants.app_updates_default_enabled and the
-- new tables. Apply → restart patched-api.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0021_tenant_app_update_policy.sql

BEGIN;

-- ============================================================================
-- TENANTS — fleet-wide default for app updates
-- ============================================================================

ALTER TABLE tenants
    ADD COLUMN app_updates_default_enabled boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN tenants.app_updates_default_enabled IS
    'Fleet-wide default for app updates. Applies to every app with no row in tenant_app_update_policies. true = updater keeps apps current by default; false = updater leaves apps alone unless an override opts them in. See PAT-364/PAT-365.';

-- ============================================================================
-- TENANT_APP_UPDATE_POLICIES — per-app override of the fleet default
-- ============================================================================

CREATE TABLE tenant_app_update_policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    platform    TEXT NOT NULL CHECK (platform IN ('macos', 'windows')),
    identifier  TEXT NOT NULL,
    name        TEXT,
    publisher   TEXT,
    enabled     BOOLEAN NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, platform, identifier)
);

CREATE INDEX idx_tappolicies_tenant ON tenant_app_update_policies(tenant_id);

COMMENT ON TABLE tenant_app_update_policies IS
    'Per-app override of tenants.app_updates_default_enabled. One row per (tenant, platform, app). Present = explicit on/off for that app; absent = inherit the fleet default.';
COMMENT ON COLUMN tenant_app_update_policies.identifier IS
    'App identity, matching device_apps.identifier: bundle id (macOS); MSI product code or registry uninstall key (Windows). The updater maps this onto its engine key space (Installomator label / winget id).';
COMMENT ON COLUMN tenant_app_update_policies.enabled IS
    'true = updater keeps this app current for this tenant; false = updater leaves this app alone, overriding the fleet default.';

-- ============================================================================
-- TENANT_APP_POLICY_CHANGES — append-only audit log
-- ============================================================================

CREATE TABLE tenant_app_policy_changes (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   UUID         NOT NULL,
    platform    TEXT         CHECK (platform IN ('macos', 'windows')),  -- NULL for default_changed
    identifier  TEXT,                                                    -- NULL for default_changed
    changed_by  TEXT         NOT NULL DEFAULT 'system',
    change_type TEXT         NOT NULL CHECK (change_type IN (
                                'app_enabled', 'app_disabled', 'app_removed',
                                'default_changed'
                            )),
    old_enabled BOOLEAN,
    new_enabled BOOLEAN,
    changed_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_tappchanges_tenant_time ON tenant_app_policy_changes(tenant_id, changed_at DESC);

COMMENT ON TABLE tenant_app_policy_changes IS
    'Append-only audit trail of every app-update-policy mutation: per-app toggles (app_enabled/app_disabled/app_removed) and fleet-default flips (default_changed). Never UPDATE or DELETE rows here — use INSERT to record each change.';
COMMENT ON COLUMN tenant_app_policy_changes.changed_by IS
    'Identity of the actor: email address, API key label, or "system" for automated changes.';

-- ============================================================================
-- PERMISSIONS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE ON TABLE tenants TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_app_update_policies TO patched;
GRANT SELECT, INSERT ON TABLE tenant_app_policy_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_app_policy_changes_id_seq TO patched;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0021_tenant_app_update_policy');

COMMIT;
