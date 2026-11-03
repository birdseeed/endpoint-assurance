-- patched.im — 0010_tenant_platform_switches.sql
-- Adds a per-tenant, per-OS master switch and its audit log.
--
-- Two additions:
--
--   1. tenants gains two boolean columns:
--      - macos_enabled:   when false, macOS devices for this tenant are not
--                         evaluated — no compliance_evaluations row is written
--                         and exec-summary reports exclude macOS devices.
--      - windows_enabled: same for Windows devices.
--
--      DEFAULT true means every existing and future tenant has both OSes on
--      unless an operator explicitly switches one off.
--
--   2. tenant_platform_changes: append-only audit log of every master-switch
--      flip, mirroring the tenant_rule_changes pattern from migration 0005.
--
-- The master switch overrides everything — including T1 always-on rules.
-- OFF means the platform is not scored at all, not just "T2 disabled".
--
-- ⚠️  DEPLOY ORDERING: apply this migration BEFORE deploying the binary that
-- uses it. The evaluator reads tenants.macos_enabled / windows_enabled at row
-- processing time; the admin endpoints also select these columns.
-- Apply → restart patched-api and patched-extractor.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0010_tenant_platform_switches.sql
-- Note: 0009_windows_schema_compat.sql must have been applied first.

BEGIN;

-- ============================================================================
-- TENANTS — per-OS master switch columns
-- ============================================================================

ALTER TABLE tenants
    ADD COLUMN macos_enabled   boolean NOT NULL DEFAULT true,
    ADD COLUMN windows_enabled boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN tenants.macos_enabled IS
    'When false, macOS devices for this tenant are not evaluated (no compliance_evaluations rows written) and are excluded from exec-summary reports. Overrides T1 always-on rules.';
COMMENT ON COLUMN tenants.windows_enabled IS
    'When false, Windows devices for this tenant are not evaluated and are excluded from exec-summary reports. Overrides T1 always-on rules.';

-- ============================================================================
-- TENANT_PLATFORM_CHANGES — append-only audit log of master-switch flips
-- ============================================================================

CREATE TABLE tenant_platform_changes (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   UUID         NOT NULL,
    platform    TEXT         NOT NULL CHECK (platform IN ('macos', 'windows')),
    changed_by  TEXT         NOT NULL DEFAULT 'system',
    old_enabled BOOLEAN      NOT NULL,
    new_enabled BOOLEAN      NOT NULL,
    changed_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_tplatchanges_tenant_time ON tenant_platform_changes(tenant_id, changed_at DESC);

COMMENT ON TABLE tenant_platform_changes IS
    'Append-only audit trail of every tenants.macos_enabled / windows_enabled flip. Never UPDATE or DELETE rows here — use INSERT to record each change.';
COMMENT ON COLUMN tenant_platform_changes.changed_by IS
    'Identity of the actor: email address, API key label, or "system" for automated changes.';

-- ============================================================================
-- PERMISSIONS
-- ============================================================================

GRANT SELECT, INSERT ON TABLE tenant_platform_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_platform_changes_id_seq TO patched;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0010_tenant_platform_switches');

COMMIT;
