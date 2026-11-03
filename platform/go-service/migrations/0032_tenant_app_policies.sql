-- patched.im — 0032_tenant_app_policies.sql
-- PAT-470: per-tenant app-policy store (mandatory / approved / unapproved / unmanaged).
--
-- This is the control plane behind the dashboard Approved Software toggle (D1)
-- and the Self Service uninstall affordance. It extends the existing allowlist
-- seam with a mandatory flag and stable signer-based matching.
--
-- Matching precedence (highest → lowest specificity):
--   1. team_id (Apple Developer Team ID / Windows Authenticode signer) — most stable
--   2. bundle_id (CFBundleIdentifier / Windows GUID)
--   3. name (display name, case-insensitive) — fallback
--
-- At least one identity column must be non-null (enforced by CHECK constraint).
--
-- policy values:
--   mandatory   — must be present; absence is a drift finding.
--   approved    — allowed; no drift action on presence.
--   unapproved  — should not be present; presence is a drift finding.
--   unmanaged   — explicitly excluded from policy evaluation (suppress false positives).
--
-- enforcement_tier gates what the caller may do in response to a drift finding:
--   report         → advisory only; surface in dashboard / posture response.
--   app_management → agent may prompt user action (T3 App-Management tier).
--   managed        → Intune/MDM blocking is in place (T4 Managed tier).
--
-- The act (user uninstall, mandatory reinstall) belongs to the agent. This
-- table stores intent; the agent owns execution. Carry enforcement_tier in
-- the posture response so callers gate honestly (PAT-447/448).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0032_tenant_app_policies.sql

BEGIN;

CREATE TABLE tenant_app_policies (
    id               BIGSERIAL    PRIMARY KEY,
    tenant_id        UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Stable app identity — at least one must be non-null.
    team_id          TEXT,        -- Apple Developer Team ID / Windows Authenticode signer
    bundle_id        TEXT,        -- CFBundleIdentifier / Windows package GUID
    name             TEXT,        -- display name fallback (matched case-insensitively)
    platform         TEXT         NOT NULL DEFAULT 'any'
                                      CHECK (platform IN ('macos', 'windows', 'any')),
    policy           TEXT         NOT NULL
                                      CHECK (policy IN ('mandatory', 'approved', 'unapproved', 'unmanaged')),
    enforcement_tier TEXT         NOT NULL DEFAULT 'report'
                                      CHECK (enforcement_tier IN ('report', 'app_management', 'managed')),
    notes            TEXT         NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT tenant_app_policies_has_identity CHECK (
        team_id IS NOT NULL OR bundle_id IS NOT NULL OR name IS NOT NULL
    )
);

-- Prevent duplicate policies for the same logical app within a tenant.
-- COALESCE converts NULLs to empty strings so the index treats them as equal
-- (two rows with team_id=NULL for the same tenant conflict correctly).
CREATE UNIQUE INDEX tenant_app_policies_tenant_identity_uniq
    ON tenant_app_policies (
        tenant_id,
        COALESCE(team_id, ''),
        COALESCE(bundle_id, ''),
        COALESCE(lower(name), ''),
        platform
    );

-- Tenant lookup (most common query pattern: load all policies for one tenant).
CREATE INDEX tenant_app_policies_tenant_idx
    ON tenant_app_policies (tenant_id);

-- Signer-based lookup for high-precision matching.
CREATE INDEX tenant_app_policies_team_id_idx
    ON tenant_app_policies (team_id)
    WHERE team_id IS NOT NULL;

-- Bundle-id lookup.
CREATE INDEX tenant_app_policies_bundle_id_idx
    ON tenant_app_policies (bundle_id)
    WHERE bundle_id IS NOT NULL;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0032_tenant_app_policies');

COMMIT;
