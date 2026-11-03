-- 0071_tenant_extension_policies.sql
-- Per-tenant browser-extension policy store (PAT-826, sub-ticket 1/5 of PAT-773).
--
-- Records an admin's approve/unapprove/ignore decision for a browser extension,
-- keyed by (browser, extension_id). Deliberately NOT reusing tenant_allowlists
-- (0023) or tenant_app_policies (0032): those match apps on name/publisher or
-- bundle_id/team_id, none of which a browser extension carries. An extension's
-- stable identity is its store extension_id, so this table matches on that.
--
-- Pure policy plane. No enforcement or removal here — that is PAT-828/PAT-829.
-- The scan endpoint (internal/handlers/extension_policies.go) joins this table
-- against device_browser_extensions (0018) to surface unreviewed/unapproved
-- extensions across the estate.
--
-- policy values:
--   approved    → admin has sanctioned this extension
--   unapproved  → admin has flagged it as not permitted (surfaced as drift)
--   ignored     → deliberately excluded from review (noise suppression)
--
-- browser values mirror device_browser_extensions.browser ('chrome' | 'edge' |
-- 'firefox') plus 'any' for a browser-agnostic decision.
--
-- DO NOT APPLY — listed here for Andy to run on patched-api-01:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0071_tenant_extension_policies.sql

BEGIN;

CREATE TABLE tenant_extension_policies (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    browser       TEXT         NOT NULL DEFAULT 'any'
                      CHECK (browser IN ('chrome', 'edge', 'firefox', 'any')),
    extension_id  TEXT         NOT NULL,
    name          TEXT         NOT NULL DEFAULT '',   -- display label; extension_id alone is opaque
    publisher     TEXT,                               -- optional; store/CWS-reported publisher
    webstore_id   TEXT,                               -- optional; store listing id when distinct from extension_id
    policy        TEXT         NOT NULL DEFAULT 'approved'
                      CHECK (policy IN ('approved', 'unapproved', 'ignored')),
    approved_by   TEXT         NOT NULL DEFAULT '',
    notes         TEXT         NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- One policy row per (tenant, browser, extension). extension_id is a canonical
-- store identifier so it is matched verbatim (no LOWER()).
CREATE UNIQUE INDEX idx_tenant_extension_policies_unique
    ON tenant_extension_policies (tenant_id, browser, extension_id);
CREATE INDEX idx_tenant_extension_policies_tenant
    ON tenant_extension_policies (tenant_id);

-- Grants (enforced by check-grants.sh; missing grants have caused prod 500s).
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_extension_policies TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_extension_policies_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0071_tenant_extension_policies');

COMMIT;
