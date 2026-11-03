-- 0067: per-tenant Self-Service App Catalogue store (PAT-659 / PAT-660).
--
-- tenant_catalogue holds the operator-curated list of apps to be installed on
-- enrolled devices belonging to a tenant. The agent polls
-- GET /v1/allowlist/pending-installs and receives only enabled=true entries.
--
-- package_source is constrained to the three currently supported package
-- managers: winget (Windows Package Manager), mas (Mac App Store), and vendor
-- (direct vendor slug used by Patched Updater).
--
-- A partial index on (tenant_id) WHERE enabled=true keeps the agent-poll
-- query fast — disabled entries are excluded from the index and from all
-- agent-facing reads.

BEGIN;

CREATE TABLE tenant_catalogue (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    package_id     TEXT        NOT NULL,
    package_source TEXT        NOT NULL CHECK (package_source IN ('winget', 'mas', 'vendor')),
    display_name   TEXT        NOT NULL,
    added_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by       TEXT        NOT NULL,
    enabled        BOOLEAN     NOT NULL DEFAULT true,
    UNIQUE (tenant_id, package_id)
);

CREATE INDEX tenant_catalogue_tenant_id
    ON tenant_catalogue (tenant_id)
    WHERE enabled = true;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_catalogue TO patched;

INSERT INTO schema_migrations (version) VALUES ('0067_tenant_catalogue')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
