-- Rollback for 0121_retire_tenant_catalogue.sql (PAT-1561).
--
-- Recreates tenant_catalogue exactly as 0067_tenant_catalogue.sql defined it.
-- Data is not restored (it was dropped with the table) — this only restores
-- the empty schema so the application code from before PAT-1561 would have
-- somewhere to write again.

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

DELETE FROM schema_migrations WHERE version = '0121_retire_tenant_catalogue';

COMMIT;
