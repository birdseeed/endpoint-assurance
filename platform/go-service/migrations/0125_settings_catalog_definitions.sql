-- patched.im — 0125_settings_catalog_definitions.sql
-- PAT-1663: cache of Settings Catalog setting definitions (display
-- name/description + option display names/descriptions) used to resolve
-- raw Graph setting-definition/option ids into human-readable names.
--
-- This is a resolution CACHE, not audit evidence like
-- intune_config_snapshots/intune_config_objects (0124) — it is fine to
-- overwrite a row for a definition_id/version that was already fetched
-- (re-fetching the same version is expected to be idempotent), so this
-- table is upserted, not append-only.
--
-- Global, not tenant-scoped: Microsoft's setting-catalog definitions are
-- part of the shared Intune catalogue, identical content for every tenant
-- at a given version — fetching still requires a tenant's Graph token for
-- auth (see GraphDefinitionSource.FetchAll), but the definitions themselves
-- are not per-tenant data, so there is no tenant_id column here.
--
-- definition_id/version together are the cache key everywhere in
-- internal/intune/settingscatalog.go: a definition cached under one version
-- must never be returned for a lookup at a different version, so an older
-- version's row is never deleted when a newer version is fetched — a
-- policy snapshot still citing that older version must keep resolving
-- correctly. See Resolver.Resolve's ReasonVersionMismatch.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0125_settings_catalog_definitions.sql
BEGIN;

CREATE TABLE intune_setting_definitions (
    id            BIGSERIAL   PRIMARY KEY,
    definition_id TEXT        NOT NULL,
    version       TEXT        NOT NULL,
    display_name  TEXT        NOT NULL,
    description   TEXT        NOT NULL DEFAULT '',
    -- Verbatim resolved options for this definition/version, as a JSON
    -- array of {"id","displayName","description"} objects. Kept as JSONB
    -- rather than a child table: options are read/written only as a whole
    -- unit (never queried individually), so there is no join this would
    -- ever serve.
    options       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (definition_id, version)
);

-- CachedVersion (VersionAwareCache) looks up "what version, if any, do we
-- have cached for this definition_id" — most recently fetched wins when
-- more than one version is on file.
CREATE INDEX idx_intune_setting_definitions_definition_id
    ON intune_setting_definitions (definition_id, fetched_at DESC);

COMMENT ON TABLE intune_setting_definitions IS
    'Cache of Settings Catalog setting definitions, keyed by (definition_id, version), used to resolve raw Graph setting/option ids into display names. Upserted on refresh, not append-only. Global catalogue, not tenant-scoped.';

GRANT SELECT, INSERT, UPDATE ON TABLE intune_setting_definitions TO patched;
GRANT USAGE, SELECT ON SEQUENCE intune_setting_definitions_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0125_settings_catalog_definitions')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
