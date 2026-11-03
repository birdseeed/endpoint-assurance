-- patched.im - 0163_software_category_tags.sql
-- PAT-2015 (part of PAT-2001): server-side product category tags.
--
-- A category tag says "this software is an AI tool" (or, later, a remote
-- access tool, a VPN and so on) without an agent release. Two global,
-- curated sources attach a tag:
--
--   * software_category_product_tags: a tag on a normalised product identity
--     (software_products, PAT-1461). Used where the catalogue already has one.
--   * software_category_rules: a match rule on an observed identifier (bundle
--     ID, Team ID, Authenticode publisher plus product name, browser extension
--     ID per store, IDE marketplace ID, package name per source, MCP server
--     name). Used where the catalogue has no product identity yet.
--
-- Matching is evaluated on ingest and by a backfill whenever a rule is
-- published, and the result is materialised per tenant in
-- software_category_tags.
--
-- Isolation: every software_category_* table except software_category_tags is
-- global. They have no tenant column and no foreign key to tenants; the
-- integration suite asserts this. software_category_tags is tenant data and
-- is bound to its tenant by composite foreign keys, so a tag can never point
-- at another tenant's observation.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0163_software_category_tags.sql

BEGIN;

CREATE TABLE software_categories (
    key          TEXT PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    display_name TEXT NOT NULL CHECK (btrim(display_name) <> ''),
    description  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE software_category_subtypes (
    category_key TEXT NOT NULL REFERENCES software_categories(key) ON DELETE RESTRICT,
    key          TEXT NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    display_name TEXT NOT NULL CHECK (btrim(display_name) <> ''),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (category_key, key)
);

-- Match rules. identifier_value and qualifier are stored already normalised
-- by internal/categorytag (NormalizeRule); matching is exact equality on the
-- normalised tuple, never a substring or a display-name guess.
--
-- qualifier carries the second half of a two-part identifier:
--   windows_authenticode -> product name
--   browser_extension    -> store (chrome_web_store | edge_addons | firefox_addons)
--   ide_extension        -> marketplace (vscode_marketplace | open_vsx | jetbrains_marketplace)
--   package              -> source (brew_formula | brew_cask | npm | pip | winget)
--   everything else      -> ''
CREATE TABLE software_category_rules (
    id                 BIGSERIAL PRIMARY KEY,
    identifier_type    TEXT NOT NULL CHECK (identifier_type IN (
                           'macos_bundle_id', 'macos_team_id', 'windows_authenticode',
                           'browser_extension', 'ide_extension', 'package', 'mcp_server')),
    identifier_value   TEXT NOT NULL CHECK (btrim(identifier_value) <> '' AND length(identifier_value) <= 512),
    qualifier          TEXT NOT NULL DEFAULT '' CHECK (length(qualifier) <= 512),
    platform           TEXT NOT NULL CHECK (platform IN ('macos', 'windows', 'any')),
    category_key       TEXT NOT NULL,
    subtype_key        TEXT NOT NULL,
    notes              TEXT NOT NULL DEFAULT '',
    version            INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    state              TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'retired')),
    created_by         TEXT NOT NULL,
    created_by_claimed TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at       TIMESTAMPTZ,
    retired_at         TIMESTAMPTZ,
    FOREIGN KEY (category_key, subtype_key)
        REFERENCES software_category_subtypes(category_key, key) ON DELETE RESTRICT,
    CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
    CHECK (state = 'draft' OR published_at IS NOT NULL OR state = 'retired')
);
-- One live rule per identifier and classification. A retired rule frees the
-- slot so a corrected replacement can be created.
CREATE UNIQUE INDEX software_category_rules_live_uq
    ON software_category_rules (identifier_type, platform, qualifier, identifier_value, category_key, subtype_key)
    WHERE state <> 'retired';
CREATE INDEX software_category_rules_published_idx
    ON software_category_rules (identifier_type, identifier_value)
    WHERE state = 'published';

CREATE TABLE software_category_product_tags (
    id                 BIGSERIAL PRIMARY KEY,
    product_id         UUID NOT NULL REFERENCES software_products(id) ON DELETE RESTRICT,
    category_key       TEXT NOT NULL,
    subtype_key        TEXT NOT NULL,
    notes              TEXT NOT NULL DEFAULT '',
    state              TEXT NOT NULL DEFAULT 'published' CHECK (state IN ('published', 'retired')),
    created_by         TEXT NOT NULL,
    created_by_claimed TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at         TIMESTAMPTZ,
    FOREIGN KEY (category_key, subtype_key)
        REFERENCES software_category_subtypes(category_key, key) ON DELETE RESTRICT,
    CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX software_category_product_tags_live_uq
    ON software_category_product_tags (product_id, category_key, subtype_key)
    WHERE state = 'published';

-- Append-only audit of every rule and product-tag change: who, when, before
-- and after. actor is the server-established identity (PAT-1135); the
-- caller's own claim is kept separately in claimed_actor and never trusted.
--
-- Known limitation, shared with the other audit tables: the triggers stop an
-- accidental UPDATE, DELETE or TRUNCATE. They do not stop the owning role,
-- and in production that is `patched`, which runs both the migrations and the
-- application, so it can disable the triggers or drop the table. Tamper
-- resistance needs a separate owner role, a deploy-privilege change
-- deliberately not made here.
CREATE TABLE software_category_audit (
    id            BIGSERIAL PRIMARY KEY,
    entity_type   TEXT NOT NULL CHECK (entity_type IN ('rule', 'product_tag')),
    entity_id     BIGINT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('create', 'edit', 'publish', 'retire')),
    actor         TEXT NOT NULL,
    claimed_actor TEXT,
    source_addr   TEXT,
    before        JSONB,
    after         JSONB NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX software_category_audit_entity_idx
    ON software_category_audit (entity_type, entity_id, at);

CREATE FUNCTION reject_software_category_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_category_audit is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_software_category_audit_reject_update
    BEFORE UPDATE OR DELETE ON software_category_audit
    FOR EACH ROW EXECUTE FUNCTION reject_software_category_audit_mutation();
CREATE TRIGGER trg_software_category_audit_reject_truncate
    BEFORE TRUNCATE ON software_category_audit
    FOR EACH STATEMENT EXECUTE FUNCTION reject_software_category_audit_mutation();

-- Composite keys so a tag's tenant is enforced by PostgreSQL, the same
-- approach 0111 takes for the observation domain. These take ACCESS
-- EXCLUSIVE locks while the unique indexes build; both tables are small in
-- production today (hundreds of rows), so that is sub-second. If they ever
-- grow large, build the indexes first with CREATE UNIQUE INDEX CONCURRENTLY
-- outside a transaction and attach them with ADD CONSTRAINT ... USING INDEX.
ALTER TABLE software_installations
    ADD CONSTRAINT software_installations_id_tenant_device_uq UNIQUE (id, tenant_id, device_id);
ALTER TABLE device_browser_extensions
    ADD CONSTRAINT device_browser_extensions_id_device_uq UNIQUE (id, device_id);

-- Exact-value lookups for the publish backfill, so a rule publish reads only
-- the observations with its identifier instead of scanning the tables.
CREATE INDEX software_installations_identity_value_present_idx
    ON software_installations (identity_value_normalized) WHERE removed_at IS NULL;
CREATE INDEX device_browser_extensions_lower_extension_id_idx
    ON device_browser_extensions (lower(extension_id));

-- Tenant-scoped materialised matches. A tag is retired (retired_at set, with
-- a reason), never deleted, when its rule or product tag is retired or edited
-- so that it no longer matches: the tenant keeps the record of what was
-- classified, when and by which rule. Observation deletion (device or tenant
-- retention) cascades.
CREATE TABLE software_category_tags (
    id                   BIGSERIAL PRIMARY KEY,
    tenant_id            UUID NOT NULL,
    device_id            UUID NOT NULL,
    observation_kind     TEXT NOT NULL CHECK (observation_kind IN ('app', 'browser_extension')),
    installation_id      UUID,
    browser_extension_id BIGINT,
    rule_id              BIGINT REFERENCES software_category_rules(id) ON DELETE RESTRICT,
    product_tag_id       BIGINT REFERENCES software_category_product_tags(id) ON DELETE RESTRICT,
    tagged_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at           TIMESTAMPTZ,
    retired_reason       TEXT CHECK (retired_reason IN ('rule_retired', 'rule_changed', 'no_longer_matches')),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (installation_id, tenant_id, device_id)
        REFERENCES software_installations(id, tenant_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (browser_extension_id, device_id)
        REFERENCES device_browser_extensions(id, device_id) ON DELETE CASCADE,
    CHECK ((observation_kind = 'app' AND installation_id IS NOT NULL AND browser_extension_id IS NULL)
        OR (observation_kind = 'browser_extension' AND browser_extension_id IS NOT NULL AND installation_id IS NULL)),
    CHECK (num_nonnulls(rule_id, product_tag_id) = 1),
    CHECK ((retired_at IS NULL) = (retired_reason IS NULL))
);
CREATE UNIQUE INDEX software_category_tags_live_app_rule_uq
    ON software_category_tags (installation_id, rule_id)
    WHERE retired_at IS NULL AND installation_id IS NOT NULL AND rule_id IS NOT NULL;
CREATE UNIQUE INDEX software_category_tags_live_app_product_uq
    ON software_category_tags (installation_id, product_tag_id)
    WHERE retired_at IS NULL AND installation_id IS NOT NULL AND product_tag_id IS NOT NULL;
CREATE UNIQUE INDEX software_category_tags_live_ext_rule_uq
    ON software_category_tags (browser_extension_id, rule_id)
    WHERE retired_at IS NULL AND browser_extension_id IS NOT NULL AND rule_id IS NOT NULL;
CREATE INDEX software_category_tags_tenant_live_idx
    ON software_category_tags (tenant_id) WHERE retired_at IS NULL;
CREATE INDEX software_category_tags_device_live_idx
    ON software_category_tags (device_id) WHERE retired_at IS NULL;
CREATE INDEX software_category_tags_rule_live_idx
    ON software_category_tags (rule_id) WHERE retired_at IS NULL AND rule_id IS NOT NULL;
CREATE INDEX software_category_tags_product_tag_live_idx
    ON software_category_tags (product_tag_id) WHERE retired_at IS NULL AND product_tag_id IS NOT NULL;

-- The category taxonomy PAT-2001 names. The match rules themselves are the
-- reviewed seed list of PAT-2016 and are deliberately not written here.
INSERT INTO software_categories (key, display_name, description) VALUES
    ('ai_tooling', 'AI tooling', 'AI applications, browser and IDE extensions, command-line tools, local model runtimes and MCP servers.')
ON CONFLICT (key) DO NOTHING;
INSERT INTO software_category_subtypes (category_key, key, display_name) VALUES
    ('ai_tooling', 'desktop_app', 'Desktop app'),
    ('ai_tooling', 'browser_extension', 'Browser extension'),
    ('ai_tooling', 'ide_extension', 'IDE extension'),
    ('ai_tooling', 'cli', 'Command-line tool'),
    ('ai_tooling', 'local_runtime', 'Local model runtime'),
    ('ai_tooling', 'mcp_server', 'MCP server')
ON CONFLICT (category_key, key) DO NOTHING;

COMMENT ON TABLE software_category_rules IS
    'PAT-2015: global category match rules. No tenant identifier, ever. Values are normalised by internal/categorytag.';
COMMENT ON TABLE software_category_product_tags IS
    'PAT-2015: global category tags on normalised product identities (software_products). No tenant identifier, ever.';
COMMENT ON TABLE software_category_audit IS
    'PAT-2015: append-only who/when/before/after audit of every rule and product-tag change.';
COMMENT ON TABLE software_category_tags IS
    'PAT-2015: tenant-scoped materialised category matches. Retired, never deleted, when a rule stops matching.';

GRANT SELECT ON software_categories TO patched;
GRANT SELECT ON software_category_subtypes TO patched;
GRANT SELECT, INSERT, UPDATE ON software_category_rules TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_category_rules_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE ON software_category_product_tags TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_category_product_tags_id_seq TO patched;
GRANT SELECT, INSERT ON software_category_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_category_audit_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE ON software_category_tags TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_category_tags_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0163_software_category_tags')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
