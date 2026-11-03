-- 0166: IDE extensions, npm and pip packages, local models and MCP servers
-- on the software observation seam (PAT-2021)
--
-- The four payload blocks the agents collect under PAT-2017 (ide_extensions),
-- PAT-2018 (package_managers), PAT-2019 (local_models) and PAT-2020
-- (mcp_servers) are stored as ordinary software_observations and
-- software_installations rows, the PAT-1461 seam Homebrew already uses. Each
-- item gets its own identity kind:
--
--   ide_extension          value = extension id, companion = marketplace
--                          (vscode_marketplace | open_vsx | jetbrains_marketplace)
--   npm_package            value = npm name (PAT-2015 package normalisation)
--   pip_package            value = PEP 503 name (pip user site and pipx)
--   local_model            value = name[:tag], companion = runtime
--   local_model_runtime    value = runtime, companion = runtime
--   mcp_server             value = server name, companion = client
--
-- plus an *_unidentified / mcp_server_unnamed kind for an item the agent saw
-- but could not name (an unreadable manifest, a secret-shaped server key).
-- Those are kept as evidence at low confidence and never match a rule.
--
-- None of these is product identity (AGENTS.md "identity is not packaging"):
-- software_product_aliases admits none of the kinds, so every observation is
-- unresolved until a reviewed mapping exists.
--
-- The three tables below hold what software_observations cannot:
--
--   tooling_observation_details  the item exactly as reported (typed and
--                                allowlisted by the extractor), immutable.
--   tooling_device_state         newest collection_status per device per
--                                block, per-unit statuses (sources, runtimes,
--                                clients), a small summary and the per-unit
--                                absence authority. failed and not_present
--                                stay distinct.
--   tooling_current_entries      one row per item per device: the newest
--                                report that listed it. partial only adds or
--                                refreshes; only an authoritative unit
--                                (complete or not_present, block not
--                                truncated) prunes what it did not list.
--
-- None of them references catalogue, package, deployment or remediation
-- records.
--
-- Locking (review P2): the three CHECK constraints are re-added NOT VALID,
-- so this transaction takes only brief ACCESS EXCLUSIVE locks and scans no
-- table. New rows are checked at once. 0167 validates them in its own
-- transaction (SHARE UPDATE EXCLUSIVE, reads and writes continue) and builds
-- software_installations_kind_value_present_idx CONCURRENTLY, which cannot
-- run inside this transaction.
BEGIN;

-- Absence authority, one scope per unit. A unit grants its scope only when
-- its own status is complete or not_present and the block is neither failed
-- nor truncated. Each scope closes only its own identity kinds.
ALTER TABLE software_inventory_runs
    DROP CONSTRAINT software_inventory_runs_authoritative_scopes_check;
ALTER TABLE software_inventory_runs
    ADD CONSTRAINT software_inventory_runs_authoritative_scopes_check
    CHECK (authoritative_scopes <@ ARRAY[
        'all_software','windows_winget','homebrew',
        'ide_extensions',
        'packages:npm_global','packages:pip_user','packages:pipx',
        'local_models:ollama','local_models:lm_studio','local_models:llama_cpp',
        'mcp_servers:claude_desktop','mcp_servers:cursor','mcp_servers:vscode',
        'mcp_servers:windsurf','mcp_servers:claude_code'
    ]::TEXT[]) NOT VALID;

CREATE TABLE tooling_observation_details (
    observation_id    BIGINT PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    device_id         UUID NOT NULL,
    inventory_run_id  UUID NOT NULL,
    block             TEXT NOT NULL CHECK (block IN ('ide_extensions','package_managers','local_models','mcp_servers')),
    -- the absence-authority unit: '' (ide_extensions), the package source,
    -- the model runtime or the MCP client
    unit              TEXT NOT NULL,
    entry_kind        TEXT NOT NULL CHECK (entry_kind IN ('extension','package','model','runtime_installation','server')),
    -- sha256 of the item's natural key (see tooling_current_entries)
    entry_key         TEXT NOT NULL CHECK (entry_key ~ '^[0-9a-f]{64}$'),
    user_name         TEXT,
    user_id           TEXT,
    attributes        JSONB NOT NULL,
    observed_at       TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (observation_id, tenant_id)
        REFERENCES software_observations(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (inventory_run_id, tenant_id, device_id)
        REFERENCES software_inventory_runs(id, tenant_id, device_id) ON DELETE CASCADE
);
CREATE INDEX tooling_observation_details_device_idx
    ON tooling_observation_details (tenant_id, device_id, block, observed_at DESC);

CREATE FUNCTION reject_tooling_observation_detail_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tooling_observation_details evidence is immutable: UPDATE is not permitted on observation_id=%', OLD.observation_id;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_tooling_observation_details_reject_update
    BEFORE UPDATE ON tooling_observation_details
    FOR EACH ROW EXECUTE FUNCTION reject_tooling_observation_detail_update();

CREATE TABLE tooling_device_state (
    device_id                UUID NOT NULL,
    tenant_id                UUID NOT NULL,
    block                    TEXT NOT NULL CHECK (block IN ('ide_extensions','package_managers','local_models','mcp_servers')),
    collection_status        TEXT NOT NULL
                             CHECK (collection_status IN ('complete','partial','not_present','failed')),
    truncated                BOOLEAN,
    truncation_reason        TEXT,
    -- sources, runtimes or clients: unit -> collection_status, as reported
    unit_statuses            JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- counts from the newest report (totals, rows read, users)
    summary                  JSONB NOT NULL DEFAULT '{}'::jsonb,
    issues                   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- received_at of the payload this row reflects; an older replay never
    -- overwrites a newer report
    reported_at              TIMESTAMPTZ NOT NULL,
    raw_payload_id           BIGINT,
    raw_payload_received_at  TIMESTAMPTZ,
    inventory_run_id         UUID,
    -- unit -> received_at of the newest report that granted that unit
    -- absence authority. Only moves forward; partial and failed never move it.
    authority                JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, block),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX tooling_device_state_tenant_idx ON tooling_device_state (tenant_id, block, collection_status);

CREATE TABLE tooling_current_entries (
    device_id          UUID NOT NULL,
    tenant_id          UUID NOT NULL,
    block              TEXT NOT NULL CHECK (block IN ('ide_extensions','package_managers','local_models','mcp_servers')),
    unit               TEXT NOT NULL,
    entry_kind         TEXT NOT NULL CHECK (entry_kind IN ('extension','package','model','runtime_installation','server')),
    entry_key          TEXT NOT NULL CHECK (entry_key ~ '^[0-9a-f]{64}$'),
    observation_id     BIGINT NOT NULL,
    -- received_at of the newest report that listed this item
    observed_at        TIMESTAMPTZ NOT NULL,
    inventory_run_id   UUID NOT NULL,
    PRIMARY KEY (device_id, block, entry_key),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (observation_id, tenant_id)
        REFERENCES software_observations(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (inventory_run_id, tenant_id, device_id)
        REFERENCES software_inventory_runs(id, tenant_id, device_id) ON DELETE CASCADE
);
CREATE INDEX tooling_current_entries_tenant_idx
    ON tooling_current_entries (tenant_id, block, device_id);
CREATE INDEX tooling_current_entries_observation_idx
    ON tooling_current_entries (observation_id);

-- PAT-2015 tags on the new installation kinds. They are installations like
-- apps, so they use installation_id; observation_kind says what they are.
ALTER TABLE software_category_tags
    DROP CONSTRAINT software_category_tags_observation_kind_check;
ALTER TABLE software_category_tags
    ADD CONSTRAINT software_category_tags_observation_kind_check
    CHECK (observation_kind IN ('app','browser_extension','ide_extension','package','mcp_server','local_model')) NOT VALID;
ALTER TABLE software_category_tags
    DROP CONSTRAINT software_category_tags_check;
ALTER TABLE software_category_tags
    ADD CONSTRAINT software_category_tags_check
    CHECK ((observation_kind IN ('app','ide_extension','package','mcp_server','local_model')
            AND installation_id IS NOT NULL AND browser_extension_id IS NULL)
        OR (observation_kind = 'browser_extension' AND browser_extension_id IS NOT NULL AND installation_id IS NULL)) NOT VALID;

COMMENT ON TABLE tooling_observation_details IS
    'PAT-2021: the reported IDE extension, package, local model, runtime installation or MCP server for one software_observations row. Allowlisted fields only. Immutable.';
COMMENT ON TABLE tooling_device_state IS
    'PAT-2021: newest collection_status per device per block, per-unit statuses and per-unit absence authority. failed and not_present are distinct.';
COMMENT ON TABLE tooling_current_entries IS
    'PAT-2021: newest report per device item. partial only adds or refreshes; only an authoritative unit prunes. Derived; rebuilt by re-extraction.';

GRANT SELECT, INSERT ON tooling_observation_details TO patched;
GRANT SELECT, INSERT, UPDATE ON tooling_device_state TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON tooling_current_entries TO patched;

INSERT INTO schema_migrations (version) VALUES ('0166_tooling_inventory')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
