-- 0164: Homebrew inventory on the software observation seam (PAT-2013)
--
-- Homebrew formulae, casks and taps reported by the macOS agent (updater
-- PAT-2012, payload key `homebrew`) are stored as ordinary
-- software_observations / software_installations rows with identity kinds
-- homebrew_formula, homebrew_cask and homebrew_tap. They join the same
-- run, the same immutable evidence log and the same installation projection
-- as application bundles. No parallel formula or cask table exists.
--
-- The three tables below hold only what software_observations cannot:
--
--   homebrew_observation_details  per-observation Homebrew evidence (prefix,
--                                 tap, receipt status, dependency flags,
--                                 homepage/source url, cask app paths, tap
--                                 remote). Immutable, like the observation it
--                                 extends.
--   homebrew_device_state         per-device collection_status and prefix
--                                 roster from the newest report. This is how
--                                 not_present and failed stay distinct, and
--                                 authority_at is the cut-off that makes
--                                 "complete replaces, partial never prunes"
--                                 hold for the current per-device list.
--   homebrew_cask_app_links       a cask installation linked to the app
--                                 bundle installation it put on disk, so the
--                                 estate counts that install once.
--
-- None of these reference catalogue, package, deployment or remediation
-- records. A formula name or cask token is package-namespace evidence, not a
-- normalised product: observations stay unresolved until a reviewed mapping
-- exists (AGENTS.md "identity is not packaging").
BEGIN;

-- Homebrew absence has its own authority. The macOS `all_software` scope
-- covers the `apps` snapshot only; a complete or not_present Homebrew block
-- grants the separate `homebrew` scope, and nothing else can close a
-- Homebrew installation.
ALTER TABLE software_inventory_runs
    DROP CONSTRAINT software_inventory_runs_authoritative_scopes_check;
ALTER TABLE software_inventory_runs
    ADD CONSTRAINT software_inventory_runs_authoritative_scopes_check
    CHECK (authoritative_scopes <@ ARRAY['all_software','windows_winget','homebrew']::TEXT[]);

-- homebrew_cask_app_links binds both installations to one device and tenant
-- through software_installations_id_tenant_device_uq (id, tenant_id,
-- device_id). 0163 (PAT-2015) owns that constraint; this migration relies on
-- it and neither adds nor drops it.

CREATE TABLE homebrew_observation_details (
    observation_id           BIGINT PRIMARY KEY,
    tenant_id                UUID NOT NULL,
    device_id                UUID NOT NULL,
    inventory_run_id         UUID NOT NULL,
    package_kind             TEXT NOT NULL CHECK (package_kind IN ('formula','cask','tap')),
    prefix                   TEXT NOT NULL CHECK (btrim(prefix) <> ''),
    -- formula name, cask token or tap name, exactly as reported
    name                     TEXT NOT NULL CHECK (btrim(name) <> ''),
    version                  TEXT,
    tap                      TEXT,
    installed_on_request     BOOLEAN,
    installed_as_dependency  BOOLEAN,
    installed_at             TIMESTAMPTZ,
    runtime_dependencies     TEXT[],
    homepage                 TEXT,
    source_url               TEXT,
    opt_linked               BOOLEAN,
    receipt_status           TEXT CHECK (receipt_status IN ('read','missing','unreadable','unparseable')),
    formula_file_status      TEXT CHECK (formula_file_status IN ('read','missing','unreadable')),
    versions_on_disk         TEXT[],
    apps                     JSONB,
    tap_directory            TEXT,
    remote_url               TEXT,
    config_status            TEXT CHECK (config_status IN ('read','missing','unreadable','not_a_directory')),
    observed_at              TIMESTAMPTZ NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (observation_id, tenant_id)
        REFERENCES software_observations(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (inventory_run_id, tenant_id, device_id)
        REFERENCES software_inventory_runs(id, tenant_id, device_id) ON DELETE CASCADE,
    CHECK ((package_kind = 'formula' AND version IS NOT NULL
            AND receipt_status IS NOT NULL AND formula_file_status IS NOT NULL
            AND versions_on_disk IS NULL AND apps IS NULL
            AND tap_directory IS NULL AND config_status IS NULL)
        OR (package_kind = 'cask' AND receipt_status IS NOT NULL
            AND versions_on_disk IS NOT NULL AND apps IS NOT NULL
            AND formula_file_status IS NULL AND runtime_dependencies IS NULL
            AND tap_directory IS NULL AND config_status IS NULL)
        OR (package_kind = 'tap' AND tap_directory IS NOT NULL AND config_status IS NOT NULL
            AND version IS NULL AND tap IS NULL AND receipt_status IS NULL
            AND formula_file_status IS NULL AND versions_on_disk IS NULL AND apps IS NULL))
);
CREATE INDEX homebrew_observation_details_device_observed_idx
    ON homebrew_observation_details (tenant_id, device_id, observed_at DESC);
CREATE INDEX homebrew_observation_details_tenant_name_idx
    ON homebrew_observation_details (tenant_id, package_kind, name);

CREATE FUNCTION reject_homebrew_observation_detail_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'homebrew_observation_details evidence is immutable: UPDATE is not permitted on observation_id=%', OLD.observation_id;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_homebrew_observation_details_reject_update
    BEFORE UPDATE ON homebrew_observation_details
    FOR EACH ROW EXECUTE FUNCTION reject_homebrew_observation_detail_update();

CREATE TABLE homebrew_device_state (
    device_id                UUID PRIMARY KEY,
    tenant_id                UUID NOT NULL,
    collection_status        TEXT NOT NULL
                             CHECK (collection_status IN ('complete','partial','not_present','failed')),
    truncated                BOOLEAN,
    truncation_reason        TEXT,
    prefixes                 JSONB NOT NULL DEFAULT '[]'::jsonb,
    issues                   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- received_at of the payload this row reflects; an older replay never
    -- overwrites a newer report.
    reported_at              TIMESTAMPTZ NOT NULL,
    raw_payload_id           BIGINT,
    raw_payload_received_at  TIMESTAMPTZ,
    inventory_run_id         UUID,
    -- received_at of the newest complete or not_present report. Evidence
    -- older than this is superseded; partial and failed reports never move it.
    authority_at             TIMESTAMPTZ,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX homebrew_device_state_tenant_idx ON homebrew_device_state (tenant_id, collection_status);

CREATE TABLE homebrew_cask_app_links (
    tenant_id                UUID NOT NULL,
    device_id                UUID NOT NULL,
    cask_installation_id     UUID NOT NULL,
    app_installation_id      UUID NOT NULL,
    app_path                 TEXT NOT NULL,
    link_basis               TEXT NOT NULL CHECK (link_basis IN ('reported_path','default_appdir')),
    cask_observation_id      BIGINT,
    linked_at                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cask_installation_id, app_installation_id),
    FOREIGN KEY (cask_installation_id, tenant_id, device_id)
        REFERENCES software_installations(id, tenant_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (app_installation_id, tenant_id, device_id)
        REFERENCES software_installations(id, tenant_id, device_id) ON DELETE CASCADE,
    CHECK (cask_installation_id <> app_installation_id)
);
CREATE INDEX homebrew_cask_app_links_app_idx ON homebrew_cask_app_links (app_installation_id);
CREATE INDEX homebrew_cask_app_links_tenant_idx ON homebrew_cask_app_links (tenant_id, device_id);

COMMENT ON TABLE homebrew_observation_details IS
    'PAT-2013: Homebrew-specific evidence for one software_observations row (identity kinds homebrew_formula, homebrew_cask, homebrew_tap). Immutable.';
COMMENT ON TABLE homebrew_device_state IS
    'PAT-2013: newest Homebrew collection_status per device. not_present and failed are distinct; authority_at moves only on complete or not_present.';
COMMENT ON TABLE homebrew_cask_app_links IS
    'PAT-2013: a Homebrew cask installation linked to the application bundle installation it installed, so the estate counts it once.';

GRANT SELECT, INSERT ON homebrew_observation_details TO patched;
GRANT SELECT, INSERT, UPDATE ON homebrew_device_state TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON homebrew_cask_app_links TO patched;

INSERT INTO schema_migrations (version) VALUES ('0164_homebrew_inventory')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
