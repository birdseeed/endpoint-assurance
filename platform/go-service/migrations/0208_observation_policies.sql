-- 0208: customer approval decisions for named PAT-2021 observation identities
-- (PAT-2031).
--
-- Homebrew keeps the compatible tenant_homebrew_policies store introduced by
-- 0195. This table is intentionally only for the named tooling identities
-- written by 0166. The tuple is the extractor's exact observed identity:
-- (identity_kind, identity_value_normalized, companion_value_normalized).
-- It is not an application-name fallback and it never admits unidentified
-- observations, which are evidence but not a safe object for a decision.
--
-- Apply with:
-- psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0208_observation_policies.sql

BEGIN;

CREATE TABLE tenant_observation_policies (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_kind TEXT NOT NULL CHECK (identity_kind IN (
        'ide_extension', 'npm_package', 'pip_package',
        'local_model', 'local_model_runtime', 'mcp_server'
    )),
    -- Both strings are pre-normalised by the extractor's
    -- normalizedIdentityValue. source is deliberately allowed to be empty:
    -- npm and pip have no companion while an extension has a marketplace and
    -- an MCP server has a client.
    name          TEXT NOT NULL CHECK (name = lower(btrim(name)) AND name <> '' AND length(name) <= 256),
    source        TEXT NOT NULL DEFAULT '' CHECK (source = lower(btrim(source)) AND length(source) <= 256),
    policy        TEXT NOT NULL CHECK (policy IN ('approved', 'unapproved', 'unmanaged')),
    notes         TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 1000),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, identity_kind, name, source)
);
CREATE INDEX tenant_observation_policies_tenant_idx ON tenant_observation_policies (tenant_id);

COMMENT ON TABLE tenant_observation_policies IS
    'PAT-2031: customer portal approval decisions keyed to a named PAT-2021 software observation identity. Unidentified observations are deliberately not decision targets.';

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_observation_policies TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_observation_policies_id_seq TO patched;

-- Preserve the append-only audit table while making the observation identity
-- explicit rather than overloading identifier or browser. Existing rows keep
-- both new columns NULL. The product key remains the history lookup key.
ALTER TABLE software_approval_decisions
    ADD COLUMN observation_kind TEXT,
    ADD COLUMN observation_source TEXT;
ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_product_type_check;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_product_type_check
    CHECK (product_type IN ('application', 'browser_extension', 'homebrew_formula', 'homebrew_cask', 'observation'));
ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_check1;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_check1
    CHECK ((product_type = 'application' AND platform IS NOT NULL AND browser IS NULL
            AND observation_kind IS NULL AND observation_source IS NULL)
        OR (product_type = 'browser_extension' AND platform IS NULL AND team_id IS NULL AND browser IS NOT NULL
            AND observation_kind IS NULL AND observation_source IS NULL)
        OR (product_type IN ('homebrew_formula', 'homebrew_cask')
            AND platform IS NULL AND team_id IS NULL AND browser IS NULL
            AND observation_kind IS NULL AND observation_source IS NULL)
        OR (product_type = 'observation' AND platform IS NULL AND team_id IS NULL AND browser IS NULL
            AND observation_kind IN ('ide_extension', 'npm_package', 'pip_package',
                                     'local_model', 'local_model_runtime', 'mcp_server')
            AND observation_source IS NOT NULL));

-- The maintained unapproved summary is an optimisation, never a second
-- resolver. It therefore carries the exact identity needed to rebuild an
-- observation product from a clean summary row.
ALTER TABLE software_unapproved_presence
    ADD COLUMN observation_kind TEXT NOT NULL DEFAULT '',
    ADD COLUMN observation_source TEXT NOT NULL DEFAULT '';
ALTER TABLE software_unapproved_presence
    DROP CONSTRAINT software_unapproved_presence_policy_kind_check;
ALTER TABLE software_unapproved_presence
    ADD CONSTRAINT software_unapproved_presence_policy_kind_check
    CHECK (policy_kind IN ('application', 'browser_extension', 'homebrew_formula', 'homebrew_cask', 'observation'));

-- Exact resolver inputs invalidate the summary. Tooling rows are current only
-- while their own block/unit remains authoritative, so both tables dirty the
-- device. The policy trigger advances the tenant version atomically with the
-- policy write.
CREATE TRIGGER trg_unapproved_presence_tooling_current
    AFTER INSERT OR UPDATE OR DELETE ON tooling_current_entries
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_tooling_state_ins_del
    AFTER INSERT OR DELETE ON tooling_device_state
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_tooling_state_upd
    AFTER UPDATE ON tooling_device_state
    FOR EACH ROW
    WHEN (OLD.device_id IS DISTINCT FROM NEW.device_id
       OR OLD.collection_status IS DISTINCT FROM NEW.collection_status
       OR OLD.unit_statuses IS DISTINCT FROM NEW.unit_statuses
       OR OLD.authority IS DISTINCT FROM NEW.authority)
    EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_observation_policies_ins_del
    AFTER INSERT OR DELETE ON tenant_observation_policies
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_policy_trg();
CREATE TRIGGER trg_unapproved_presence_observation_policies_upd
    AFTER UPDATE ON tenant_observation_policies
    FOR EACH ROW
    WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.identity_kind IS DISTINCT FROM NEW.identity_kind
       OR OLD.name IS DISTINCT FROM NEW.name
       OR OLD.source IS DISTINCT FROM NEW.source
       OR OLD.policy IS DISTINCT FROM NEW.policy)
    EXECUTE FUNCTION software_unapproved_presence_policy_trg();

-- Cask-to-app links alter the policy resolver. Dirty both linked
-- installations' devices, including OLD identities on an UPDATE.
CREATE FUNCTION software_unapproved_presence_cask_link_dirty_trg() RETURNS trigger AS $$
DECLARE
    cask_id UUID;
    app_id UUID;
    old_cask_id UUID;
    old_app_id UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        cask_id := OLD.cask_installation_id; app_id := OLD.app_installation_id;
    ELSE
        cask_id := NEW.cask_installation_id; app_id := NEW.app_installation_id;
        IF TG_OP = 'UPDATE' THEN old_cask_id := OLD.cask_installation_id; old_app_id := OLD.app_installation_id; END IF;
    END IF;
    PERFORM software_unapproved_presence_mark_dirty(si.device_id)
    FROM software_installations si WHERE si.id IN (cask_id, app_id, old_cask_id, old_app_id);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_unapproved_presence_cask_link
    AFTER INSERT OR UPDATE OR DELETE ON homebrew_cask_app_links
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_cask_link_dirty_trg();

-- The resolver now gives a linked cask its app policy. Invalidate only the
-- tenants that already have a cask-app link; unrelated tenant summaries keep
-- their current version.
INSERT INTO software_unapproved_presence_state (tenant_id, policy_version, summary_version, policy_changed_at)
SELECT DISTINCT ci.tenant_id, 1, 0, now()
FROM homebrew_cask_app_links l
JOIN software_installations ci ON ci.id = l.cask_installation_id
JOIN software_installations ai ON ai.id = l.app_installation_id AND ai.tenant_id = ci.tenant_id
ON CONFLICT (tenant_id) DO UPDATE SET
    policy_version = software_unapproved_presence_state.policy_version + 1,
    policy_changed_at = EXCLUDED.policy_changed_at;

INSERT INTO schema_migrations (version) VALUES ('0208_observation_policies')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
