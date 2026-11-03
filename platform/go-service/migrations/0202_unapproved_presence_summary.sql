-- patched.im - 0202_unapproved_presence_summary.sql
-- PAT-2095: an incrementally maintained Unapproved-present summary, so the
-- portal overview and the marked unapproved alert stop loading the whole
-- tenant estate on every request.
--
-- Additive. No existing column, index, constraint or row is changed. Existing
-- tables gain AFTER triggers that only write to the new tables below:
--
--   device_apps (0001), device_browser_extensions (0018), devices (0001)
--       mark the device dirty when a column the approval resolver reads
--       changes (identity, name, first_seen, os, tenant).
--   homebrew_current_entries, homebrew_device_state,
--   homebrew_observation_details, software_installations
--       mark the device dirty (PAT-2058 Homebrew presence reads them).
--   tenant_app_policies, tenant_extension_policies, tenant_homebrew_policies
--       bump the tenant's policy_version when a resolution input changes.
--
-- software_unapproved_episodes (0183) gains one nullable column,
-- policy_version, the tenant policy version the episode was opened at.
--
-- The triggers reference device_apps.identifier_kind added by 0110 and
-- homebrew_device_state.authority_at added by 0164, both above the migration
-- floor, plus core devices columns (os, tenant_id).
-- The composite presence FK requires devices_id_tenant_uq from 0111.
-- device_apps and devices were created at 0001, below MIGRATION_FLOOR: check
-- the live shape (\d device_apps, \d devices) before deploying.
--
-- Presence rows can be rebuilt from inventory and policy tables
-- (softwaregov.ReconcileTenant). Device checks and their authority are
-- derived from raw evidence; re-extraction recreates them. The migration seeds a
-- state row per existing tenant with summary_version < policy_version, so the
-- runner rebuilds every tenant's summary after deploy and the overview falls
-- back to the full computation until it has.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0202_unapproved_presence_summary.sql

BEGIN;

-- One row per (device, Unapproved assessment): the device currently resolves
-- product_key to Unapproved under policy (policy_kind, policy_id). Hostname,
-- os and last_seen are joined live from devices at read time.
CREATE TABLE software_unapproved_presence (
    tenant_id      UUID        NOT NULL,
    device_id      UUID        NOT NULL,
    product_key    TEXT        NOT NULL,
    policy_kind    TEXT        NOT NULL CHECK (policy_kind IN ('application', 'browser_extension', 'homebrew_formula', 'homebrew_cask')),
    policy_id      BIGINT      NOT NULL,
    product_type   TEXT        NOT NULL,
    -- The lexically smallest display name the device reports for it.
    name           TEXT        NOT NULL,
    platform       TEXT        NOT NULL DEFAULT '',
    identifier     TEXT        NOT NULL DEFAULT '',
    team_id        TEXT        NOT NULL DEFAULT '',
    browser        TEXT        NOT NULL DEFAULT '',
    extension_id   TEXT        NOT NULL DEFAULT '',
    tap            TEXT        NOT NULL DEFAULT '',
    -- Earliest first_seen among the product's inventory rows on the device.
    observed_since TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, product_key, policy_kind, policy_id),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX software_unapproved_presence_tenant_policy_idx
    ON software_unapproved_presence (tenant_id, policy_kind, policy_id);

-- These correlated columns identify one overview group, not three independent
-- dimensions. Without their joint cardinality, ANALYZE can make the planner
-- sort every device/product row on disk instead of using a small hash aggregate.
CREATE STATISTICS software_unapproved_presence_group_stats (ndistinct)
    ON product_key, policy_kind, policy_id FROM software_unapproved_presence;

-- One row per device whose summary has ever been refreshed. Its row lock
-- serialises refreshes of one device.
CREATE TABLE software_unapproved_presence_devices (
    device_id      UUID        PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    policy_version BIGINT      NOT NULL DEFAULT 0,
    refreshed_at   TIMESTAMPTZ
);

-- Devices whose inventory changed since their summary rows were computed.
-- seq is the writing transaction's id: a refresh deletes the row only when
-- seq still holds the value it read before reading the inventory, so a write
-- that lands during a refresh leaves the device dirty. No foreign key: the
-- triggers fire inside cascaded deletes, and the runner removes orphans.
CREATE TABLE software_unapproved_presence_dirty (
    device_id  UUID        PRIMARY KEY,
    seq        BIGINT      NOT NULL,
    dirtied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- The cross-tenant bounded sweep consumes the oldest rows first.
CREATE INDEX software_unapproved_presence_dirty_order_idx
    ON software_unapproved_presence_dirty (dirtied_at, device_id);

-- Durable observed-alert checks. Inventory writes enqueue inside their own
-- transaction, so a failed or busy post-commit hook cannot lose a check.
-- No FK: inventory cascades can enqueue after deleting a device. The runner
-- drops these orphans. seq guards acknowledgement against a later write.
CREATE TABLE software_unapproved_detection_queue (
    device_id UUID PRIMARY KEY,
    seq BIGINT NOT NULL,
    apps_complete BOOLEAN NOT NULL DEFAULT FALSE,
    detect_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX software_unapproved_detection_queue_order_idx
    ON software_unapproved_detection_queue (queued_at, device_id);

-- Per tenant: policy_version counts resolution-relevant policy changes (bumped
-- by trigger inside the policy transaction); summary_version is the policy
-- version the whole summary was last rebuilt at. The summary is usable only
-- when a row exists and summary_version >= policy_version. A missing row
-- requires rebuild (or live fallback), never an implicitly current summary. No
-- foreign key, for the same cascade reason as the dirty table.
CREATE TABLE software_unapproved_presence_state (
    tenant_id         UUID        PRIMARY KEY,
    policy_version    BIGINT      NOT NULL DEFAULT 0,
    summary_version   BIGINT      NOT NULL DEFAULT 0,
    policy_changed_at TIMESTAMPTZ,
    reconciled_at     TIMESTAMPTZ
);
CREATE INDEX software_unapproved_presence_state_stale_idx
    ON software_unapproved_presence_state (tenant_id) WHERE summary_version < policy_version;

ALTER TABLE software_unapproved_episodes ADD COLUMN policy_version BIGINT;

-- Scheduling metadata is separate from the work's locked rows. Stamp before
-- attempting work; unattempted/least-recently attempted work goes first, so
-- repeated failures cannot occupy every bounded selector window forever.
-- Successful work deletes its stamp; maintenance prunes missed completions.
CREATE TABLE software_unapproved_runner_attempts (
    work_kind TEXT NOT NULL CHECK (work_kind IN ('summary', 'marked')),
    tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    batch_key TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (work_kind, tenant_id, batch_key)
);
CREATE INDEX software_unapproved_episodes_pending_batch_idx
    ON software_unapproved_episodes (tenant_id, batch_id)
    WHERE raised_at IS NULL AND source IN ('portal', 'operator');

CREATE FUNCTION software_unapproved_presence_mark_dirty(p_device UUID) RETURNS void AS $$
    INSERT INTO software_unapproved_presence_dirty (device_id, seq, dirtied_at)
    VALUES (p_device, txid_current(), now())
    ON CONFLICT (device_id) DO UPDATE SET seq = EXCLUDED.seq, dirtied_at = EXCLUDED.dirtied_at
    WHERE software_unapproved_presence_dirty.seq <> EXCLUDED.seq;
    INSERT INTO software_unapproved_detection_queue (device_id, seq, queued_at)
    VALUES (p_device, txid_current(), now())
    ON CONFLICT (device_id) DO UPDATE SET seq = EXCLUDED.seq, queued_at = EXCLUDED.queued_at,
        apps_complete = FALSE, detect_allowed = TRUE
    WHERE software_unapproved_detection_queue.seq <> EXCLUDED.seq;
$$ LANGUAGE sql;

CREATE FUNCTION software_unapproved_presence_dirty_trg() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM software_unapproved_presence_mark_dirty(OLD.device_id);
        RETURN OLD;
    END IF;
    PERFORM software_unapproved_presence_mark_dirty(NEW.device_id);
    IF TG_OP = 'UPDATE' AND OLD.device_id IS DISTINCT FROM NEW.device_id THEN
        PERFORM software_unapproved_presence_mark_dirty(OLD.device_id);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION software_unapproved_presence_device_trg() RETURNS trigger AS $$
BEGIN
    PERFORM software_unapproved_presence_mark_dirty(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION software_unapproved_presence_policy_trg() RETURNS trigger AS $$
DECLARE
    t UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        t := OLD.tenant_id;
    ELSE
        t := NEW.tenant_id;
    END IF;
    INSERT INTO software_unapproved_presence_state (tenant_id, policy_version, summary_version, policy_changed_at)
    VALUES (t, 1, 0, now())
    ON CONFLICT (tenant_id) DO UPDATE
        SET policy_version = software_unapproved_presence_state.policy_version + 1,
            policy_changed_at = now();
    IF TG_OP = 'UPDATE' AND OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
        INSERT INTO software_unapproved_presence_state (tenant_id, policy_version, summary_version, policy_changed_at)
        VALUES (OLD.tenant_id, 1, 0, now())
        ON CONFLICT (tenant_id) DO UPDATE
            SET policy_version = software_unapproved_presence_state.policy_version + 1,
                policy_changed_at = now();
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Inventory: dirty the device when a resolver input changes.
CREATE TRIGGER trg_unapproved_presence_device_apps_ins_del
    AFTER INSERT OR DELETE ON device_apps
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_device_apps_upd
    AFTER UPDATE ON device_apps
    FOR EACH ROW
    WHEN (OLD.device_id IS DISTINCT FROM NEW.device_id
       OR OLD.identifier IS DISTINCT FROM NEW.identifier
       OR OLD.identifier_kind IS DISTINCT FROM NEW.identifier_kind
       OR OLD.team_id IS DISTINCT FROM NEW.team_id
       OR OLD.name IS DISTINCT FROM NEW.name
       OR OLD.first_seen IS DISTINCT FROM NEW.first_seen)
    EXECUTE FUNCTION software_unapproved_presence_dirty_trg();

CREATE TRIGGER trg_unapproved_presence_device_extensions_ins_del
    AFTER INSERT OR DELETE ON device_browser_extensions
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_device_extensions_upd
    AFTER UPDATE ON device_browser_extensions
    FOR EACH ROW
    WHEN (OLD.device_id IS DISTINCT FROM NEW.device_id
       OR OLD.browser IS DISTINCT FROM NEW.browser
       OR OLD.extension_id IS DISTINCT FROM NEW.extension_id
       OR OLD.name IS DISTINCT FROM NEW.name
       OR OLD.first_seen IS DISTINCT FROM NEW.first_seen)
    EXECUTE FUNCTION software_unapproved_presence_dirty_trg();

CREATE TRIGGER trg_unapproved_presence_devices_upd
    AFTER UPDATE ON devices
    FOR EACH ROW
    WHEN (OLD.os IS DISTINCT FROM NEW.os OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id)
    EXECUTE FUNCTION software_unapproved_presence_device_trg();

CREATE TRIGGER trg_unapproved_presence_homebrew_current
    AFTER INSERT OR UPDATE OR DELETE ON homebrew_current_entries
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_homebrew_state_ins_del
    AFTER INSERT OR DELETE ON homebrew_device_state
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_homebrew_state_upd
    AFTER UPDATE ON homebrew_device_state
    FOR EACH ROW
    WHEN (OLD.device_id IS DISTINCT FROM NEW.device_id OR OLD.authority_at IS DISTINCT FROM NEW.authority_at)
    EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_homebrew_details
    AFTER INSERT OR UPDATE OR DELETE ON homebrew_observation_details
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_installations_ins_del
    AFTER INSERT OR DELETE ON software_installations
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_dirty_trg();
CREATE TRIGGER trg_unapproved_presence_installations_upd
    AFTER UPDATE ON software_installations
    FOR EACH ROW
    WHEN (OLD.device_id IS DISTINCT FROM NEW.device_id
       OR OLD.identity_fingerprint IS DISTINCT FROM NEW.identity_fingerprint
       OR OLD.first_seen_at IS DISTINCT FROM NEW.first_seen_at)
    EXECUTE FUNCTION software_unapproved_presence_dirty_trg();

-- Policies: bump the tenant's policy version on a resolution input change.
CREATE TRIGGER trg_unapproved_presence_app_policies_ins_del
    AFTER INSERT OR DELETE ON tenant_app_policies
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_policy_trg();
CREATE TRIGGER trg_unapproved_presence_app_policies_upd
    AFTER UPDATE ON tenant_app_policies
    FOR EACH ROW
    WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.team_id IS DISTINCT FROM NEW.team_id
       OR OLD.bundle_id IS DISTINCT FROM NEW.bundle_id
       OR OLD.winget_id IS DISTINCT FROM NEW.winget_id
       OR OLD.name IS DISTINCT FROM NEW.name
       OR OLD.platform IS DISTINCT FROM NEW.platform
       OR OLD.policy IS DISTINCT FROM NEW.policy)
    EXECUTE FUNCTION software_unapproved_presence_policy_trg();
CREATE TRIGGER trg_unapproved_presence_extension_policies_ins_del
    AFTER INSERT OR DELETE ON tenant_extension_policies
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_policy_trg();
CREATE TRIGGER trg_unapproved_presence_extension_policies_upd
    AFTER UPDATE ON tenant_extension_policies
    FOR EACH ROW
    WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.browser IS DISTINCT FROM NEW.browser
       OR OLD.extension_id IS DISTINCT FROM NEW.extension_id
       OR OLD.policy IS DISTINCT FROM NEW.policy)
    EXECUTE FUNCTION software_unapproved_presence_policy_trg();
CREATE TRIGGER trg_unapproved_presence_homebrew_policies_ins_del
    AFTER INSERT OR DELETE ON tenant_homebrew_policies
    FOR EACH ROW EXECUTE FUNCTION software_unapproved_presence_policy_trg();
CREATE TRIGGER trg_unapproved_presence_homebrew_policies_upd
    AFTER UPDATE ON tenant_homebrew_policies
    FOR EACH ROW
    WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.kind IS DISTINCT FROM NEW.kind
       OR OLD.name IS DISTINCT FROM NEW.name
       OR OLD.tap IS DISTINCT FROM NEW.tap
       OR OLD.policy IS DISTINCT FROM NEW.policy)
    EXECUTE FUNCTION software_unapproved_presence_policy_trg();

-- Every existing tenant starts unreconciled; the runner rebuilds it.
INSERT INTO software_unapproved_presence_state (tenant_id, policy_version, summary_version, policy_changed_at)
SELECT id, 1, 0, now() FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_presence TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_presence_devices TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_presence_dirty TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_detection_queue TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_presence_state TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_runner_attempts TO patched;

INSERT INTO schema_migrations (version) VALUES ('0202_unapproved_presence_summary')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
