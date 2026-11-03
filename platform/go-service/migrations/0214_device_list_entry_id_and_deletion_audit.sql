-- patched.im - 0214_device_list_entry_id_and_deletion_audit.sql
-- PAT-2271: finishes PAT-2212 (portal /devices "Your device list" card).
--
-- 1. device_list_entries gets a stable identity column so the portal can
--    target one entry for deletion. The existing composite PK
--    (upload_id, position) is unchanged; id is additive and UNIQUE.
--    Exposed by GET /v1/portal/device-list on every on_list_never_seen row
--    and on the entry side of the new matched row (internal/devicelist.Entry.ID).
--
-- 2. device_list_entry_deletions: append-only audit of one
--    DELETE /v1/portal/device-list/entries/{entryID}. Same shape and
--    reasoning as device_retirement_decisions (0193): no FK to tenants (a
--    cascade DELETE would hit the append-only trigger and make tenant purge
--    fail, 0091/0096) and no FK to device_list_uploads or device_list_entries
--    either — the row being deleted, and potentially an upload purged later
--    by tenant deletion, must not erase or block the customer's own record
--    of having deleted it.
--
--    Append-only (0096 pattern): UPDATE, DELETE and TRUNCATE are rejected by
--    trigger. That stops an accidental write, not the owning role `patched`,
--    which can disable the trigger or drop the table (AGENTS.md). Do not
--    describe this table as tamper-proof.
--
-- 3. Grants the app role did not need until now: the existing bulk
--    PUT/DELETE endpoints only ever INSERT into device_list_entries and
--    device_list_uploads. The new per-entry delete removes exactly one
--    device_list_entries row and keeps its upload's entry_count in step, so
--    `patched` needs DELETE on device_list_entries and UPDATE on
--    device_list_uploads.entry_count (column-scoped: no other column of
--    that table is writable by the app).
--
-- Additive only. Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0214_device_list_entry_id_and_deletion_audit.sql

BEGIN;

ALTER TABLE device_list_entries ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY;
ALTER TABLE device_list_entries ADD CONSTRAINT device_list_entries_id_key UNIQUE (id);

COMMENT ON COLUMN device_list_entries.id IS
    'PAT-2271: stable per-entry id, additive. Lets the portal target one entry for DELETE /v1/portal/device-list/entries/{entryID} without relying on (upload_id, position), which is not stable across uploads.';

CREATE TABLE device_list_entry_deletions (
    id           BIGSERIAL   PRIMARY KEY,
    tenant_id    UUID        NOT NULL,
    upload_id    BIGINT      NOT NULL,
    entry_id     BIGINT      NOT NULL,
    position     INT         NOT NULL,
    hostname     TEXT,
    serial       TEXT,
    -- The verified portal email of the admin who deleted the entry, lower
    -- case, as device_retirement_decisions.actor_email.
    actor_email  TEXT        NOT NULL CHECK (btrim(actor_email) <> '' AND length(actor_email) <= 320),
    deleted_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_device_list_entry_deletions_tenant
    ON device_list_entry_deletions (tenant_id, id DESC);

CREATE FUNCTION reject_device_list_entry_deletions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_list_entry_deletions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_list_entry_deletions_append_only
    BEFORE UPDATE OR DELETE ON device_list_entry_deletions
    FOR EACH ROW
    EXECUTE FUNCTION reject_device_list_entry_deletions_mutation();

CREATE FUNCTION reject_device_list_entry_deletions_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_list_entry_deletions is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_list_entry_deletions_append_only_truncate
    BEFORE TRUNCATE ON device_list_entry_deletions
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_device_list_entry_deletions_truncate();

COMMENT ON TABLE device_list_entry_deletions IS
    'PAT-2271: append-only audit of one customer portal per-entry device-list deletion. UPDATE, DELETE and TRUNCATE rejected by trigger (not tamper-proof: the owning role can disable it). No FK to tenants, device_list_uploads or device_list_entries on purpose.';

GRANT SELECT, INSERT ON TABLE device_list_entry_deletions TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_list_entry_deletions_id_seq TO patched;

GRANT DELETE ON TABLE device_list_entries TO patched;
GRANT UPDATE (entry_count) ON TABLE device_list_uploads TO patched;

INSERT INTO schema_migrations (version) VALUES ('0214_device_list_entry_id_and_deletion_audit')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
