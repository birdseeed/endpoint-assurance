-- patched.im - 0193_device_retirement_and_device_list.sql
-- PAT-2135: two customer self-service writes from the portal /devices page,
-- replacing the "Tell us it's gone" and "Send us a device list" mailto links
-- (ruled 2026-09-25: self-service, no Patched person acts for the customer).
--
-- 1. device_retirement_decisions: a customer portal admin's "Retire device"
--    decision, and its reversal. Append-only; the device's current state is
--    the action of its latest row (highest id). Unretiring records a new
--    'unretire' row, nothing is ever updated or deleted. The API writes a row
--    only when the state actually changes, under a per-device advisory lock,
--    so ids are in decision order for one device.
--
--    This is deliberately separate from device_dispositions (0143, PAT-1825).
--    Those are operator records written through the admin API and are
--    superseded automatically when the device reports again. A customer
--    retirement is never undone automatically: a device that reports after
--    being retired stays retired and is flagged reported_after_retirement
--    by the read API, because only the customer can reverse the decision.
--
--    Same shape and rules as software_approval_decisions (0182): no FK to
--    tenants (a cascade DELETE would hit the append-only trigger and make
--    tenant purge fail, 0091/0096), and no FK to devices either, since an
--    operator can delete a devices row (admin_overview.go) and that must not
--    be blocked by, or erase, the customer's recorded decision.
--
--    Append-only (0096 pattern): UPDATE, DELETE and TRUNCATE are rejected by
--    trigger. That stops an accidental write, not the owning role `patched`,
--    which can disable the trigger or drop the table (AGENTS.md). Do not
--    describe this table as tamper-proof.
--
-- 2. device_list_uploads + device_list_entries: the customer's own list of
--    the devices they expect to have, uploaded from the portal (the portal
--    parses the CSV and sends JSON). One uploads row per upload, the current
--    list is the tenant's latest row (highest id). A row with cleared = TRUE
--    records that the customer removed their list (DELETE
--    /v1/portal/device-list). Earlier uploads are kept as history; the
--    application only ever inserts.
--
--    Separate from device_upload_lists (0140, PAT-1595), which is the
--    operator-side upload behind /admin/tenants/{id}/device-uploads and is
--    left unchanged. These rows hold the customer's device names and serial
--    numbers, so unlike the decision audit they are tenant data: FK to
--    tenants ON DELETE CASCADE, no append-only trigger, so tenant purge
--    removes them.
--
-- Additive only. Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0193_device_retirement_and_device_list.sql

BEGIN;

CREATE TABLE device_retirement_decisions (
    id           BIGSERIAL   PRIMARY KEY,
    tenant_id    UUID        NOT NULL,
    device_id    UUID        NOT NULL,
    action       TEXT        NOT NULL CHECK (action IN ('retire', 'unretire')),
    reason       TEXT        CHECK (reason IS NULL OR (btrim(reason) <> '' AND char_length(reason) <= 500)),
    -- The verified portal email of the admin who made the decision, lower
    -- case, as software_approval_decisions.actor_email.
    actor_email  TEXT        NOT NULL CHECK (btrim(actor_email) <> '' AND length(actor_email) <= 320),
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Latest decision per device, and one device's history newest first.
CREATE INDEX idx_device_retirement_decisions_device
    ON device_retirement_decisions (tenant_id, device_id, id DESC);

CREATE FUNCTION reject_device_retirement_decisions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_retirement_decisions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_retirement_decisions_append_only
    BEFORE UPDATE OR DELETE ON device_retirement_decisions
    FOR EACH ROW
    EXECUTE FUNCTION reject_device_retirement_decisions_mutation();

CREATE FUNCTION reject_device_retirement_decisions_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_retirement_decisions is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_retirement_decisions_append_only_truncate
    BEFORE TRUNCATE ON device_retirement_decisions
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_device_retirement_decisions_truncate();

COMMENT ON TABLE device_retirement_decisions IS
    'PAT-2135: append-only customer portal Retire device decisions. Current state per device = action of the row with the highest id. Never auto-reversed by a device reporting again. UPDATE, DELETE and TRUNCATE rejected by trigger (not tamper-proof: the owning role can disable it). No FK to tenants or devices on purpose.';

GRANT SELECT, INSERT ON TABLE device_retirement_decisions TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_retirement_decisions_id_seq TO patched;

CREATE TABLE device_list_uploads (
    id           BIGSERIAL   PRIMARY KEY,
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_email  TEXT        NOT NULL CHECK (btrim(actor_email) <> '' AND length(actor_email) <= 320),
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    filename     TEXT        CHECK (filename IS NULL OR (btrim(filename) <> '' AND char_length(filename) <= 255)),
    entry_count  INT         NOT NULL CHECK (entry_count >= 0 AND entry_count <= 10000),
    -- TRUE records the customer clearing their list: no entries, and the
    -- tenant has no current list until the next upload.
    cleared      BOOLEAN     NOT NULL DEFAULT FALSE,
    CHECK (NOT cleared OR (entry_count = 0 AND filename IS NULL))
);

CREATE INDEX idx_device_list_uploads_tenant_latest
    ON device_list_uploads (tenant_id, id DESC);

COMMENT ON TABLE device_list_uploads IS
    'PAT-2135: one row per customer device list upload (or clear) from the portal. The tenant''s current list is its highest-id row unless that row is cleared. Insert-only by the application; FK cascade so tenant purge removes it.';

GRANT SELECT, INSERT ON TABLE device_list_uploads TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_list_uploads_id_seq TO patched;

CREATE TABLE device_list_entries (
    upload_id            BIGINT  NOT NULL REFERENCES device_list_uploads(id) ON DELETE CASCADE,
    -- Index of the entry's first occurrence in the uploaded entries array
    -- (duplicates are collapsed before storage).
    position             INT     NOT NULL CHECK (position >= 0),
    hostname             TEXT    CHECK (hostname IS NULL OR char_length(hostname) <= 255),
    hostname_normalized  TEXT    CHECK (hostname_normalized IS NULL OR char_length(hostname_normalized) <= 255),
    serial               TEXT    CHECK (serial IS NULL OR char_length(serial) <= 255),
    serial_normalized    TEXT    CHECK (serial_normalized IS NULL OR char_length(serial_normalized) <= 255),
    PRIMARY KEY (upload_id, position),
    CHECK (hostname_normalized IS NOT NULL OR serial_normalized IS NOT NULL)
);

COMMENT ON TABLE device_list_entries IS
    'PAT-2135: the entries of one device_list_uploads row. serial_normalized is trimmed and upper case, NULL for a placeholder serial; hostname_normalized is trimmed, lower case, trailing dots and one trailing .local removed. Matching rules (serial, hostname, unique first-label fallback) live in internal/devicelist.';

GRANT SELECT, INSERT ON TABLE device_list_entries TO patched;

INSERT INTO schema_migrations (version) VALUES ('0193_device_retirement_and_device_list')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
