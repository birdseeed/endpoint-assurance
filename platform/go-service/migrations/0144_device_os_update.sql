-- patched.im — 0144_device_os_update.sql
-- PAT-1806 (platform slice): server-side receiving/persisting/rollup for the
-- OS-update-currency verdict both endpoint agents already compute locally
-- (SOFA feed on macOS, WUA COM on Windows) but do not yet upload. This
-- migration adds only the table the extractor and rollup need; the agents
-- themselves start sending os_update in a separate follow-up ticket in the
-- `updater` repo once this exists for them to send to — out of scope here,
-- this repo owns only the platform-neutral contract (see AGENTS.md).
--
-- One row per device, upserted on every ingest that carries an os_update
-- block — current-state snapshot, same pattern as device_hardware (0014),
-- not an append-only history. A payload that omits os_update entirely
-- (every agent today) leaves the row untouched — see upsertOSUpdate
-- (internal/extractor/upsert.go). A device with no row here has never
-- reported this block at all: "not reported", never "current" (absence
-- requires authority, root AGENTS.md — the same discipline PAT-1805
-- established for devices.pending_updates).
--
-- reported_at is the server's own timestamp of the last ingest that carried
-- this block, not an agent-supplied field — same convention
-- device_hardware.collected_at uses.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0144_device_os_update.sql

BEGIN;

CREATE TABLE device_os_update (
    id                   BIGSERIAL   PRIMARY KEY,
    device_id            UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    installed_os         TEXT        NOT NULL,
    latest_os            TEXT        NOT NULL,
    target_os            TEXT,
    state                TEXT        NOT NULL,
    severity             TEXT,
    security_relevant    BOOLEAN     NOT NULL DEFAULT false,
    actively_exploited   BOOLEAN     NOT NULL DEFAULT false,
    deferrals_remaining  INTEGER,
    release_age_days     INTEGER,
    deadline             TIMESTAMPTZ,
    reported_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id)
);

-- No separate index on device_id: the UNIQUE (device_id) constraint above
-- already creates one; a duplicate CREATE INDEX would just be a second
-- copy of the same btree.
CREATE INDEX idx_device_os_update_state ON device_os_update(state);

COMMENT ON TABLE device_os_update IS
    'One row per device — the OS-update-currency verdict the endpoint agent already computed locally (SOFA feed on macOS, WUA COM on Windows; PAT-1806). Upserted on each ingest carrying an os_update block; absent block leaves the existing row untouched (COALESCE-preserve, same discipline as devices.pending_updates). A device with no row here has never reported this block at all — "not reported", not "current" (absence requires authority, root AGENTS.md).';
COMMENT ON COLUMN device_os_update.state IS
    'Agent-supplied verdict string, e.g. "current" | "behind" — not enum-enforced server-side; stored verbatim so a future agent release adding a state never has its report rejected. Canonical value is lowercase "current" -- report.FetchOSUpdateStatus does an exact string match, so "Current"/"CURRENT" would be (mis)classified as behind. The agent-side follow-up ticket (updater repo) must emit lowercase; this is not case-normalized server-side because the agent verdict vocabulary is intentionally stored verbatim (see above), and silently lowercasing would blur the line between "the agent said X" and "the server interpreted X".';
COMMENT ON COLUMN device_os_update.reported_at IS
    'Server-assigned timestamp of the most recent ingest that carried an os_update block for this device — not an agent-supplied field, same convention as device_hardware.collected_at.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_os_update TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_os_update_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0144_device_os_update');

COMMIT;
