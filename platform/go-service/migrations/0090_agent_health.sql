-- patched.im — 0090_agent_health.sql
-- PAT-1064: the server half of the degraded-capability channel. Both
-- endpoint agents (macOS PAT-1065, Windows PAT-1066) can be handed a
-- directive they cannot carry out — a log-upload directive for a device_id
-- the agent no longer recognises, a removal directive for a library it never
-- installed, a catalogue sync that has never once succeeded. Today that
-- fault is written to a local log and the run continues; nothing upstream
-- ever learns. Three such faults ran silently on a real endpoint for weeks
-- (1,119 / 1,105 / every-run occurrences) while the device reported itself
-- completely healthy in every other signal it sent. This table is where the
-- agent's own admission of "I could not do what you asked, and here is why"
-- finally gets a durable, queryable home.
--
-- Carried over the existing POST /v1/inventory payload as an optional
-- top-level agent_health.degraded array (see docs/PAYLOAD_SCHEMA.md and
-- docs/payload.schema.json) — deliberately not /v1/posture, which is a GET
-- (server hands policy DOWN to the agent; the wrong direction for the agent
-- reporting UP). Decoded defensively in internal/extractor/upsert.go
-- (parseAgentHealth / sanitizeAgentHealthEntries), same PAT-871/PAT-948
-- posture as backup_status and browser_extensions: a malformed section or a
-- single malformed entry is logged and skipped, never fatal to the rest of
-- the device's inventory upload.
--
-- One row per device per distinct (kind, subject) — PAT-1029's "aggregate,
-- never per-run" constraint, the same reason device_browser_extensions and
-- device_certificates are keyed on identity rather than accumulating a row
-- per ingest. PRIMARY KEY (device_id, kind, subject) is therefore both the
-- identity and the ON CONFLICT target: re-reporting the same fault updates
-- the existing row (last_seen/count/reason refresh) instead of piling up
-- duplicates, and a capability that recovers is DELETEd by the extractor
-- (upsertAgentHealth) rather than left to rot as a stale row nobody re-reads.
--
-- kind/subject/reason are free-form text, not enum-constrained at the
-- database or ingestion layer. docs/PAYLOAD_SCHEMA.md documents the
-- vocabulary both agents draw from (directive_skipped/capability_missing/
-- sync_never_succeeded, seeded from the three faults above) as a CONVENTION,
-- not a CHECK constraint or a validate.go enum rejection — an agent release
-- that introduces a new fault kind must still have its row stored verbatim
-- rather than have its entire inventory upload rejected for using a value
-- the server doesn't recognise yet. See docs/PAYLOAD_SCHEMA.md for why this
-- is stated explicitly: it is the thing a future "let's tighten this up"
-- pass would get wrong.
--
-- ever_succeeded is reported by the agent, never recomputed server-side: the
-- agent is the only party that has ever observed whether this capability
-- worked, even once, in its history on this device. That is precisely the
-- distinction the current local-log-only behaviour destroys — a fault that
-- has "never worked" and a fault that "stopped working" look identical from
-- a cold server that only ever sees the current snapshot.
--
-- device_id cascades on delete, matching device_browser_extensions (0018):
-- this table has no independent lifecycle from the device it describes.
--
-- collected_at is the PRODUCING PAYLOAD's own "collected_at" claim, not the
-- server's receive time. It exists because this is the only section in the
-- extractor that DELETES: every other section is a last-write-wins
-- overwrite, where the extractor's claim/retry ordering being unspecified
-- (an older payload can be processed after a newer one, e.g. on retry of a
-- previously-failed row) is harmless — the newest write still wins
-- eventually and nothing is ever destroyed. For agent_health, an older
-- payload processed out of order could otherwise clear or prune faults a
-- newer payload had correctly recorded, showing a device as recovered when
-- it is not. Stored per-row as descriptive telemetry (when THIS fault was
-- last confirmed present) — but as of the watermark table below, it does
-- NOT itself gate any write. An earlier version of this migration used
-- MAX(collected_at) over these rows as the recency gate; that broke in two
-- ways a plain per-row column cannot fix (see device_agent_health_watermark
-- below), so the gate moved to its own table and this column is now
-- informational only.
--
-- NOT NULL with no default: every payload that reaches upsertAgentHealth
-- carries a parsed collected_at (extractor.go parses payload.collected_at,
-- a required top-level field, before calling in) or the extractor's own
-- safe fallback (the zero time, which always loses every recency
-- comparison and therefore never lets a parse failure be destructive) — so
-- the column is never actually written without a real value from one of
-- those two sources.
--
-- This migration has been amended in place twice (adding collected_at, then
-- device_agent_health_watermark) rather than shipped as 0091/0092: it has
-- not been applied to any real box yet (only local test databases), so
-- there is nothing to migrate forward from and no forward-only-migration
-- cost to amending instead.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0090_agent_health.sql
BEGIN;

CREATE TABLE device_agent_health (
    device_id      uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind           text        NOT NULL,             -- e.g. 'directive_skipped', 'capability_missing', 'sync_never_succeeded'
    subject        text        NOT NULL,             -- what the directive/capability was about, e.g. 'log_upload', 'extension_removal'
    reason         text        NOT NULL DEFAULT '',  -- why it could not be done, e.g. 'device_id_mismatch', 'lib_not_installed'
    first_seen     timestamptz NOT NULL,
    last_seen      timestamptz NOT NULL,
    count          bigint      NOT NULL CHECK (count >= 1),
    ever_succeeded boolean     NOT NULL,
    collected_at   timestamptz NOT NULL,              -- producing payload's own collected_at; descriptive only, see above
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, kind, subject)
);

COMMENT ON TABLE device_agent_health IS
    'Degraded-capability channel (PAT-1064): faults the agent could not act on, reported by both endpoint agents over POST /v1/inventory agent_health.degraded. One row per device per (kind, subject) — re-reports upsert in place, a recovered capability is deleted by the extractor. kind/subject/reason vocabulary is documented in docs/PAYLOAD_SCHEMA.md but NOT enum-enforced at ingestion or here. Write ordering is gated by device_agent_health_watermark, not by this table''s own collected_at column.';
COMMENT ON COLUMN device_agent_health.kind IS
    'Fault category. Documented vocabulary (docs/PAYLOAD_SCHEMA.md), not a CHECK-constrained enum: an agent release introducing a new kind must still ingest, not be rejected.';
COMMENT ON COLUMN device_agent_health.ever_succeeded IS
    'Reported by the agent, never inferred server-side. Distinguishes "has never worked" from "stopped working" — the agent is the only party that can know this, and today''s local-only logging is exactly what destroys the distinction.';
COMMENT ON COLUMN device_agent_health.collected_at IS
    'The producing payload''s own collected_at claim, not the server receive time. Descriptive only (when this fault was last confirmed present) — recency GATING for inserts/updates/clears/prunes is done against device_agent_health_watermark, not this column.';

-- Grouped-by-device admin read (GET /admin/tenants/{tenantID}/agent-health)
-- joins devices -> device_agent_health by device_id and needs every row for
-- a tenant's devices; the primary key already leads with device_id, so no
-- extra index is needed for that access path today.

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_agent_health TO patched;

-- device_agent_health_watermark: the recency gate for the whole agent_health
-- section, one row per device, independent of whether that device currently
-- has ANY degraded-capability rows. This is the fix for a real hole in the
-- first cut of the recency design (review round 3): deriving the watermark
-- from MAX(collected_at) over device_agent_health's own rows fails the
-- moment a newer payload reports degraded: [] — the DELETE removes every
-- row, and with them the only record of how recent the device's health data
-- is, so a delayed OLDER payload arriving afterwards finds no watermark at
-- all and resurrects faults that were correctly resolved. A per-row
-- ON CONFLICT ... WHERE guard has a second, narrower hole: it only blocks
-- an UPDATE, so an older payload naming a (kind, subject) that is NOT
-- currently in device_agent_health takes the unguarded INSERT path. A
-- watermark that survives having zero fault rows closes both.
--
-- upsertAgentHealth (internal/extractor/upsert.go) takes this row's lock
-- with SELECT ... FOR UPDATE (via an INSERT ... ON CONFLICT DO UPDATE ...
-- RETURNING, which creates the row with a sentinel value on first contact
-- and locks+returns the existing value otherwise) as the FIRST statement of
-- agent_health processing for that device, before any staleness decision —
-- this serialises all agent-health writes for one device within the
-- transactions that touch it, closing a race where a concurrent older
-- transaction reads a not-yet-stale watermark, blocks on the lock, and only
-- proceeds (now stale, but already past its own read) after a newer
-- transaction commits.
--
-- collected_at here has no default: the lock-acquire query always supplies
-- a sentinel value explicitly for a first-contact device
-- (agentHealthWatermarkSentinel, the Unix epoch — deliberately NOT
-- '-infinity'::timestamptz, which pgx v5 cannot scan into a plain
-- time.Time; see the doc comment on agentHealthWatermarkSentinel in
-- upsert.go for why '-infinity' was tried first and rejected). The epoch
-- compares older than any real payload timestamp and therefore never blocks
-- a device's very first agent_health section.
CREATE TABLE device_agent_health_watermark (
    device_id    uuid        PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    collected_at timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE device_agent_health_watermark IS
    'Per-device recency gate for the agent_health degraded-capability channel (PAT-1064), independent of device_agent_health''s own row count so it survives an all-clear (degraded: []) wiping every fault row. Locked with SELECT ... FOR UPDATE as the first step of upsertAgentHealth, before any staleness decision, to serialise concurrent agent-health writes for one device. Advanced only when an incoming payload''s collected_at is >= the stored value AND not more than agentHealthFutureTolerance (5 minutes) ahead of the server''s own clock; an older, out-of-order payload OR an implausibly-far-future one (broken agent clock) is rejected here before it can touch device_agent_health at all, and before it can advance this watermark and permanently wedge the device''s future reports (review round 5, FIX 14).';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_agent_health_watermark TO patched;

INSERT INTO schema_migrations (version) VALUES ('0090_agent_health')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
