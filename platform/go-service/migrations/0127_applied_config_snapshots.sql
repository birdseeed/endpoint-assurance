-- patched.im — 0127_applied_config_snapshots.sql
-- PAT-1668: append-only, immutable, per-device snapshots of the
-- configuration actually APPLIED on a Mac — the raw material the
-- internal/appliedconfig diff and estate rollup run over.
--
-- Storage for the macOS agent's applied_configuration object (PAT-1667,
-- updater/macos/lib/config_profiles.sh). Until this migration nothing on the
-- platform side parsed or stored that object at all.
--
-- APPLIED CONFIGURATION IS NOT AUTHORED POLICY. Every row here says "this is
-- what was observed on this device at this time". There is deliberately no
-- policy id, no policy name and no actor column anywhere below, and nothing
-- in this schema may be joined to intune_config_objects (0124) as though the
-- two described the same record. A Mac managed by Intune produces related
-- rows in both places; that is one change with two independent observations,
-- and counting them together double-counts. Keep them separate.
--
-- Two tables, append-only, never UPDATEd — same pattern as raw_payloads /
-- provenance_records / intune_config_snapshots:
--
--   applied_config_snapshots — one header row per device per collection run.
--   collection_status is decided by the agent on the device, before the
--   payload is ever sent, so this table is INSERT-only: there is never a
--   reason to go back and flip a committed row's status.
--
--   applied_config_profiles — one row per profile per snapshot run, stored
--   verbatim. Every run records the full observed list, including profiles
--   that did not change, so any two snapshots diff cleanly against each
--   other with no carry-forward logic and no reparse.
--
-- WHY payload IS TEXT AND NOT JSONB. The agent head-caps each profile's
-- serialised payload at a fixed byte budget, so a large profile arrives as a
-- truncated fragment that is not valid JSON and would be rejected by a JSONB
-- column. Storing the fragment verbatim in TEXT preserves exactly what was
-- observed; re-serialising it into something JSONB would accept would be the
-- lossy reparse 0124's own comment forbids. payload_capped says which rows
-- are fragments.
--
-- WHY A NON-OK collection_status ROW IS STILL STORED. macOS rate-limits the
-- `profiles` family to roughly one call per 23 hours; on a rate-limited or
-- failed run the agent serves its last-known-good cache rather than failing
-- the whole inventory upload. Those runs are recorded so "the collection
-- could not read state" stays visible and distinguishable from "the device
-- reported zero profiles" and from "the device stopped reporting at all".
-- They are never used as a diff baseline — internal/appliedconfig.Diff
-- rejects them outright, the same rule 0124's 'partial' status carries.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0127_applied_config_snapshots.sql
BEGIN;

CREATE TABLE applied_config_snapshots (
    id                      BIGSERIAL   PRIMARY KEY,
    tenant_id               UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id               UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- The raw_payloads row this observation was extracted from. Not a
    -- foreign key: raw_payloads is partitioned and its primary key is the
    -- composite (id, received_at), so both halves are recorded instead.
    -- The UNIQUE below makes re-extraction of an already-extracted payload a
    -- no-op rather than a duplicate snapshot.
    raw_payload_id          BIGINT      NOT NULL,
    raw_payload_received_at TIMESTAMPTZ NOT NULL,

    -- The agent's own collected_at: when the device looked like this, not
    -- when the server heard about it. Every change this data supports is
    -- reported as a window between two of these, never as a single event
    -- time, because no single event time is observable.
    observed_at             TIMESTAMPTZ NOT NULL,

    collection_status       TEXT        NOT NULL CHECK (collection_status IN ('ok', 'rate_limited', 'unavailable')),

    -- profiles_count is the count the agent reported; it can exceed the
    -- number of applied_config_profiles rows when profiles_truncated is
    -- true, which is exactly what that flag is for. A truncated list cannot
    -- support an absence claim.
    profiles_count          INTEGER     NOT NULL DEFAULT 0,
    profiles_truncated      BOOLEAN     NOT NULL DEFAULT false,

    -- The enrolled management server, NULL when the Mac is unenrolled. This
    -- is the only attribution stored here: which platform manages the
    -- device, never which policy produced a profile.
    mdm_server_url          TEXT,
    mdm_supervised          TEXT        NOT NULL DEFAULT 'Unknown' CHECK (mdm_supervised IN ('Yes', 'No', 'Unknown')),

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (device_id, raw_payload_id)
);

-- The query the diff pass runs: "this device's most recent ok observations".
-- collection_status is in the index and still filtered explicitly in SQL —
-- an index is not a substitute for the WHERE clause being right.
CREATE INDEX idx_applied_config_snapshots_device_latest
    ON applied_config_snapshots (device_id, collection_status, observed_at DESC, id DESC);

-- The tenant-wide sweep's entry point.
CREATE INDEX idx_applied_config_snapshots_tenant_observed
    ON applied_config_snapshots (tenant_id, observed_at DESC);

CREATE TABLE applied_config_profiles (
    id                 BIGSERIAL   PRIMARY KEY,
    snapshot_id        BIGINT      NOT NULL REFERENCES applied_config_snapshots(id) ON DELETE CASCADE,

    -- ordinal preserves the agent's own list order verbatim. There is no
    -- UNIQUE (snapshot_id, profile_identifier): a profile the agent could
    -- not decode arrives with an empty identifier, and a device is not
    -- guaranteed to report distinct identifiers. Storing what was observed
    -- and letting the diff engine record the ambiguity beats rejecting the
    -- observation or silently collapsing rows.
    ordinal            INTEGER     NOT NULL,

    profile_identifier TEXT        NOT NULL DEFAULT '',
    display_name       TEXT        NOT NULL DEFAULT '',
    organization       TEXT        NOT NULL DEFAULT '',

    -- Verbatim as the agent sent it. TEXT, not JSONB — see the header.
    payload            TEXT,
    payload_capped     BOOLEAN     NOT NULL DEFAULT false,

    -- The agent itself could not serialise this profile's payload. The
    -- profile is genuinely present on the device; its payload content is
    -- unknown. An unknown payload is never read as an empty one.
    decode_error       BOOLEAN     NOT NULL DEFAULT false,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_applied_config_profiles_snapshot ON applied_config_profiles (snapshot_id, ordinal);

COMMENT ON TABLE applied_config_snapshots IS
    'One row per macOS device per applied-configuration collection run (PAT-1668). Immutable — never UPDATE a row after insert; a new run is always a new row. This is configuration OBSERVED on the device, not authored MDM policy: no policy identity and no actor is recorded because neither is observable from the endpoint.';
COMMENT ON TABLE applied_config_profiles IS
    'One row per configuration profile per snapshot run, stored verbatim including head-capped payload fragments. payload is TEXT because a capped payload is not valid JSON; never re-serialise it into JSONB, that reparse is lossy.';
COMMENT ON COLUMN applied_config_snapshots.collection_status IS
    'ok = the run read real state. rate_limited/unavailable = the run happened but could not read state (the agent served a cached list); such a snapshot is stored and flagged but must NEVER be used as a diff baseline, or a failed collection reads as every profile having vanished.';
COMMENT ON COLUMN applied_config_snapshots.observed_at IS
    'The agent collected_at for this run. Changes derived from these rows are always reported as a window between two observations, never as a single event time.';

GRANT SELECT, INSERT ON TABLE applied_config_snapshots TO patched;
GRANT SELECT, INSERT ON TABLE applied_config_profiles TO patched;
GRANT USAGE, SELECT ON SEQUENCE applied_config_snapshots_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE applied_config_profiles_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0127_applied_config_snapshots')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
