-- patched.im — 0124_intune_config_snapshots.sql
-- PAT-1662: versioned, immutable, per-tenant snapshots of Intune
-- configuration objects and their assignments — raw material for a later
-- diff/change-list/rollback ticket (not this one).
--
-- Two tables, append-only, never UPDATEd — same pattern as raw_payloads /
-- provenance_records:
--
--   intune_config_snapshots — one header row per pull run (per tenant, per
--   object_type). status is decided BEFORE this row is written (the whole
--   pull, including any mid-run failure, happens in application code first),
--   so this table is INSERT-only: there is never a reason to go back and
--   flip status on a row already committed.
--
--   intune_config_objects — one row per object per snapshot run, including
--   objects that did not change (their prior raw_body/raw_assignments are
--   copied forward verbatim so the new snapshot still diffs clean against
--   the old one without a single extra Graph call) and tombstones for
--   objects that disappeared (change_kind = 'disappeared', raw_body/
--   raw_assignments NULL).
--
-- api_version is recorded on every snapshot even though this ticket only
-- ever writes 'v1.0', so a later beta-object addition's failures trace to
-- the beta surface, not to this core schema.
--
-- A 'partial' snapshot is a first-class, queryable state, not a TODO bolted
-- on later: a partial pull must never be usable as a diff baseline (it would
-- read as "everything not re-observed got deleted"), so intune_config_store
-- .PriorObjects only ever looks at the latest snapshot with status =
-- 'complete' for a given (tenant_id, object_type).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0124_intune_config_snapshots.sql
BEGIN;

CREATE TABLE intune_config_snapshots (
    id            BIGSERIAL   PRIMARY KEY,
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    object_type   TEXT        NOT NULL CHECK (object_type IN ('compliance_policy')),
    api_version   TEXT        NOT NULL CHECK (api_version IN ('v1.0', 'beta')),
    started_at    TIMESTAMPTZ NOT NULL,
    completed_at  TIMESTAMPTZ NOT NULL,
    status        TEXT        NOT NULL CHECK (status IN ('complete', 'partial')),
    error         TEXT,       -- populated when status = 'partial'
    object_count  INTEGER     NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The query PriorObjects runs on every snapshot run: "the latest complete
-- snapshot for this tenant+object_type". Partial rows are deliberately not
-- part of this index's selectivity concern — the query still filters
-- status = 'complete' explicitly in SQL (belt and braces: an index alone is
-- not a substitute for the WHERE clause being right).
CREATE INDEX idx_intune_config_snapshots_latest
    ON intune_config_snapshots (tenant_id, object_type, status, started_at DESC, id DESC);

CREATE TABLE intune_config_objects (
    id                      BIGSERIAL   PRIMARY KEY,
    snapshot_id             BIGINT      NOT NULL REFERENCES intune_config_snapshots(id) ON DELETE CASCADE,
    graph_object_id         TEXT        NOT NULL,
    last_modified_date_time TIMESTAMPTZ,            -- NULL for change_kind = 'disappeared'
    change_kind             TEXT        NOT NULL CHECK (change_kind IN (
                                'appeared', 'unchanged', 'refreshed', 'disappeared')),
    body_changed            BOOLEAN     NOT NULL DEFAULT false,
    assignments_changed     BOOLEAN     NOT NULL DEFAULT false,
    raw_body                JSONB,                  -- verbatim Graph object body; NULL only for tombstones
    raw_assignments         JSONB,                  -- verbatim Graph assignments array; NULL only for tombstones
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, graph_object_id)
);

CREATE INDEX idx_intune_config_objects_snapshot ON intune_config_objects (snapshot_id);

COMMENT ON TABLE intune_config_snapshots IS
    'One row per Intune config pull run per tenant/object_type. Immutable — never UPDATE a row after insert; a new run is always a new row.';
COMMENT ON TABLE intune_config_objects IS
    'One row per object per snapshot run, including objects carried forward unchanged and disappeared tombstones. raw_body/raw_assignments are the verbatim Graph response bodies a later rollback artefact is generated from — never store a lossy parse here instead.';

GRANT SELECT, INSERT ON TABLE intune_config_snapshots TO patched;
GRANT SELECT, INSERT ON TABLE intune_config_objects TO patched;
GRANT USAGE, SELECT ON SEQUENCE intune_config_snapshots_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE intune_config_objects_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0124_intune_config_snapshots')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
