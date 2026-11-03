-- patched.im - 0161_event_driven_cve_match.sql
-- PAT-2024: change-driven CVE matching with per-product assessment state.
--
-- device_cve_findings used to be written only by the nightly patched-cve-sync
-- run. This migration adds the durable state for three change-driven triggers
-- (ingest delta, feed-sync delta, mapping publish) and for the assessment
-- state the portal reports per observed product. Everything here is additive:
-- no existing table or column changes, and the nightly full match keeps
-- working unchanged if every new table is empty.
--
--   cve_match_queue        bounded, durable work queue drained by the
--                          extractor. 'observation' rows name one
--                          (device, product) to re-match; 'mapping' rows name
--                          a published or changed CPE mapping, expanded by the
--                          worker into observation rows.
--   cve_match_assessments  last successful match per (device, product) for
--                          MAPPED products only. An unmapped product never has
--                          a row here, so it can never read as "matched, zero
--                          findings" (absence requires authority).
--   cve_mapping_snapshot   the app_cpe_mappings state the matcher last acted
--                          on. The worker diffs app_cpe_mappings against it to
--                          detect a publish, change or removal from any write
--                          path (migration, SQL, a future admin endpoint)
--                          without a trigger on app_cpe_mappings, whose
--                          ownership on patched-api-01 predates this role
--                          model. Seeded below so existing mappings do not all
--                          read as newly published on first run; the nightly
--                          full match covers them.
--   cve_feed_delta         normalised "vendor:product" CPE keys touched by a
--                          feed sync and not yet re-matched. Durable across a
--                          failed run, so a delta is never lost to a crash.
--   cve_match_runs         completion time of the last feed sync, full match
--                          and delta match, for the portal's
--                          last_feed_sync_at / last_full_match_at.
--
-- None of these tables is evidence: all of them are rebuildable from
-- device_apps, app_cpe_mappings and cve_feed_entries by one full match.
BEGIN;

CREATE TABLE cve_match_queue (
    id            BIGSERIAL PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('observation', 'mapping')),
    reason        TEXT NOT NULL CHECK (reason IN ('ingest', 'mapping_publish')),
    tenant_id     UUID,
    device_id     UUID,
    app_name      TEXT,
    match_name    TEXT,
    -- enqueued_at is when the oldest outstanding request for this row arrived
    -- and drives the backlog-age metric; requested_at is refreshed when the
    -- same observation is requested again while still queued.
    enqueued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts      INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error    TEXT,
    FOREIGN KEY (device_id, tenant_id)
        REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT cve_match_queue_shape CHECK (
        (kind = 'observation'
            AND tenant_id IS NOT NULL AND device_id IS NOT NULL
            AND app_name IS NOT NULL AND btrim(app_name) <> ''
            AND match_name IS NULL) OR
        (kind = 'mapping'
            AND tenant_id IS NULL AND device_id IS NULL AND app_name IS NULL
            AND match_name IS NOT NULL AND btrim(match_name) <> '')
    )
);

-- One outstanding request per observation: a repeat request refreshes
-- requested_at instead of adding a row, which keeps re-matching idempotent
-- and the queue bounded by the number of distinct observations.
CREATE UNIQUE INDEX uq_cve_match_queue_observation
    ON cve_match_queue (device_id, app_name) WHERE kind = 'observation';
CREATE INDEX idx_cve_match_queue_order ON cve_match_queue (enqueued_at, id);
CREATE INDEX idx_cve_match_queue_tenant
    ON cve_match_queue (tenant_id) WHERE kind = 'observation';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cve_match_queue TO patched;
GRANT USAGE, SELECT ON SEQUENCE cve_match_queue_id_seq TO patched;

CREATE TABLE cve_match_assessments (
    device_id        UUID NOT NULL,
    tenant_id        UUID NOT NULL,
    app_name         TEXT NOT NULL CHECK (btrim(app_name) <> ''),
    -- Sorted distinct versions of app_name on the device at match time. The
    -- read path compares this with the current inventory: a mismatch means
    -- the product changed since it was matched, so it reads as pending.
    app_versions     TEXT[] NOT NULL,
    finding_count    INT NOT NULL CHECK (finding_count >= 0),
    last_matched_at  TIMESTAMPTZ NOT NULL,
    match_source     TEXT NOT NULL CHECK (match_source IN (
        'ingest', 'mapping_publish', 'feed_sync', 'full_match'
    )),
    PRIMARY KEY (device_id, app_name),
    FOREIGN KEY (device_id, tenant_id)
        REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_cve_match_assessments_tenant ON cve_match_assessments (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cve_match_assessments TO patched;

CREATE TABLE cve_mapping_snapshot (
    mapping_id   BIGINT PRIMARY KEY,
    match_name   TEXT NOT NULL,
    cpe_vendor   TEXT NOT NULL,
    cpe_product  TEXT NOT NULL,
    captured_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cve_mapping_snapshot TO patched;

INSERT INTO cve_mapping_snapshot (mapping_id, match_name, cpe_vendor, cpe_product)
SELECT id, match_name, cpe_vendor, cpe_product
FROM app_cpe_mappings
ON CONFLICT (mapping_id) DO NOTHING;

CREATE TABLE cve_feed_delta (
    cpe_key      TEXT PRIMARY KEY CHECK (btrim(cpe_key) <> ''),
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cve_feed_delta TO patched;

CREATE TABLE cve_match_runs (
    run_kind      TEXT PRIMARY KEY CHECK (run_kind IN ('feed_sync', 'full_match', 'delta_match')),
    completed_at  TIMESTAMPTZ NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cve_match_runs TO patched;

INSERT INTO schema_migrations (version) VALUES ('0161_event_driven_cve_match')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
