-- patched.im — 0106_cve_sync_checkpoints.sql
-- PAT-1375: durable resume point for patched-cve-sync's NVD page walk.
--
-- The 2026-08-14 incident: patched-cve-sync walks the NVD feed ~180 pages
-- (~40 minutes), reached page 103/180 (record 206,000 of 359,674), hit a
-- single upstream 524, and died — throwing away 40 minutes of fetched-and-
-- ingested progress and leaving patched-cve-sync.service `failed` for 24h
-- until the next nightly timer.
--
-- One row per "sync query" (see nvdSyncQueryModified / nvdSyncQueryFull in
-- cmd/patched-cve-sync/main.go): the last startIndex whose page was
-- successfully fetched AND upserted into cve_feed_entries, so a resumed run
-- only ever skips pages that are already durably in the DB (see
-- fetchAndIngestPages' incremental-ingest comment for why that is what
-- makes resume correct rather than silently dropping records).
--
-- updated_at is read back by loadNVDCheckpoint to reject a stale checkpoint
-- (older than nvdCheckpointMaxAge) instead of resuming against a query
-- window that has since shifted.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0106_cve_sync_checkpoints.sql

BEGIN;

CREATE TABLE cve_sync_checkpoints (
    sync_query    TEXT PRIMARY KEY,
    start_index   INTEGER NOT NULL,
    total_results INTEGER NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cve_sync_checkpoints TO patched;

INSERT INTO schema_migrations (version) VALUES ('0106_cve_sync_checkpoints')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
