-- Rollback for PAT-2024 (0161_event_driven_cve_match.sql).
--
-- Every table dropped here is derived, rebuildable state: the queue,
-- assessment rows, mapping snapshot, feed delta and run timestamps can all be
-- reconstructed by one full `patched-cve-sync --mode=match` run from
-- device_apps, app_cpe_mappings and cve_feed_entries. No evidence ledger and
-- no customer decision lives in any of them, so this rollback carries no
-- destructive-data guard. device_cve_findings and the finding lifecycle
-- tables are untouched by this migration and by this rollback.
--
-- Roll the binaries back first: a PAT-2024 extractor or patched-api reading
-- these tables after they are dropped fails the queue drain and the portal
-- assessment fields.

BEGIN;

DROP TABLE IF EXISTS cve_match_runs;
DROP TABLE IF EXISTS cve_feed_delta;
DROP TABLE IF EXISTS cve_mapping_snapshot;
DROP TABLE IF EXISTS cve_match_assessments;
DROP TABLE IF EXISTS cve_match_queue;

DELETE FROM schema_migrations WHERE version = '0161_event_driven_cve_match';

COMMIT;
