-- Rollback for PAT-2045 (0171_homebrew_event_match.sql).
--
-- Roll the binaries back first: a PAT-2045 extractor reads and writes these
-- columns on every queue drain.
--
-- Homebrew rows are removed from the snapshot and Homebrew mapping jobs from
-- the queue before the columns go, so a PAT-2024 binary never reads a
-- Homebrew mapping as an application match_name. Both are derived state; the
-- nightly full match covers anything dropped here.

BEGIN;

DELETE FROM cve_match_queue WHERE mapping_source_type <> 'app_name';
DELETE FROM cve_mapping_snapshot WHERE source_type <> 'app_name';

ALTER TABLE cve_match_queue
    DROP CONSTRAINT IF EXISTS cve_match_queue_mapping_source_shape,
    DROP COLUMN IF EXISTS mapping_source_type;

ALTER TABLE cve_mapping_snapshot
    DROP COLUMN IF EXISTS review_state,
    DROP COLUMN IF EXISTS source_type;

DELETE FROM schema_migrations WHERE version = '0171_homebrew_event_match';

COMMIT;
