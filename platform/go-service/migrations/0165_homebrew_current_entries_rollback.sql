-- Rollback for 0165_homebrew_current_entries (PAT-2032).
--
-- Drops the derived projection and its supporting index. Nothing is lost:
-- the projection is rebuilt from homebrew_observation_details by 0165's
-- backfill on re-apply. Pre-0165 code computes the current list from the
-- detail history and never reads this table.
BEGIN;

DROP TABLE IF EXISTS homebrew_current_entries;
DROP INDEX IF EXISTS homebrew_observation_details_run_entry_idx;

DELETE FROM schema_migrations WHERE version = '0165_homebrew_current_entries';

COMMIT;
