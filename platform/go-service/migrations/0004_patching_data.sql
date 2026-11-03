-- patched.im — 0004_patching_data.sql
-- Surfaces the patching picture that collector 0.3.0 starts emitting:
--   * devices.pending_updates JSONB — list of currently outstanding macOS
--     updates from `softwareupdate -l`. Replaced per ingest (the list is a
--     current-state snapshot, not history).
--   * patches table is unchanged — exists since 0001 — but the extractor now
--     starts populating it from `softwareupdate --history`.
--
-- Backward compatible: old (0.2.0) collectors that don't emit these fields
-- are silently unaffected — the new column is nullable, and patches stays
-- empty for those payloads.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0004_patching_data.sql

BEGIN;

ALTER TABLE devices
    ADD COLUMN pending_updates JSONB;

COMMENT ON COLUMN devices.pending_updates IS
    'Latest snapshot of currently-outstanding macOS updates from `softwareupdate -l`. Replaced per ingest. Schema: [{"label": "...", "title": "...", "version": "...", "recommended": true|false, "action": "shut down|restart|null"}].';

-- patches.installed_at can be NULL when the collector couldn't parse the
-- locale-formatted date from softwareupdate --history. Already nullable;
-- no schema change needed, but make the contract explicit.
COMMENT ON COLUMN patches.installed_at IS
    'When the patch was applied to the device, parsed from softwareupdate --history. NULL when date parsing failed.';

INSERT INTO schema_migrations (version) VALUES ('0004_patching_data');

COMMIT;
