-- patched.im — 0087_device_backup_status.sql
-- Surfaces the backup_status picture both endpoint agents now emit:
--   * devices.backup_status JSONB — latest snapshot of Time Machine
--     (macOS, PAT-679) / File History (Windows, PAT-680) detection, plus
--     OneDrive/iCloud sync and third-party tool presence. Replaced per
--     ingest (current-state snapshot, not history) — same treatment as
--     devices.pending_updates (0004).
--
-- Backward compatible: agents that predate PAT-679/680 omit the
-- backup_status key entirely; the new column is nullable and the extractor
-- COALESCE-preserves the existing value on re-extraction (see
-- internal/extractor/upsert.go upsertDevice). No column-level GRANT needed —
-- devices already has table-level GRANTs from 0056_grant_all_to_patched.sql.
--
-- Apply with:
--   psql -h ... -f migrations/0087_device_backup_status.sql
--
-- PAT-948.

BEGIN;

ALTER TABLE devices
    ADD COLUMN backup_status JSONB;

COMMENT ON COLUMN devices.backup_status IS
    'Latest backup-status snapshot from the endpoint agent (PAT-679 macOS Time Machine / PAT-680 Windows File History, plus OneDrive/iCloud sync and third-party tool presence). Replaced per ingest. Schema: {"has_backup":bool,"backup_type":string|null,"last_backup_at":string|null (RFC3339),"last_backup_days_ago":int|null,"stale":bool,"sync_only":bool,"notes":string|null}. NULL when the reporting agent predates PAT-679/680, or the section failed to parse on ingest (see parseBackupStatus, PAT-948).';

INSERT INTO schema_migrations (version) VALUES ('0087_device_backup_status')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
