-- Rollback for PAT-2049 (0175_google_drive_cpe_key.sql).
--
-- Deletes exactly the row this migration inserted, identified by its
-- 'PAT-2049 NVD audit: real key, CVE-2022-3421' notes marker -- never by
-- app or key, since google:backup_and_sync_from_google is a pre-existing
-- row for the same app ("Google Drive") that this migration did not touch
-- and must not remove.

BEGIN;

DELETE FROM app_cpe_mappings WHERE notes = 'PAT-2049 NVD audit: real key, CVE-2022-3421';

DELETE FROM schema_migrations WHERE version = '0175_google_drive_cpe_key';

COMMIT;
