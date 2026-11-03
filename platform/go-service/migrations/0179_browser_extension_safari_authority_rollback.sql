-- Rollback for 0179_browser_extension_safari_authority (PAT-2067)
--
-- Drops the Safari authority columns, which returns every Safari row to
-- "never absent". Roll the binaries back first: the PAT-2067 extractor
-- writes these columns and internal/extpresence reads them.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0179_browser_extension_safari_authority_rollback.sql

BEGIN;

ALTER TABLE browser_extension_device_state
    DROP COLUMN IF EXISTS safari_complete_at,
    DROP COLUMN IF EXISTS safari_reported_at;

DELETE FROM schema_migrations WHERE version = '0179_browser_extension_safari_authority';

COMMIT;
