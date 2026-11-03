-- Rollback for 0018_device_browser_extensions
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0018_device_browser_extensions_rollback.sql

BEGIN;

DROP TABLE IF EXISTS device_browser_extensions;

DELETE FROM schema_migrations WHERE version = '0018_device_browser_extensions';

COMMIT;
