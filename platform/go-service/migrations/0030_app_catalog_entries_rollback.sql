-- patched.im — 0030_app_catalog_entries_rollback.sql
-- Rolls back 0030_app_catalog_entries.sql (PAT-472).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0030_app_catalog_entries_rollback.sql

BEGIN;

DROP TABLE IF EXISTS app_catalog_entries CASCADE;

DELETE FROM schema_migrations WHERE version = '0030_app_catalog_entries';

COMMIT;
