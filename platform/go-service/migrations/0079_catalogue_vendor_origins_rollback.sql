-- patched.im — 0079_catalogue_vendor_origins_rollback.sql
-- Reverses 0079_catalogue_vendor_origins.sql.
BEGIN;

DROP TABLE IF EXISTS catalogue_vendor_origins CASCADE;

DELETE FROM schema_migrations WHERE version = '0079_catalogue_vendor_origins';

COMMIT;
