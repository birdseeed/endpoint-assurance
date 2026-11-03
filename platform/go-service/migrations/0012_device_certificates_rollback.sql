-- patched.im — 0012_device_certificates_rollback.sql
-- Rolls back 0012_device_certificates.sql: drops device_certificates and
-- removes the schema_migrations bookmark.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0012_device_certificates_rollback.sql

BEGIN;

DROP TABLE IF EXISTS device_certificates;

DELETE FROM schema_migrations WHERE version = '0012_device_certificates';

COMMIT;
