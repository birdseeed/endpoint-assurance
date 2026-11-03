-- patched.im — 0013_device_certificates_classification_rollback.sql
-- Rolls back 0013_device_certificates_classification.sql: drops the three
-- classification columns and removes the schema_migrations bookmark.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0013_device_certificates_classification_rollback.sql

BEGIN;

ALTER TABLE device_certificates
    DROP COLUMN IF EXISTS ext_key_usage,
    DROP COLUMN IF EXISTS basic_constraints_ca,
    DROP COLUMN IF EXISTS is_self_signed;

DELETE FROM schema_migrations WHERE version = '0013_device_certificates_classification';

COMMIT;
