-- patched.im — 0128_devices_collection_status_rollback.sql
-- Reverses 0128_devices_collection_status.sql: drops devices.collection_status.
-- Data loss on rollback is expected and accepted (same as every other
-- ADD COLUMN rollback in this directory) — the raw payload in raw_payloads
-- remains the source of truth and can be re-extracted after a forward
-- migration restores the column.
BEGIN;

ALTER TABLE devices
    DROP COLUMN IF EXISTS collection_status;

DELETE FROM schema_migrations WHERE version = '0128_devices_collection_status';

COMMIT;
