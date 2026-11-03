-- patched.im — 0085_device_browser_extensions_length_bounds_rollback.sql
-- Reverses 0085_device_browser_extensions_length_bounds.sql: drops the six
-- CHECK constraints. Does NOT attempt to un-truncate the backfilled data —
-- the pre-truncation values are not recoverable from the database (this
-- migration overwrote them in place), and per this repo's rollback
-- convention, rollbacks reverse schema changes only, never data changes.
BEGIN;

ALTER TABLE device_browser_extensions
    DROP CONSTRAINT IF EXISTS device_browser_extensions_extension_id_len,
    DROP CONSTRAINT IF EXISTS device_browser_extensions_browser_len,
    DROP CONSTRAINT IF EXISTS device_browser_extensions_name_len,
    DROP CONSTRAINT IF EXISTS device_browser_extensions_version_len,
    DROP CONSTRAINT IF EXISTS device_browser_extensions_user_account_len,
    DROP CONSTRAINT IF EXISTS device_browser_extensions_profile_len;

DELETE FROM schema_migrations WHERE version = '0085_device_browser_extensions_length_bounds';

COMMIT;
