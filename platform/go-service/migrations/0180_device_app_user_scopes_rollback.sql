-- Rollback for 0180_device_app_user_scopes (PAT-2075)
--
-- Roll the binaries back first: the PAT-2075 extractor writes both the
-- column and the table. After the rollback every remaining device_apps row
-- reads as machine-wide again, so a per-user row of a logged-off user is
-- pruned by the next authoritative report, which is the pre-PAT-2075
-- behaviour. raw_payloads keeps every report, so a re-apply plus
-- re-extraction rebuilds the scopes.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0180_device_app_user_scopes_rollback.sql

BEGIN;

DROP TABLE IF EXISTS device_app_user_scopes;
ALTER TABLE device_apps DROP COLUMN IF EXISTS machine_wide;

DELETE FROM schema_migrations WHERE version = '0180_device_app_user_scopes';

COMMIT;
