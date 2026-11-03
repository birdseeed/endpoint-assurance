-- Rollback for 0193_device_retirement_and_device_list (PAT-2135)
--
-- Roll the API binary back first: the PAT-2135 portal handlers, the device
-- roster, the overview and the software coverage figures read these tables.
--
-- Dropping device_retirement_decisions loses every customer Retire device
-- decision and its history (who, when, why); it cannot be rebuilt. Dropping
-- the device list tables loses every uploaded customer device list. Export
-- first:
--   psql ... -c "\copy device_retirement_decisions TO 'device_retirement_decisions.csv' CSV HEADER"
--   psql ... -c "\copy device_list_uploads TO 'device_list_uploads.csv' CSV HEADER"
--   psql ... -c "\copy device_list_entries TO 'device_list_entries.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0193_device_retirement_and_device_list_rollback.sql

BEGIN;

DROP TABLE IF EXISTS device_list_entries;
DROP TABLE IF EXISTS device_list_uploads;
DROP TABLE IF EXISTS device_retirement_decisions;
DROP FUNCTION IF EXISTS reject_device_retirement_decisions_mutation();
DROP FUNCTION IF EXISTS reject_device_retirement_decisions_truncate();

DELETE FROM schema_migrations WHERE version = '0193_device_retirement_and_device_list';

COMMIT;
