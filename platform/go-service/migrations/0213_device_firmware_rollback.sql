-- Rollback for 0213_device_firmware (PAT-2262).
--
-- Roll the binaries back first: a PAT-2262 extractor writes both tables on
-- every report that carries the firmware block. Both tables are derived from
-- the immutable raw_payloads archive, which still holds every block, so a
-- re-apply plus re-extraction rebuilds what this drops. No append-only
-- ledger is involved, so there is no destructive-data guard.
BEGIN;

DROP TABLE IF EXISTS device_firmware_current;
DROP TABLE IF EXISTS device_firmware_observations;
DROP FUNCTION IF EXISTS reject_device_firmware_observation_update();

DELETE FROM schema_migrations WHERE version = '0213_device_firmware';

COMMIT;
