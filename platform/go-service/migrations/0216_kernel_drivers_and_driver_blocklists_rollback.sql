-- Rollback for 0216_kernel_drivers_and_driver_blocklists (PAT-2263).
--
-- Roll the binaries back first: a PAT-2263 extractor writes the device tables
-- on every report that carries the kernel_drivers block, and a PAT-2263
-- patched-cve-sync writes the list tables every night. The device tables are
-- derived from the immutable raw_payloads archive, which still holds every
-- block, and the list tables are refetched by the next refresh, so a re-apply
-- plus re-extraction and one refresh rebuilds what this drops. No append-only
-- ledger is involved, so there is no destructive-data guard.
BEGIN;

DROP TABLE IF EXISTS driver_blocklist_entries;
DROP TABLE IF EXISTS driver_blocklist_source_state;
DROP TABLE IF EXISTS device_kernel_drivers;
DROP TABLE IF EXISTS device_kernel_driver_state;
DROP TABLE IF EXISTS device_kernel_driver_observations;
DROP FUNCTION IF EXISTS reject_device_kernel_driver_observation_update();

DELETE FROM schema_migrations WHERE version = '0216_kernel_drivers_and_driver_blocklists';

COMMIT;
