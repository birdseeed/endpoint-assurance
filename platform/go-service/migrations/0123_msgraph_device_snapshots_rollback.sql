-- Roll back PAT-1654's msgraph device snapshot/join tables.
BEGIN;

DROP TABLE IF EXISTS msgraph_device_join_results;
DROP TABLE IF EXISTS msgraph_intune_managed_devices;
DROP TABLE IF EXISTS msgraph_entra_devices;
DROP TABLE IF EXISTS msgraph_device_snapshots;

DELETE FROM schema_migrations
WHERE version = '0123_msgraph_device_snapshots';

COMMIT;
