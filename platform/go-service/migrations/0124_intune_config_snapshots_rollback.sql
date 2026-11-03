-- Roll back PAT-1662's Intune configuration snapshot tables.
BEGIN;

DROP TABLE IF EXISTS intune_config_objects;
DROP TABLE IF EXISTS intune_config_snapshots;

DELETE FROM schema_migrations
WHERE version = '0124_intune_config_snapshots';

COMMIT;
