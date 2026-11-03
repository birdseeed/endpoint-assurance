-- Roll back PAT-1668's macOS applied-configuration snapshot tables.
--
-- Safe to run: these tables are derived evidence. raw_payloads keeps the
-- immutable archive of every applied_configuration object ever received, so
-- resetting extracted_at rebuilds everything dropped here.
BEGIN;

DROP TABLE IF EXISTS applied_config_profiles;
DROP TABLE IF EXISTS applied_config_snapshots;

DELETE FROM schema_migrations
WHERE version = '0127_applied_config_snapshots';

COMMIT;
