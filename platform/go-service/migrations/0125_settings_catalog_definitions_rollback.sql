-- Roll back PAT-1663's Settings Catalog setting-definition cache table.
BEGIN;

DROP TABLE IF EXISTS intune_setting_definitions;

DELETE FROM schema_migrations
WHERE version = '0125_settings_catalog_definitions';

COMMIT;
