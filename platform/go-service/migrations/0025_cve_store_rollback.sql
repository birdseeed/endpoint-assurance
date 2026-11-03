BEGIN;
DELETE FROM schema_migrations WHERE version = '0025_cve_store';
DROP TABLE IF EXISTS device_cve_findings;
DROP TABLE IF EXISTS app_cpe_mappings;
DROP TABLE IF EXISTS cve_feed_entries;
COMMIT;
