-- Rollback for 0076_known_app_bundles.sql (PAT-806).

BEGIN;

DROP TABLE IF EXISTS known_app_bundles;

DELETE FROM schema_migrations WHERE version = '0076_known_app_bundles';

COMMIT;
