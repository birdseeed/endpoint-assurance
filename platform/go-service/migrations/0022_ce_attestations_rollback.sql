BEGIN;
DELETE FROM schema_migrations WHERE version = '0022_ce_attestations';
DROP TABLE IF EXISTS ce_attestations;
COMMIT;
