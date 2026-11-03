-- Rollback for 0016_seen_nonces.sql
BEGIN;
DROP TABLE IF EXISTS seen_nonces;
DELETE FROM schema_migrations WHERE version = '0016';
COMMIT;
