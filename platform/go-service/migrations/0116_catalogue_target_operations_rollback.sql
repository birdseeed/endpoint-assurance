-- Roll back PAT-1538's global per-(target,operation) verification state machine.
BEGIN;

DROP TABLE IF EXISTS catalogue_target_operations;

DELETE FROM schema_migrations
WHERE version = '0116_catalogue_target_operations';

COMMIT;
