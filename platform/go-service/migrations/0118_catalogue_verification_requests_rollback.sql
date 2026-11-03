-- Roll back PAT-1538's coalescing verification outbox.
BEGIN;

DROP TABLE IF EXISTS catalogue_verification_requests;

DELETE FROM schema_migrations
WHERE version = '0118_catalogue_verification_requests';

COMMIT;
