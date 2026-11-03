-- Reverses 0154_hmac_compatibility_telemetry.sql. This table is disposable
-- aggregate compatibility telemetry, not customer evidence or audit history.
-- Dropping it does not change any authentication acceptance flag or branch.

BEGIN;

DROP TABLE IF EXISTS hmac_compatibility_telemetry;

DELETE FROM schema_migrations WHERE version = '0154_hmac_compatibility_telemetry';

COMMIT;
