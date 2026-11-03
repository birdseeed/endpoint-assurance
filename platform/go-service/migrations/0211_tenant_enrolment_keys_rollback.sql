-- Rollback for 0211_tenant_enrolment_keys (PAT-2250)
--
-- Roll the API binary back first: /v1/enrol and the
-- /v1/portal/enrolment-keys routes read and write these tables.
--
-- Dropping tenant_enrolment_keys invalidates every outstanding key, so any
-- installer deployed with one stops enrolling new devices (401
-- "invalid enrollment_token"). Devices already enrolled are unaffected:
-- their credentials live in tenant_credentials. Dropping
-- tenant_enrolment_key_uses loses the record of which device enrolled with
-- which key. Export first if that record matters:
--   psql ... -c "\copy tenant_enrolment_key_uses TO 'tenant_enrolment_key_uses.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0211_tenant_enrolment_keys_rollback.sql

BEGIN;

DROP TABLE IF EXISTS tenant_enrolment_key_uses;
DROP TABLE IF EXISTS tenant_enrolment_keys;

DELETE FROM schema_migrations WHERE version = '0211_tenant_enrolment_keys';

COMMIT;
