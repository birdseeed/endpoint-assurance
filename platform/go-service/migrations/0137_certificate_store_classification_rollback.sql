-- patched.im — 0137_certificate_store_classification_rollback.sql
-- Reverses 0137_certificate_store_classification.sql (PAT-1738).
--
-- Safe to run at any time: platform_root_certificates carries no data that
-- isn't reconstructible by re-running `patched-cve-sync --mode=root-sync`
-- against the published CCADB lists, and device_certificates.store carries
-- no data that predates this migration (every existing row was already
-- implicitly 'My'/'System'). No other table references either by foreign
-- key.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0137_certificate_store_classification_rollback.sql

BEGIN;

DROP TABLE IF EXISTS platform_root_certificates;

ALTER TABLE device_certificates DROP COLUMN IF EXISTS store;

DELETE FROM schema_migrations WHERE version = '0137_certificate_store_classification';

COMMIT;
