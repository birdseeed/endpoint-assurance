-- patched.im — 0089_signed_catalogue_rollback.sql
-- Reverses 0089_signed_catalogue.sql: drops the signed_catalogue table.
-- Data loss on rollback is expected and accepted (same as every other DROP
-- rollback in this directory) — the CI publish path (POST
-- /admin/catalogue/signed) simply republishes the current signed catalogue
-- on its next nightly run.
BEGIN;

DROP TABLE IF EXISTS signed_catalogue;

DELETE FROM schema_migrations WHERE version = '0089_signed_catalogue';

COMMIT;
