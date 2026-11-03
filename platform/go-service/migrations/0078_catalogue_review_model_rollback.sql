-- patched.im — 0078_catalogue_review_model_rollback.sql
-- Reverses 0078_catalogue_review_model.sql. Drops the four review-model tables
-- in FK-safe order. mirror_eula_approvals is untouched (it was never altered).
BEGIN;

DROP TABLE IF EXISTS catalogue_dismissals CASCADE;
DROP TABLE IF EXISTS catalogue_review_audit CASCADE;
DROP TABLE IF EXISTS catalogue_platform_targets CASCADE;
DROP TABLE IF EXISTS catalogue_products CASCADE;

DELETE FROM schema_migrations WHERE version = '0078_catalogue_review_model';

COMMIT;
