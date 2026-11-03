-- Rollback for PAT-2046 (0176_homebrew_review_admin.sql).
BEGIN;

DROP TRIGGER IF EXISTS trg_homebrew_review_audit_reject_truncate ON homebrew_review_audit;
DROP TRIGGER IF EXISTS trg_homebrew_review_audit_reject_update ON homebrew_review_audit;
DROP FUNCTION IF EXISTS reject_homebrew_review_audit_mutation();
DROP TABLE IF EXISTS homebrew_review_audit;

DELETE FROM schema_migrations WHERE version = '0176_homebrew_review_admin';

COMMIT;
