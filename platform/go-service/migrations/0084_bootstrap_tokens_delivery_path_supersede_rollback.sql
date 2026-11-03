-- patched.im - 0084_bootstrap_tokens_delivery_path_supersede_rollback.sql
-- Reverses 0084_bootstrap_tokens_delivery_path_supersede.sql.
--
-- Only roll back alongside a revert of the enrolment.go change (the
-- INSERT/UPDATE statements there reference delivery_path and
-- superseded_at directly and will fail once these columns are gone).
BEGIN;

DROP INDEX IF EXISTS idx_bootstrap_tokens_supersede_scan;

ALTER TABLE bootstrap_tokens
    DROP COLUMN IF EXISTS superseded_at;

ALTER TABLE bootstrap_tokens
    DROP COLUMN IF EXISTS delivery_path;

DELETE FROM schema_migrations WHERE version = '0084_bootstrap_tokens_delivery_path_supersede';

COMMIT;
