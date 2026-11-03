-- patched.im — 0073_mirror_eula_approvals_rollback.sql
-- Rollback for 0073_mirror_eula_approvals.sql (PAT-794).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0073_mirror_eula_approvals_rollback.sql
BEGIN;

DROP TABLE IF EXISTS mirror_eula_approvals CASCADE;

DELETE FROM schema_migrations WHERE version = '0073_mirror_eula_approvals';

COMMIT;
