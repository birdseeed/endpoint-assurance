-- patched.im — 0088_discovery_job_model_rollback.sql
-- Reverses 0088_discovery_job_model.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0088_discovery_job_model_rollback.sql
BEGIN;

ALTER TABLE catalogue_platform_targets
    DROP COLUMN IF EXISTS last_published_version,
    DROP COLUMN IF EXISTS last_published_sha256,
    DROP COLUMN IF EXISTS last_published_at,
    DROP COLUMN IF EXISTS last_verified_version,
    DROP COLUMN IF EXISTS last_verified_sha256,
    DROP COLUMN IF EXISTS last_verified_signer,
    DROP COLUMN IF EXISTS last_verified_at;

DROP TABLE IF EXISTS discovery_jobs;
DROP TABLE IF EXISTS discovery_runs;

DELETE FROM schema_migrations WHERE version = '0088_discovery_job_model';

COMMIT;
