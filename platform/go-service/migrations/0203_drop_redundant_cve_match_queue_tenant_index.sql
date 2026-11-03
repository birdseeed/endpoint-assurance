-- patched.im - 0203_drop_redundant_cve_match_queue_tenant_index.sql
-- PAT-2169: 0194's partial composite index covers every production queue
-- access that used 0161's tenant-only prefix: distinct tenant walking,
-- per-tenant capacity counts, queue metric aggregation, and the drain's
-- tenant prefix ordered by enqueued_at/id. The pending-assessment lookup is
-- keyed by device_id/app_name and has its own partial unique index. The
-- integration planner regression asserts each surviving path. On
-- patched-api-01 the old index had 11,600 historical scans while the
-- composite had none before this change, so deploy-time pg_stat_user_indexes
-- evidence remains required before treating the old index as reclaimed there.
--
-- Schema only: no queue rows or CVE evidence are changed. The rollback
-- recreates the old index before removing this migration receipt.
BEGIN;

DROP INDEX IF EXISTS idx_cve_match_queue_tenant;

INSERT INTO schema_migrations (version) VALUES ('0203_drop_redundant_cve_match_queue_tenant_index')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
