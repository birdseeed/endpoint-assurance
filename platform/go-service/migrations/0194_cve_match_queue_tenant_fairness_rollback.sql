-- Rollback for 0194 (PAT-2030). Drops the per-tenant drain index. The
-- binaries keep working without it (the round-robin drain falls back to
-- idx_cve_match_queue_tenant plus a per-tenant sort), so the order of
-- binary and schema rollback does not matter.
BEGIN;

DROP INDEX IF EXISTS idx_cve_match_queue_tenant_order;

DELETE FROM schema_migrations WHERE version = '0194_cve_match_queue_tenant_fairness';

COMMIT;
