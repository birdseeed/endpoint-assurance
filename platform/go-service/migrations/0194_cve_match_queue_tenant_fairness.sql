-- patched.im - 0194_cve_match_queue_tenant_fairness.sql
-- PAT-2030: per-tenant fairness for cve_match_queue.
--
-- Drain now takes observation rows round-robin across tenants, oldest first
-- within each tenant, through a LATERAL per tenant (see drainSelectSQL in
-- internal/cvepipeline/queue.go). This index serves that walk in order,
-- reading at most one batch per tenant instead of sorting the whole queue,
-- and serves the loose index scan that lists tenants with queued rows. It
-- also covers the per-tenant count behind TenantQueueCapacity.
--
-- Additive only: no column, constraint or row changes. The table is bounded
-- at 50,000 rows by QueueCapacity, so a plain CREATE INDEX inside the
-- migration transaction is brief. The existing idx_cve_match_queue_tenant
-- (0161) is left in place; it is redundant with this one and can be dropped
-- in a later migration once this has shipped.
BEGIN;

CREATE INDEX idx_cve_match_queue_tenant_order
    ON cve_match_queue (tenant_id, enqueued_at, id) WHERE kind = 'observation';

INSERT INTO schema_migrations (version) VALUES ('0194_cve_match_queue_tenant_fairness')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
