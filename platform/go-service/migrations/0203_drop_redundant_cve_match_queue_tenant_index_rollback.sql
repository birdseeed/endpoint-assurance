-- Rollback for 0203 (PAT-2169). Restore the former partial tenant prefix
-- index before removing the receipt. This is schema-only and leaves queue
-- rows and their retry state untouched.
BEGIN;

CREATE INDEX IF NOT EXISTS idx_cve_match_queue_tenant
    ON cve_match_queue (tenant_id) WHERE kind = 'observation';

DELETE FROM schema_migrations WHERE version = '0203_drop_redundant_cve_match_queue_tenant_index';

COMMIT;
