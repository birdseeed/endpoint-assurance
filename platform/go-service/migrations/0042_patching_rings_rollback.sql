-- patched.im — 0042_patching_rings_rollback.sql (PAT-117)
-- Rolls back 0042_patching_rings.sql.

BEGIN;

DROP TABLE IF EXISTS ring_config_changes CASCADE;
DROP TABLE IF EXISTS ring_version_approvals CASCADE;
DROP TABLE IF EXISTS tenant_ring_config CASCADE;

ALTER TABLE devices
    DROP COLUMN IF EXISTS ring_override,
    DROP COLUMN IF EXISTS ring_computed;

DELETE FROM schema_migrations WHERE version = '0042_patching_rings';

COMMIT;
