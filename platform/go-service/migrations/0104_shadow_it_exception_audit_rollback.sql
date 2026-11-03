-- patched.im — rollback for 0104_shadow_it_exception_audit.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_tenant_shadow_it_policy_changes_append_only_truncate ON tenant_shadow_it_policy_changes;
DROP TRIGGER IF EXISTS trg_tenant_shadow_it_policy_changes_append_only ON tenant_shadow_it_policy_changes;
DROP FUNCTION IF EXISTS reject_tenant_shadow_it_policy_changes_truncate();
DROP FUNCTION IF EXISTS reject_tenant_shadow_it_policy_changes_mutation();
DROP TABLE IF EXISTS tenant_shadow_it_policy_changes;

ALTER TABLE tenant_shadow_it_policy
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor,
    DROP COLUMN IF EXISTS actor,
    DROP COLUMN IF EXISTS reason;

DELETE FROM schema_migrations WHERE version = '0104_shadow_it_exception_audit';

COMMIT;
