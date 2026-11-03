-- patched.im — 0117_tenant_app_execution_policies.sql
-- PAT-1538 (PAT-1481 ADR-0011 §5): tenant-authorization side of the execution
-- state machine.
--
-- Parallel to tenant_catalogue (0067) but referencing global operation state
-- rather than owning package data. A tenant enabling install/update/uninstall
-- for a target creates or reuses this row; activation_state starts
-- 'pending_catalogue' until the referenced catalogue_target_operations row(s)
-- reach 'verified' — automatic addition means automatic enrolment, not
-- automatic approval (ADR-0011 §5).
--
-- Additive / non-actuating: nothing enforces this yet.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0117_tenant_app_execution_policies.sql
BEGIN;

CREATE TABLE tenant_app_execution_policies (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    software_product_id UUID       NOT NULL REFERENCES software_products(id),
    catalogue_target_id UUID       NOT NULL REFERENCES catalogue_platform_targets(id) ON DELETE CASCADE,
    install_enabled    BOOLEAN     NOT NULL DEFAULT false,
    update_enabled     BOOLEAN     NOT NULL DEFAULT false,
    uninstall_enabled  BOOLEAN     NOT NULL DEFAULT false,
    activation_state   TEXT        NOT NULL DEFAULT 'pending_catalogue' CHECK (activation_state IN (
                         'pending_catalogue', 'active', 'blocked', 'disabled')),
    policy_generation  INTEGER     NOT NULL DEFAULT 1,
    requested_by       TEXT        NOT NULL,
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, catalogue_target_id)
);
CREATE INDEX tenant_app_execution_policies_tenant_idx ON tenant_app_execution_policies (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_app_execution_policies TO patched;

INSERT INTO schema_migrations (version) VALUES ('0117_tenant_app_execution_policies')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
