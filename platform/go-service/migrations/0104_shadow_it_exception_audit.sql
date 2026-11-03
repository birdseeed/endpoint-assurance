-- patched.im — 0104_shadow_it_exception_audit.sql
-- PAT-1354: make Shadow IT exceptions reviewable, reversible and audited.

BEGIN;

ALTER TABLE tenant_shadow_it_policy
    ADD COLUMN reason TEXT,
    ADD COLUMN actor TEXT NOT NULL DEFAULT 'legacy',
    ADD COLUMN claimed_actor TEXT,
    ADD COLUMN source_addr INET;

CREATE TABLE tenant_shadow_it_policy_changes (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    label         TEXT NOT NULL,
    old_policy    TEXT CHECK (old_policy IS NULL OR old_policy IN ('flag', 'allow')),
    new_policy    TEXT NOT NULL CHECK (new_policy IN ('flag', 'allow')),
    reason        TEXT,
    actor         TEXT NOT NULL,
    claimed_actor TEXT,
    source_addr   INET,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tenant_shadow_it_policy_changes_tenant_idx
    ON tenant_shadow_it_policy_changes (tenant_id, changed_at DESC);

COMMENT ON TABLE tenant_shadow_it_policy_changes IS
    'Append-only audit trail for tenant Shadow IT exception changes.';

CREATE FUNCTION reject_tenant_shadow_it_policy_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_shadow_it_policy_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_shadow_it_policy_changes_append_only
    BEFORE UPDATE OR DELETE ON tenant_shadow_it_policy_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_shadow_it_policy_changes_mutation();

CREATE FUNCTION reject_tenant_shadow_it_policy_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_shadow_it_policy_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_shadow_it_policy_changes_append_only_truncate
    BEFORE TRUNCATE ON tenant_shadow_it_policy_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_shadow_it_policy_changes_truncate();

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_shadow_it_policy TO patched;
GRANT SELECT, INSERT ON TABLE tenant_shadow_it_policy_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_shadow_it_policy_changes_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0104_shadow_it_exception_audit')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
