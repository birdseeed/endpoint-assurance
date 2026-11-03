-- PAT-550: audit log for admin enrollment-token generation.
-- Records every call to POST /admin/tenants/{id}/bootstrap-tokens
-- (and its /v1/admin alias) so we know which admin generated which
-- deployment artifact and when.

CREATE TABLE IF NOT EXISTS enrollment_token_audit (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id     UUID        NOT NULL REFERENCES bootstrap_tokens(id) ON DELETE CASCADE,
    delivery_path TEXT       NOT NULL CHECK (delivery_path IN ('mdm', 'email-link')),
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    admin_note   TEXT
);

CREATE INDEX IF NOT EXISTS eta_tenant_id_idx ON enrollment_token_audit (tenant_id);
CREATE INDEX IF NOT EXISTS eta_generated_at_idx ON enrollment_token_audit (generated_at DESC);
