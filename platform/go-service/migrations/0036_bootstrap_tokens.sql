-- PAT-23: bootstrap tokens for device enrolment.
-- Short-lived, one-use tokens issued by admin/dashboard; agent presents one at
-- POST /v1/enrol to prove it was provisioned by the tenant admin.
-- consumed_at IS NULL means the token is still valid (not yet used).
-- Rate-limited per tenant at the endpoint level; token expiry is the second gate.

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  BYTEA       NOT NULL,       -- SHA-256(plaintext_token)
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,                -- NULL = not yet used
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS bootstrap_tokens_tenant_id_idx ON bootstrap_tokens (tenant_id);
