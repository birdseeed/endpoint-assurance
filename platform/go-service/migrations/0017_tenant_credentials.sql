-- Migration 0017: tenant_credentials table for in-place credential rotation (PAT-339)
--
-- Supports multiple concurrently-valid credential rows per tenant to allow
-- zero-downtime key rotation with a grace/overlap window.
--
-- Auth hot path: LookupTenantByBearer queries this table instead of tenants
-- directly. The unique index on bearer_token_hash makes it a single indexed
-- lookup — equivalent cost to the previous tenants lookup.
--
-- Existing tenants.bearer_token_hash / hmac_secret columns are left in place
-- (deprecated) so the service can be redeployed safely before migration, and
-- rolled back without data loss if needed.

BEGIN;

CREATE TABLE tenant_credentials (
    id                BIGSERIAL   PRIMARY KEY,
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bearer_token_hash BYTEA       NOT NULL,
    hmac_secret       BYTEA       NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ
);

-- Unique index so bearer hash lookup is O(log n) and prevents duplicate rows.
CREATE UNIQUE INDEX tenant_credentials_bearer_hash_idx
    ON tenant_credentials (bearer_token_hash);

-- Partial index on tenant_id for the rotate-credentials endpoint (fetch active rows).
CREATE INDEX tenant_credentials_tenant_active_idx
    ON tenant_credentials (tenant_id)
    WHERE revoked_at IS NULL;

-- Seed: copy each non-revoked tenant's credentials into the new table as the
-- initial active credential row. The created_at matches the tenant's creation
-- time for audit continuity.
INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret, created_at)
SELECT id, bearer_token_hash, hmac_secret, created_at
FROM tenants
WHERE revoked_at IS NULL
  AND bearer_token_hash IS NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0017');

COMMIT;
