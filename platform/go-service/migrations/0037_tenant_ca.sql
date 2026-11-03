-- PAT-23: per-tenant CA key material.
-- One row per tenant; provisioned via POST /admin/tenants/{tenantID}/ca.
-- ca_cert_pem is the PEM-encoded self-signed CA cert (public, safe to return to agents).
-- ca_key_pem is the PEM-encoded ECDSA P-256 private key (encrypted at rest via volume;
-- never returned via API).

CREATE TABLE IF NOT EXISTS tenant_ca (
    tenant_id   UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    ca_cert_pem TEXT        NOT NULL,
    ca_key_pem  TEXT        NOT NULL,   -- ECDSA P-256 private key, PEM PKCS#8
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
