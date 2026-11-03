-- PAT-2389: public certificate metadata only. Never retain uploaded bytes/keys.
BEGIN;
CREATE TABLE tenant_uploaded_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 200),
    subject_cn TEXT NOT NULL,
    issuer_cn TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    sha1 TEXT NOT NULL CHECK (sha1 ~ '^[0-9a-f]{40}$'),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL CHECK (not_after >= not_before),
    ext_key_usage TEXT[] NOT NULL DEFAULT '{}',
    basic_constraints_ca BOOLEAN NOT NULL,
    is_self_signed BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint_sha256)
);
CREATE INDEX tenant_uploaded_certificates_expiry ON tenant_uploaded_certificates(tenant_id, not_after);
CREATE TABLE tenant_uploaded_certificate_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Stable reference, deliberately not an FK to the removable certificate.
    certificate_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upload', 'update_label', 'replace', 'delete')),
    actor_email TEXT NOT NULL,
    old_metadata JSONB,
    new_metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX tenant_uploaded_certificate_audit_history ON tenant_uploaded_certificate_audit(tenant_id, certificate_id, created_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_uploaded_certificates TO patched;
GRANT SELECT, INSERT, DELETE ON tenant_uploaded_certificate_audit TO patched;
COMMENT ON TABLE tenant_uploaded_certificates IS 'Customer-managed public certificate metadata, not a device observation or evidence of endpoint installation/trust.';
COMMENT ON TABLE tenant_uploaded_certificate_audit IS 'Metadata-only decision history survives certificate removal; tenant erasure cascades.';
INSERT INTO schema_migrations(version) VALUES ('0223_manual_certificate_expiry') ON CONFLICT DO NOTHING;
COMMIT;
