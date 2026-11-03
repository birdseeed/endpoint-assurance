BEGIN;

-- PAT-1405: immutable, specialist-authored Endpoint Assurance deliverables.
-- Paths are server-derived opaque keys under REPORT_STORAGE_ROOT. Staff callers
-- upload bytes; they never supply a filesystem path.
CREATE TABLE assessment_artifacts (
    id                   UUID PRIMARY KEY,
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_reference TEXT NOT NULL CHECK (engagement_reference ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'),
    document_version     TEXT NOT NULL CHECK (document_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'),
    content_type         TEXT NOT NULL CHECK (content_type IN (
                             'application/pdf',
                             'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                         )),
    storage_path         TEXT NOT NULL UNIQUE,
    sha256               BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    byte_size            BIGINT NOT NULL CHECK (byte_size > 0 AND byte_size <= 26214400),
    generated_at         TIMESTAMPTZ NOT NULL,
    approved_at          TIMESTAMPTZ NOT NULL,
    approved_by          TEXT NOT NULL CHECK (approved_by <> '' AND length(approved_by) <= 320),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (generated_at <= approved_at),
    CHECK (storage_path IN (
        'assessments/' || tenant_id::text || '/' || id::text || '/assessment.pdf',
        'assessments/' || tenant_id::text || '/' || id::text || '/assessment.docx'
    )),
    CHECK (
        (content_type = 'application/pdf' AND storage_path LIKE '%/assessment.pdf')
        OR
        (content_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
         AND storage_path LIKE '%/assessment.docx')
    ),
    UNIQUE (tenant_id, engagement_reference, document_version),
    UNIQUE (id, tenant_id)
);

CREATE INDEX idx_assessment_artifacts_tenant
    ON assessment_artifacts (tenant_id, approved_at DESC);

CREATE TABLE assessment_download_tokens (
    id              BIGSERIAL PRIMARY KEY,
    artifact_id     UUID NOT NULL,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL CHECK (recipient_email <> '' AND length(recipient_email) <= 320),
    purpose         TEXT NOT NULL DEFAULT 'assessment_artifact'
                    CHECK (purpose = 'assessment_artifact'),
    token_hash      BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    issued_by       TEXT NOT NULL CHECK (issued_by <> '' AND length(issued_by) <= 320),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '720 hours'),
    FOREIGN KEY (artifact_id, tenant_id)
        REFERENCES assessment_artifacts(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_assessment_download_tokens_artifact
    ON assessment_download_tokens (artifact_id);

CREATE OR REPLACE FUNCTION assessment_artifact_reject_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'assessment_artifacts rows are immutable';
END;
$$;

CREATE TRIGGER trg_assessment_artifact_reject_update
    BEFORE UPDATE ON assessment_artifacts
    FOR EACH ROW EXECUTE FUNCTION assessment_artifact_reject_update();

CREATE OR REPLACE FUNCTION assessment_download_token_use_once()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.used_at IS NOT NULL
       OR NEW.used_at IS NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.artifact_id IS DISTINCT FROM OLD.artifact_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.recipient_email IS DISTINCT FROM OLD.recipient_email
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.issued_by IS DISTINCT FROM OLD.issued_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'assessment download tokens only permit first-use redemption';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_assessment_download_token_use_once
    BEFORE UPDATE ON assessment_download_tokens
    FOR EACH ROW EXECUTE FUNCTION assessment_download_token_use_once();

CREATE TABLE assessment_artifact_audit (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    artifact_id     UUID NOT NULL,
    token_id        BIGINT,
    action          TEXT NOT NULL CHECK (action IN ('approved','token_issued','downloaded')),
    actor           TEXT,
    recipient_email TEXT,
    sha256          BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (action = 'approved' AND token_id IS NULL AND actor IS NOT NULL AND recipient_email IS NULL)
        OR
        (action = 'token_issued' AND token_id IS NOT NULL AND actor IS NOT NULL AND recipient_email IS NOT NULL)
        OR
        (action = 'downloaded' AND token_id IS NOT NULL AND actor IS NULL AND recipient_email IS NOT NULL)
    )
);

-- COMPLIANCE NOTE (not decided in this migration, flagged for explicit
-- product/legal review): this trigger makes assessment_artifact_audit
-- genuinely undeletable, and the table stores recipient_email (PII). Tenant
-- deletion cascades away assessment_artifacts and assessment_download_tokens
-- (both FK ON DELETE CASCADE to tenants), but assessment_artifact_audit has
-- no FK to tenants at all — its rows are permanently orphaned, not erasable,
-- and there is currently no path to honor a GDPR-style erasure request
-- against a recipient's email address short of dropping this trigger. This
-- is a retention-policy question for product/legal, not something to
-- resolve unilaterally in code — needs an explicit decision (e.g. a bounded
-- retention window with an authorized purge path, or a documented
-- compliance basis for indefinite retention) before this table accumulates
-- real customer PII in production.
CREATE OR REPLACE FUNCTION assessment_artifact_audit_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'assessment_artifact_audit is append-only';
END;
$$;

CREATE TRIGGER trg_assessment_artifact_audit_append_only
    BEFORE UPDATE OR DELETE ON assessment_artifact_audit
    FOR EACH ROW EXECUTE FUNCTION assessment_artifact_audit_append_only();

-- `patched` is the fixed application role name every migration in this repo
-- has granted to since 0001 (see e.g. 0057_grant_all_to_patched.sql, the
-- dedicated catch-up migration for this exact role name). This migration
-- follows that established, repo-wide convention rather than introducing a
-- new assumption — the deploy/test DB role name is already relied on
-- everywhere else.
GRANT SELECT, INSERT ON assessment_artifacts TO patched;
GRANT SELECT, INSERT ON assessment_download_tokens TO patched;
GRANT UPDATE (used_at) ON assessment_download_tokens TO patched;
GRANT SELECT, INSERT ON assessment_artifact_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE assessment_download_tokens_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE assessment_artifact_audit_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0108_assessment_artifacts');
COMMIT;
