-- 0022_ce_attestations.sql
-- Attestation store for Cyber Essentials controls that cannot be
-- automatically evidenced from agent-collected signals.
-- Each row holds the most-recent answer for a (tenant, control) pair.
BEGIN;

CREATE TABLE ce_attestations (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    control_id  TEXT         NOT NULL,
    answer      TEXT         NOT NULL CHECK (answer IN ('yes', 'no', 'partial', 'not_applicable')),
    notes       TEXT         NOT NULL DEFAULT '',
    attested_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, control_id)
);

CREATE INDEX idx_ce_attestations_tenant ON ce_attestations(tenant_id);

INSERT INTO schema_migrations (version) VALUES ('0022_ce_attestations');

COMMIT;
