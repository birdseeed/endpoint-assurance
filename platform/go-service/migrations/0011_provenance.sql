-- patched.im — 0011_provenance.sql
-- Adds provenance_records: the immutable audit trail of third-party app
-- updates performed by the Patched Updater on client endpoints.
--
-- POST /v1/provenance writes one row per app action. As with raw_payloads the
-- JSONB body is the source of truth. Unlike raw_payloads this table is NOT
-- partitioned — provenance volume is far lower, so a plain BIGSERIAL table is
-- right.
--
-- Apply BEFORE deploying the binary that serves POST /v1/provenance.
--   psql -h patched-api-01 -U patched -d patched -f migrations/0011_provenance.sql

BEGIN;

CREATE TABLE provenance_records (
    id           BIGSERIAL    PRIMARY KEY,
    tenant_id    UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    received_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source_ip    INET,
    user_agent   TEXT,
    body         JSONB        NOT NULL
);

CREATE INDEX idx_provenance_tenant_received ON provenance_records(tenant_id, received_at DESC);
CREATE INDEX idx_provenance_body            ON provenance_records USING GIN (body);

COMMENT ON TABLE provenance_records IS
    'Immutable audit trail of third-party app updates from the Patched Updater. One row per app action. body JSONB is the source of truth — never UPDATE or DELETE rows here.';

GRANT SELECT, INSERT ON TABLE provenance_records TO patched;
GRANT USAGE, SELECT ON SEQUENCE provenance_records_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0011_provenance');

COMMIT;
