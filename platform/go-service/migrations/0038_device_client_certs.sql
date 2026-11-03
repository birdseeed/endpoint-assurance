-- PAT-23: per-device client certificates issued during enrolment.
-- One active row per (tenant_id, hw_uuid) — the UNIQUE constraint gives idempotency:
-- re-enrolment UPSERTs a fresh cert, replacing the old one.
-- The private key is NOT stored server-side; it is returned once at enrolment and
-- stored by the agent.

CREATE TABLE IF NOT EXISTS device_client_certs (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   UUID        REFERENCES devices(id) ON DELETE SET NULL,
    hw_uuid     UUID        NOT NULL,
    cert_pem    TEXT        NOT NULL,
    serial_num  BIGINT      NOT NULL,
    not_after   TIMESTAMPTZ NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, hw_uuid)
);

CREATE INDEX IF NOT EXISTS device_client_certs_device_id_idx ON device_client_certs (device_id);
