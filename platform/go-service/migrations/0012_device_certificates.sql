-- patched.im — 0012_device_certificates.sql
-- Adds device_certificates: per-device System Keychain certificate inventory
-- collected by the macOS agent (PAT-216).
--
-- sha1 is the unique fingerprint for a cert within a device's keychain.
-- days_until_expiry_at_collection is the agent's point-in-time snapshot kept
-- for audit/debugging only — live expiry queries must use not_after directly.
--
-- Rollback: migrations/0012_device_certificates_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0012_device_certificates.sql
-- Note: 0011_provenance.sql must have been applied first.

BEGIN;

CREATE TABLE device_certificates (
    id                              BIGSERIAL    PRIMARY KEY,
    device_id                       UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    subject_cn                      TEXT         NOT NULL,
    issuer_cn                       TEXT         NOT NULL,
    sha1                            TEXT         NOT NULL,
    not_after                       TIMESTAMPTZ  NOT NULL,
    days_until_expiry_at_collection INTEGER      NOT NULL,
    collected_at                    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (device_id, sha1)
);

CREATE INDEX idx_device_certs_device_id ON device_certificates(device_id);
CREATE INDEX idx_device_certs_not_after  ON device_certificates(not_after);

COMMENT ON TABLE device_certificates IS
    'Per-device System Keychain certificate inventory from the macOS agent. Upserted on each collection; absent certs are pruned. One (device_id, sha1) pair is one cert slot.';
COMMENT ON COLUMN device_certificates.days_until_expiry_at_collection IS
    'Agent-computed expiry countdown at collection time. Audit/debug snapshot only — never use for live queries. Always recompute from not_after at query time.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_certificates TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_certificates_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0012_device_certificates');

COMMIT;
