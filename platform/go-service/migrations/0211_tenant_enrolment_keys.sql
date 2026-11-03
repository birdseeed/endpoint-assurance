-- patched.im - 0211_tenant_enrolment_keys.sql
-- PAT-2250: reusable, revocable per-tenant enrolment keys.
--
-- A single-use bootstrap token (0036) cannot drive an estate-wide rollout
-- through Intune, Jamf or an RMM: one installer, many devices, over weeks.
-- A tenant enrolment key is one credential that up to max_devices distinct
-- devices can redeem at POST /v1/enrol until it expires or is revoked. It is
-- supplied alongside the generic signed installer (MSI ENROLLMENT_TOKEN,
-- macOS enrollment.json / /etc/patched/enrollment-token), never baked into
-- the package, and it travels in the SAME request field as a bootstrap token.
--
-- 1. tenant_enrolment_keys: one row per key. key_hash is SHA-256 of the
--    plaintext ("pek_" + base64url(32 random bytes)); the plaintext is
--    returned to the portal admin once and never stored. key_hint is the
--    first four characters after the prefix, so a leaked key can be matched
--    to its row without storing the secret. Revocation is a timestamp, not a
--    delete: devices already enrolled keep their per-device credentials.
--    Tenant data: FK to tenants ON DELETE CASCADE so tenant purge removes it.
--
-- 2. tenant_enrolment_key_uses: one row per successful enrolment against a
--    key (key id, device id, hw_uuid, time). The device cap counts DISTINCT
--    hw_uuid, so re-enrolling a device that already used the key (wipe and
--    reinstall) is recorded again but does not consume a second slot,
--    matching /v1/enrol's existing (tenant_id, hw_uuid) device upsert.
--    device_id deliberately has no FK to devices: removing a device must not
--    free a slot on the key that enrolled it, and the enrolment record
--    outlives the device.
--
-- Additive only: two new tables, no change to any existing table. Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0211_tenant_enrolment_keys.sql

BEGIN;

CREATE TABLE tenant_enrolment_keys (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash     BYTEA       NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    key_hint     TEXT        NOT NULL CHECK (key_hint ~ '^[A-Za-z0-9_-]{4}$'),
    label        TEXT        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 100),
    max_devices  INTEGER     NOT NULL CHECK (max_devices BETWEEN 1 AND 100000),
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Verified portal email of the admin who created / revoked the key.
    created_by   TEXT        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 320),
    revoked_at   TIMESTAMPTZ,
    revoked_by   TEXT        CHECK (revoked_by IS NULL OR char_length(revoked_by) BETWEEN 1 AND 320),
    CHECK (expires_at > created_at),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX tenant_enrolment_keys_tenant_idx
    ON tenant_enrolment_keys (tenant_id, created_at DESC);

CREATE TABLE tenant_enrolment_key_uses (
    id          BIGSERIAL   PRIMARY KEY,
    key_id      UUID        NOT NULL REFERENCES tenant_enrolment_keys(id) ON DELETE CASCADE,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   UUID        NOT NULL,
    hw_uuid     UUID        NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tenant_enrolment_key_uses_key_hw_idx
    ON tenant_enrolment_key_uses (key_id, hw_uuid);
CREATE INDEX tenant_enrolment_key_uses_tenant_idx
    ON tenant_enrolment_key_uses (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_enrolment_keys TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_enrolment_key_uses TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_enrolment_key_uses_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0211_tenant_enrolment_keys')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
