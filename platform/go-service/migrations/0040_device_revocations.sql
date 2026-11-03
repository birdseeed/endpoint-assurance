-- 0040_device_revocations: audit log for device revocation events (PAT-549).
--
-- Device revocation is implemented by setting revoked_at on all
-- tenant_credentials rows where device_id = <target> and tenant_id matches.
-- LookupDeviceByBearer already gates on tc.revoked_at IS NULL, so once
-- those rows are revoked the device cannot authenticate any agent API call.
--
-- This table is an append-only audit record: one row per revoke action so
-- operators can see who revoked which device and when.

BEGIN;

CREATE TABLE device_revocations (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   UUID        NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    admin_id    TEXT        NOT NULL DEFAULT 'system',   -- operator identity (email / label)
    action      TEXT        NOT NULL DEFAULT 'revoke',
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX device_revocations_device_idx  ON device_revocations (device_id);
CREATE INDEX device_revocations_tenant_idx  ON device_revocations (tenant_id, revoked_at DESC);

COMMENT ON TABLE device_revocations IS
    'Append-only audit trail of every device revocation (PAT-549). Never UPDATE or DELETE rows here.';
COMMENT ON COLUMN device_revocations.admin_id IS
    'Identity of the operator who revoked the device. "system" for automated revocations.';

INSERT INTO schema_migrations (version) VALUES ('0040_device_revocations');

COMMIT;
