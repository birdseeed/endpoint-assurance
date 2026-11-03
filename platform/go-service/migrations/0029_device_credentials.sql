-- 0029_device_credentials: add device_id to tenant_credentials so per-device
-- credentials can be issued for the GET /v1/posture endpoint.
--
-- Nullable: existing tenant-level rows are unaffected (device_id = NULL).
-- Per-device rows have device_id set and are used exclusively by the posture
-- read path; the posture handler rejects any credential with device_id = NULL.
--
-- Deploy before the binary that serves GET /v1/posture.

ALTER TABLE tenant_credentials
    ADD COLUMN device_id UUID REFERENCES devices(id) ON DELETE CASCADE;

-- Partial index on active per-device credentials — posture auth hot path.
CREATE INDEX tenant_credentials_device_active_idx
    ON tenant_credentials (device_id)
    WHERE revoked_at IS NULL AND device_id IS NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0029_device_credentials');
