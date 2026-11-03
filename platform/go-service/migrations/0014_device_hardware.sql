-- patched.im — 0014_device_hardware.sql
-- Creates three tables for hardware health data collected by the macOS agent
-- (PAT-251 / PAT-252):
--
--   device_hardware       — one parent row per device; battery health snapshot.
--   device_storage_volume — real mounted volumes with byte counts and used_pct.
--   device_disk           — physical disks with SMART status and media type.
--
-- Semantics: on every ingest the device_hardware row is upserted (ON CONFLICT
-- (device_id) DO UPDATE), and the child rows are replaced in full
-- (DELETE + INSERT) — the same replace-snapshot pattern used by
-- device_certificates. hardware_health is optional in the payload — payloads
-- that omit the key leave these tables untouched.
--
-- Rollback: migrations/0014_device_hardware_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0014_device_hardware.sql
-- Note: 0013_device_certificates_classification.sql must have been applied first.

BEGIN;

CREATE TABLE device_hardware (
    id                       BIGSERIAL   PRIMARY KEY,
    device_id                UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    battery_present          BOOLEAN     NOT NULL DEFAULT false,
    battery_cycle_count      INTEGER,
    battery_condition        TEXT,
    battery_max_capacity_pct INTEGER,
    collected_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id)
);

CREATE INDEX idx_device_hardware_device_id ON device_hardware(device_id);

COMMENT ON TABLE device_hardware IS
    'One row per device — battery health snapshot from the macOS agent (PAT-251). Upserted on each hardware_health ingest. Child tables device_storage_volume and device_disk hold the snapshot arrays.';
COMMENT ON COLUMN device_hardware.battery_max_capacity_pct IS
    'Battery maximum capacity as an integer percentage (e.g. 94 = 94 %). Integer only — the collector strips the % sign and casts to int. NULL when device has no battery or the field could not be read.';

CREATE TABLE device_storage_volume (
    id                 BIGSERIAL   PRIMARY KEY,
    device_hardware_id BIGINT      NOT NULL REFERENCES device_hardware(id) ON DELETE CASCADE,
    mount              TEXT        NOT NULL,
    total_bytes        BIGINT      NOT NULL,
    free_bytes         BIGINT      NOT NULL,
    used_pct           INTEGER     NOT NULL
);

CREATE INDEX idx_device_storage_hw_id ON device_storage_volume(device_hardware_id);

COMMENT ON TABLE device_storage_volume IS
    'Real mounted volumes per device (from df -k). Snapshot replaced in full on every ingest (DELETE + INSERT). Excludes pseudo filesystems (devfs, map auto*).';

CREATE TABLE device_disk (
    id                 BIGSERIAL   PRIMARY KEY,
    device_hardware_id BIGINT      NOT NULL REFERENCES device_hardware(id) ON DELETE CASCADE,
    device_node        TEXT        NOT NULL,
    smart_status       TEXT        NOT NULL,
    internal           BOOLEAN     NOT NULL,
    solid_state        BOOLEAN     NOT NULL
);

CREATE INDEX idx_device_disk_hw_id ON device_disk(device_hardware_id);

COMMENT ON TABLE device_disk IS
    'Physical disks per device (from diskutil list physical). Snapshot replaced in full on every ingest (DELETE + INSERT).';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_hardware TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_hardware_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_storage_volume TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_storage_volume_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_disk TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_disk_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0014_device_hardware');

COMMIT;
