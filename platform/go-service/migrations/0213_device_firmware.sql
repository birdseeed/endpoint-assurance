-- 0213: device firmware observations and current projection (PAT-2262)
--
-- First, observation-only slice of PAT-1863 (BIOS/firmware assurance). The
-- Windows agent's new top-level payload block "firmware" (see
-- internal/extractor/firmware.go for the wire shape) carries BIOS vendor,
-- version, SMBIOS version and release date, plus system and baseboard
-- identity, with collection_status complete | partial | unavailable for the
-- block and for each of its three sections, and bounded error codes.
--
-- Nothing here says whether a firmware version is current, outdated or
-- vulnerable. No column name implies a verdict, and no advisory, driver or
-- finding table is referenced.
--
--   device_firmware_observations  one row per report that carried the
--                                 block, exactly as reported (after
--                                 validation). Immutable: UPDATE is
--                                 rejected by trigger. Idempotent on
--                                 raw_payload_id, so re-extraction adds
--                                 nothing.
--   device_firmware_current       one row per device: the newest report's
--                                 block status and errors, plus per-section
--                                 values. A section is written only by a
--                                 report whose section status is complete
--                                 (replace) or partial (fill in what it
--                                 read); an unavailable section or block
--                                 never overwrites or blanks stored values.
--                                 An older replay never overwrites a newer
--                                 report.
--
-- Not reported versus unavailable: a device with no row here never sent the
-- block (an agent that predates PAT-2262, or macOS). A row whose
-- collection_status is 'unavailable' is an agent that tried and could not
-- read anything. The two are never collapsed.
--
-- Both tables are derived from the immutable raw_payloads archive and can be
-- rebuilt by re-extraction, so the rollback loses nothing re-extraction
-- cannot restore.
BEGIN;

CREATE TABLE device_firmware_observations (
    id                       BIGSERIAL PRIMARY KEY,
    tenant_id                UUID NOT NULL,
    device_id                UUID NOT NULL,
    raw_payload_id           BIGINT NOT NULL UNIQUE,
    raw_payload_received_at  TIMESTAMPTZ NOT NULL,
    -- the agent's collected_at; NULL when it did not parse
    observed_at              TIMESTAMPTZ,
    block_schema_version     SMALLINT NOT NULL CHECK (block_schema_version >= 1),
    collection_status        TEXT NOT NULL CHECK (collection_status IN ('complete','partial','unavailable')),
    errors                   TEXT[] NOT NULL DEFAULT '{}'
                             CHECK (cardinality(errors) <= 16),
    bios_status              TEXT CHECK (bios_status IN ('complete','partial','unavailable')),
    bios_manufacturer        TEXT CHECK (char_length(bios_manufacturer) <= 128),
    bios_version             TEXT CHECK (char_length(bios_version) <= 128),
    smbios_version           TEXT CHECK (char_length(smbios_version) <= 128),
    bios_release_date        DATE,
    bios_release_date_raw    TEXT CHECK (char_length(bios_release_date_raw) <= 64),
    system_status            TEXT CHECK (system_status IN ('complete','partial','unavailable')),
    system_manufacturer      TEXT CHECK (char_length(system_manufacturer) <= 128),
    system_model             TEXT CHECK (char_length(system_model) <= 128),
    baseboard_status         TEXT CHECK (baseboard_status IN ('complete','partial','unavailable')),
    baseboard_manufacturer   TEXT CHECK (char_length(baseboard_manufacturer) <= 128),
    baseboard_product        TEXT CHECK (char_length(baseboard_product) <= 128),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    -- an unavailable block carries no sections
    CHECK (collection_status <> 'unavailable'
           OR (bios_status IS NULL AND system_status IS NULL AND baseboard_status IS NULL)),
    CHECK (collection_status = 'unavailable'
           OR (bios_status IS NOT NULL AND system_status IS NOT NULL AND baseboard_status IS NOT NULL))
);
CREATE INDEX device_firmware_observations_device_idx
    ON device_firmware_observations (tenant_id, device_id, raw_payload_received_at DESC, id DESC);

CREATE FUNCTION reject_device_firmware_observation_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_firmware_observations evidence is immutable: UPDATE is not permitted on id=%', OLD.id;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_device_firmware_observations_reject_update
    BEFORE UPDATE ON device_firmware_observations
    FOR EACH ROW EXECUTE FUNCTION reject_device_firmware_observation_update();

CREATE TABLE device_firmware_current (
    device_id                UUID PRIMARY KEY,
    tenant_id                UUID NOT NULL,
    -- the newest report that carried the block
    collection_status        TEXT NOT NULL CHECK (collection_status IN ('complete','partial','unavailable')),
    errors                   TEXT[] NOT NULL DEFAULT '{}',
    observation_id           BIGINT NOT NULL REFERENCES device_firmware_observations(id) ON DELETE CASCADE,
    reported_at              TIMESTAMPTZ NOT NULL,
    observed_at              TIMESTAMPTZ,
    -- per section: the status of the report that last wrote it (complete or
    -- partial, never unavailable) and when; NULL until one has
    bios_status              TEXT CHECK (bios_status IN ('complete','partial')),
    bios_observation_id      BIGINT REFERENCES device_firmware_observations(id) ON DELETE SET NULL,
    bios_reported_at         TIMESTAMPTZ,
    bios_manufacturer        TEXT,
    bios_version             TEXT,
    smbios_version           TEXT,
    bios_release_date        DATE,
    bios_release_date_raw    TEXT,
    system_status            TEXT CHECK (system_status IN ('complete','partial')),
    system_observation_id    BIGINT REFERENCES device_firmware_observations(id) ON DELETE SET NULL,
    system_reported_at       TIMESTAMPTZ,
    system_manufacturer      TEXT,
    system_model             TEXT,
    baseboard_status         TEXT CHECK (baseboard_status IN ('complete','partial')),
    baseboard_observation_id BIGINT REFERENCES device_firmware_observations(id) ON DELETE SET NULL,
    baseboard_reported_at    TIMESTAMPTZ,
    baseboard_manufacturer   TEXT,
    baseboard_product        TEXT,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX device_firmware_current_tenant_idx ON device_firmware_current (tenant_id, collection_status);

COMMENT ON TABLE device_firmware_observations IS
    'PAT-2262: the firmware block (BIOS, system, baseboard identity) of one report, as reported. Observation only: no currency or vulnerability claim. Immutable.';
COMMENT ON TABLE device_firmware_current IS
    'PAT-2262: newest firmware block status per device plus per-section values. Partial fills in, unavailable never blanks. No row = never reported. Derived; rebuilt by re-extraction.';

GRANT SELECT, INSERT ON device_firmware_observations TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_firmware_observations_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE ON device_firmware_current TO patched;

INSERT INTO schema_migrations (version) VALUES ('0213_device_firmware')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
