-- PAT-2005. Additive endpoint-reported update-channel observations. These
-- are not release-soak health evidence and never affect promotion gates.
BEGIN;
CREATE TABLE agent_update_channel_observations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    device_id UUID NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('stable','beta')),
    source TEXT NOT NULL CHECK (source IN ('tenant','device_override')),
    config_version INTEGER NOT NULL CHECK (config_version > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    raw_payload_id BIGINT NOT NULL UNIQUE,
    FOREIGN KEY (device_id,tenant_id) REFERENCES devices(id,tenant_id) ON DELETE CASCADE,
    CHECK (observed_at <= received_at + interval '5 minutes')
);
CREATE INDEX agent_update_channel_observations_latest
    ON agent_update_channel_observations (tenant_id,device_id,observed_at DESC,id DESC);
GRANT SELECT, INSERT ON agent_update_channel_observations TO patched;
GRANT USAGE, SELECT ON SEQUENCE agent_update_channel_observations_id_seq TO patched;
INSERT INTO schema_migrations (version) VALUES ('0205_agent_update_channel_observations');
COMMIT;
