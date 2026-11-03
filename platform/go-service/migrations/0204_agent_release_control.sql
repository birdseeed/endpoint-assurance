-- PAT-2004. Durable release authority and evidence. No synthetic telemetry or
-- historical canary backfill: promotion stays closed until real evidence exists.
BEGIN;

CREATE TABLE agent_device_channels (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    -- An override opts a device into beta. Absence inherits tenant policy.
    channel TEXT NOT NULL CHECK (channel = 'beta'),
    entered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    baseline_faults JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(baseline_faults) = 'array'),
    baseline_health_at TIMESTAMPTZ,
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 320)
);
CREATE TABLE agent_release_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    hold BOOLEAN NOT NULL DEFAULT false,
    pinned_version TEXT CHECK (pinned_version IS NULL OR length(pinned_version) BETWEEN 1 AND 100),
    CHECK (NOT hold OR pinned_version IS NOT NULL)
);
CREATE TABLE agent_release_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 320),
    source TEXT NOT NULL CHECK (source IN ('portal', 'internal', 'inventory')),
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
    details JSONB NOT NULL CHECK (jsonb_typeof(details) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX agent_release_audit_tenant ON agent_release_audit (tenant_id, id DESC);
-- Immutable evidence intentionally has no device/tenant FK: purge cannot erase
-- a gate decision's provenance. Identifiers remain opaque, no email in evidence.
CREATE TABLE agent_release_observations (
    id BIGSERIAL PRIMARY KEY,
    device_id UUID NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('macos', 'windows', 'macos-menubar')),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    raw_payload_id BIGINT,
    source TEXT NOT NULL DEFAULT 'inventory' CHECK (source IN ('inventory','internal_probe')),
    provenance TEXT NOT NULL CHECK (length(provenance) BETWEEN 1 AND 500),
    health_complete BOOLEAN NOT NULL,
    fault_keys JSONB NOT NULL CHECK (jsonb_typeof(fault_keys) = 'array'),
    UNIQUE (device_id, platform, source, provenance),
    UNIQUE (device_id, platform, version, received_at, raw_payload_id),
    CHECK ((source='inventory' AND raw_payload_id IS NOT NULL) OR
           (source='internal_probe' AND raw_payload_id IS NULL AND platform='macos-menubar')),
    CHECK (observed_at <= received_at + interval '5 minutes')
);
CREATE INDEX agent_release_observations_version ON agent_release_observations (platform, version, device_id, received_at);
CREATE TABLE agent_release_cohorts (
    device_id UUID NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('macos', 'windows', 'macos-menubar')),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
    entered_at TIMESTAMPTZ NOT NULL,
    baseline_version TEXT,
    baseline_faults JSONB NOT NULL CHECK (jsonb_typeof(baseline_faults) = 'array'),
    baseline_health_at TIMESTAMPTZ,
    PRIMARY KEY (device_id, platform, version, entered_at)
);
CREATE TABLE agent_release_evidence (
    id BIGSERIAL PRIMARY KEY,
    device_id UUID,
    platform TEXT NOT NULL CHECK (platform IN ('macos', 'windows', 'macos-menubar')),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
    metric TEXT NOT NULL CHECK (metric IN ('artifact_verification', 'config_verification', 'service_crash', 'restart_loop', 'enrolment', 'upload')),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    attempts BIGINT NOT NULL CHECK (attempts > 0 AND attempts <= 1000000000),
    failures BIGINT NOT NULL CHECK (failures >= 0 AND failures <= attempts),
    provenance TEXT NOT NULL CHECK (length(provenance) BETWEEN 1 AND 500),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 320),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (window_end > window_start AND window_end <= recorded_at + interval '5 minutes'),
    CHECK ((metric IN ('enrolment','upload') AND device_id IS NULL) OR
           (metric NOT IN ('enrolment','upload') AND device_id IS NOT NULL)),
    UNIQUE NULLS NOT DISTINCT (device_id, platform, version, metric, window_start, window_end, provenance)
);
CREATE INDEX agent_release_evidence_version ON agent_release_evidence (platform, version, device_id, metric, window_start, window_end);
CREATE TABLE agent_release_promotions (
    platform TEXT NOT NULL,
    version TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 320),
    promoted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (platform, version)
);
CREATE TABLE agent_release_p0_notices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
    banner TEXT NOT NULL CHECK (length(banner) BETWEEN 1 AND 2000),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 320),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    scheduled_at TIMESTAMPTZ NOT NULL,
    email_due_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    email_recipient TEXT NOT NULL CHECK (length(email_recipient) BETWEEN 3 AND 320),
    email_status TEXT NOT NULL DEFAULT 'pending' CHECK (email_status IN ('pending','delivered','failed')),
    email_attempts INT NOT NULL DEFAULT 0 CHECK (email_attempts >= 0),
    email_next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    email_delivered_at TIMESTAMPTZ,
    email_last_error TEXT,
    CHECK (scheduled_at >= created_at + interval '24 hours'),
    CHECK (email_due_at <= scheduled_at - interval '24 hours')
);
CREATE INDEX agent_release_p0_due ON agent_release_p0_notices (tenant_id, scheduled_at DESC, id DESC);
CREATE TABLE agent_release_p0_activations (
    notice_id BIGINT PRIMARY KEY REFERENCES agent_release_p0_notices(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
GRANT SELECT, INSERT ON agent_release_p0_activations TO patched;
CREATE FUNCTION reject_agent_release_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % forbidden', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['agent_release_audit', 'agent_release_observations', 'agent_release_cohorts', 'agent_release_evidence', 'agent_release_promotions'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_agent_release_mutation()', t || '_immutable', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION reject_agent_release_mutation()', t || '_no_truncate', t);
    END LOOP;
END;
$$;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_device_channels, agent_release_settings TO patched;
GRANT SELECT, INSERT ON agent_release_audit, agent_release_observations, agent_release_cohorts, agent_release_evidence, agent_release_promotions, agent_release_p0_notices TO patched;
GRANT UPDATE (email_status,email_attempts,email_next_attempt_at,email_delivered_at,email_last_error) ON agent_release_p0_notices TO patched;
GRANT USAGE, SELECT ON SEQUENCE agent_release_audit_id_seq, agent_release_observations_id_seq, agent_release_evidence_id_seq, agent_release_p0_notices_id_seq TO patched;
COMMENT ON TABLE agent_release_p0_notices IS 'PAT-2004: durable email notification schedule consumed by Graph mail worker and immediately visible portal banner. Customer cannot cancel. Schedule alone is not delivery proof. Tenant purge remains permitted.';
COMMENT ON TABLE agent_release_audit IS 'PAT-2004: append-only release decisions. Accident resistant, not tamper proof against the owning deployment role. Survives tenant purge.';
INSERT INTO schema_migrations (version) VALUES ('0204_agent_release_control') ON CONFLICT (version) DO NOTHING;
COMMIT;
