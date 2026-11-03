-- patched.im — 0042_patching_rings.sql (PAT-117)
-- Customer-facing per-tenant patching rings: percentage-based rollout waves for app
-- updates. Each new app version is approved for Ring 0 first; after a soak gap with
-- acceptable failure rate it advances ring-by-ring until GA (ring=3).
--
-- Deploy ordering: apply BEFORE deploying patched-api or patched-extractor binaries
-- that reference the new tables. The new columns on devices default to NULL and the
-- new tables are absent from existing code paths, so applying this migration against
-- a running v0.0.0 binary is safe.

BEGIN;

-- Per-device ring assignment columns. NULL until first compute.
-- ring_override: admin-pinned agent ring value (0-3). Wins over ring_computed.
-- ring_computed: materialised result of the deterministic hash → band mapping.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS ring_override smallint CHECK (ring_override BETWEEN 0 AND 3),
    ADD COLUMN IF NOT EXISTS ring_computed smallint CHECK (ring_computed BETWEEN 0 AND 3);

-- Per-tenant ring policy. One row per tenant; absent row = rings disabled.
CREATE TABLE IF NOT EXISTS tenant_ring_config (
    tenant_id               UUID    PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled                 boolean NOT NULL DEFAULT false,
    ring_count              smallint NOT NULL DEFAULT 3
                                CHECK (ring_count BETWEEN 2 AND 5),
    percentages             smallint[] NOT NULL DEFAULT '{10,30,60}'
                                CHECK (array_length(percentages, 1) = ring_count),
    soak_gap_hours          integer NOT NULL DEFAULT 24
                                CHECK (soak_gap_hours >= 0),
    failure_threshold_pct   numeric(5,2) NOT NULL DEFAULT 5.00
                                CHECK (failure_threshold_pct BETWEEN 0 AND 100),
    min_failures_to_pause   integer NOT NULL DEFAULT 2
                                CHECK (min_failures_to_pause >= 1),
    min_estate_size         integer NOT NULL DEFAULT 10
                                CHECK (min_estate_size >= 1),
    config_version          integer NOT NULL DEFAULT 1,
    updated_by              text    NOT NULL DEFAULT 'system',
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenant_ring_config IS
    'Per-tenant patching-ring policy. Absent = rings disabled for this tenant.';
COMMENT ON COLUMN tenant_ring_config.percentages IS
    'Cumulative band percentages per ring (e.g. {10,30,60} = ring0 bucket [0,10), ring1 [10,40), ring2 [40,100)). Must sum to 100 — enforced in the Go handler.';
COMMENT ON COLUMN tenant_ring_config.ring_count IS
    'Number of rings (2-5). Must equal array_length(percentages, 1).';

-- Rollout state machine — one row per (tenant, platform, label, version).
-- Tracks which ring a given app version has been approved for, and whether the
-- rollout is advancing, paused (auto or manual), completed, or superseded.
CREATE TABLE IF NOT EXISTS ring_version_approvals (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    platform         text NOT NULL CHECK (platform IN ('macos', 'windows')),
    label            text NOT NULL,
    version          text NOT NULL,
    approved_ring    smallint NOT NULL DEFAULT 0
                         CHECK (approved_ring BETWEEN 0 AND 3),
    state            text NOT NULL DEFAULT 'rolling'
                         CHECK (state IN ('rolling', 'paused', 'completed', 'superseded')),
    last_advanced_at timestamptz NOT NULL DEFAULT now(),
    paused_reason    text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, platform, label, version)
);

CREATE INDEX IF NOT EXISTS idx_rva_tenant_active
    ON ring_version_approvals (tenant_id)
    WHERE state IN ('rolling', 'paused');

COMMENT ON TABLE ring_version_approvals IS
    'Per-(tenant, platform, label, version) rollout state. The extractor advances approved_ring as soak criteria are met.';
COMMENT ON COLUMN ring_version_approvals.approved_ring IS
    'Current agent approved_ring value. Devices with ring <= approved_ring may install.';
COMMENT ON COLUMN ring_version_approvals.last_advanced_at IS
    'Timestamp of last ring advancement; soak-gap timer anchor.';

-- Append-only audit log for ring config and rollout changes.
CREATE TABLE IF NOT EXISTS ring_config_changes (
    id          bigserial PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    change_type text NOT NULL CHECK (change_type IN (
        'config_updated',
        'device_override_set',
        'device_override_cleared',
        'rollout_paused',
        'rollout_resumed',
        'rollout_skipped',
        'rollout_advanced',
        'rollout_auto_paused',
        'rollout_completed',
        'rollout_superseded'
    )),
    label       text,
    version     text,
    device_id   UUID,
    old_value   jsonb,
    new_value   jsonb,
    changed_by  text NOT NULL DEFAULT 'system',
    changed_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rcc_tenant_time
    ON ring_config_changes (tenant_id, changed_at DESC);

COMMENT ON TABLE ring_config_changes IS
    'Append-only audit log for patching ring configuration and rollout state transitions.';

-- Grants (mirror 0021 pattern).
GRANT SELECT, INSERT, UPDATE ON TABLE devices TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_ring_config TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ring_version_approvals TO patched;
GRANT SELECT, INSERT ON TABLE ring_config_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE ring_config_changes_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0042_patching_rings');

COMMIT;
