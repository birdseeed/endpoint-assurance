-- patched.im - 0111_software_observation_domain.sql
-- PAT-1461: read-only Endpoint Assurance software observation and identity seam.
--
-- These tables deliberately do not reference catalogue products, installers,
-- packages, deployment rings, or remediation state. They preserve inventory
-- evidence and provide a separately curated product identity layer beside the
-- legacy device_apps projection.
BEGIN;

-- Composite keys below make the tenant boundary enforceable by PostgreSQL,
-- rather than relying on every caller to remember an extra tenant predicate.
ALTER TABLE devices
    ADD CONSTRAINT devices_id_tenant_uq UNIQUE (id, tenant_id);

CREATE TABLE software_products (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_key   TEXT NOT NULL CHECK (canonical_key = lower(btrim(canonical_key)) AND canonical_key <> ''),
    canonical_name  TEXT NOT NULL CHECK (btrim(canonical_name) <> ''),
    vendor_name     TEXT,
    lifecycle_state TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (lifecycle_state IN ('active','end_of_life','replaced','unknown')),
    replacement_product_id UUID REFERENCES software_products(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (canonical_key),
    CHECK (replacement_product_id IS NULL OR replacement_product_id <> id)
);

CREATE TABLE software_product_aliases (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id               UUID NOT NULL REFERENCES software_products(id) ON DELETE RESTRICT,
    platform                 TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    identity_kind            TEXT NOT NULL CHECK (identity_kind IN (
                                 'macos_bundle_team','macos_bundle',
                                 'windows_winget','windows_msix_publisher',
                                 'windows_msi_upgrade_publisher',
                                 'windows_native_publisher','windows_native',
                                 'name_publisher','display_name')),
    identity_value_normalized TEXT NOT NULL CHECK (
                                 identity_value_normalized = lower(btrim(identity_value_normalized))
                                 AND identity_value_normalized <> ''),
    companion_value_normalized TEXT NOT NULL DEFAULT '',
    match_confidence          TEXT NOT NULL CHECK (match_confidence IN ('exact','high')),
    provenance               TEXT NOT NULL CHECK (provenance IN ('reviewed','migration','system')),
    evidence                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform, identity_kind, identity_value_normalized, companion_value_normalized),
    UNIQUE (id, product_id),
    CHECK (companion_value_normalized = btrim(companion_value_normalized)),
    CHECK ((identity_kind = 'macos_bundle_team'
            AND companion_value_normalized <> ''
            AND companion_value_normalized = upper(companion_value_normalized))
        OR (identity_kind IN ('windows_msix_publisher','windows_msi_upgrade_publisher',
                             'windows_native_publisher','name_publisher')
            AND companion_value_normalized <> ''
            AND companion_value_normalized = lower(companion_value_normalized))
        OR (identity_kind IN ('macos_bundle','windows_winget','windows_native','display_name')
            AND companion_value_normalized = ''))
);

CREATE TABLE software_inventory_runs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id               UUID NOT NULL,
    raw_payload_id          BIGINT,
    raw_payload_received_at TIMESTAMPTZ,
    platform                TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    agent                   TEXT,
    agent_version           TEXT,
    collected_at            TIMESTAMPTZ,
    received_at             TIMESTAMPTZ NOT NULL,
    provenance              TEXT NOT NULL CHECK (provenance IN ('inventory_payload','backfill_current_snapshot')),
    coverage                JSONB NOT NULL DEFAULT '{}'::jsonb,
    authoritative_scopes    TEXT[] NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (raw_payload_id, raw_payload_received_at)
        REFERENCES raw_payloads(id, received_at) ON DELETE CASCADE,
    UNIQUE (id, tenant_id, device_id),
    UNIQUE (raw_payload_id, raw_payload_received_at),
    CHECK ((provenance = 'inventory_payload' AND raw_payload_id IS NOT NULL AND raw_payload_received_at IS NOT NULL)
        OR (provenance = 'backfill_current_snapshot' AND raw_payload_id IS NULL AND raw_payload_received_at IS NULL)),
    CHECK (authoritative_scopes <@ ARRAY['all_software','windows_winget']::TEXT[])
);
CREATE UNIQUE INDEX software_inventory_runs_backfill_device_uq
    ON software_inventory_runs (device_id)
    WHERE provenance = 'backfill_current_snapshot';
CREATE INDEX software_inventory_runs_tenant_received_idx
    ON software_inventory_runs (tenant_id, received_at DESC);
CREATE INDEX software_inventory_runs_device_received_idx
    ON software_inventory_runs (device_id, received_at DESC);

CREATE TABLE software_observations (
    id                         BIGSERIAL PRIMARY KEY,
    inventory_run_id           UUID NOT NULL,
    tenant_id                  UUID NOT NULL,
    device_id                  UUID NOT NULL,
    ordinal                    INTEGER NOT NULL CHECK (ordinal >= 0),
    platform                   TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    observed_name              TEXT NOT NULL,
    observed_version           TEXT,
    observed_identifier        TEXT,
    observed_identifier_kind   TEXT,
    observed_publisher         TEXT,
    observed_signer            TEXT,
    observed_team_id           TEXT,
    observed_path              TEXT,
    observed_architecture      TEXT,
    observed_sha256            TEXT,
    observed_notarized         BOOLEAN,
    identity_kind              TEXT NOT NULL,
    identity_value_normalized  TEXT NOT NULL,
    companion_value_normalized TEXT NOT NULL DEFAULT '',
    identity_confidence        TEXT NOT NULL CHECK (identity_confidence IN ('exact','high','medium','low')),
    identity_fingerprint       TEXT NOT NULL CHECK (identity_fingerprint ~ '^[0-9a-f]{64}$'),
    observed_at                TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (inventory_run_id, tenant_id, device_id)
        REFERENCES software_inventory_runs(id, tenant_id, device_id) ON DELETE CASCADE,
    UNIQUE (inventory_run_id, ordinal),
    UNIQUE (id, tenant_id)
);
CREATE INDEX software_observations_tenant_identity_idx
    ON software_observations (tenant_id, identity_fingerprint, observed_at DESC);
CREATE INDEX software_observations_device_observed_idx
    ON software_observations (device_id, observed_at DESC);

CREATE TABLE software_observation_resolutions (
    observation_id       BIGINT PRIMARY KEY,
    tenant_id            UUID NOT NULL,
    product_id           UUID,
    alias_id             UUID,
    resolution_state     TEXT NOT NULL CHECK (resolution_state IN ('unresolved','resolved','ambiguous','ignored')),
    resolution_confidence TEXT CHECK (resolution_confidence IN ('exact','high')),
    resolution_method    TEXT NOT NULL CHECK (resolution_method IN ('none','curated_alias')),
    resolved_at          TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (observation_id, tenant_id)
        REFERENCES software_observations(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (alias_id, product_id)
        REFERENCES software_product_aliases(id, product_id) ON DELETE RESTRICT,
    CHECK ((resolution_state = 'resolved' AND product_id IS NOT NULL AND alias_id IS NOT NULL
            AND resolution_confidence IS NOT NULL AND resolved_at IS NOT NULL
            AND resolution_method = 'curated_alias')
        OR (resolution_state <> 'resolved' AND product_id IS NULL AND alias_id IS NULL
            AND resolution_confidence IS NULL AND resolved_at IS NULL
            AND resolution_method = 'none'))
);
CREATE INDEX software_observation_resolutions_tenant_state_idx
    ON software_observation_resolutions (tenant_id, resolution_state);

CREATE TABLE software_installations (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id                  UUID NOT NULL,
    product_id                 UUID,
    alias_id                   UUID,
    platform                   TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    identity_kind              TEXT NOT NULL,
    identity_value_normalized  TEXT NOT NULL,
    companion_value_normalized TEXT NOT NULL DEFAULT '',
    identity_fingerprint       TEXT NOT NULL CHECK (identity_fingerprint ~ '^[0-9a-f]{64}$'),
    current_name               TEXT NOT NULL,
    current_version            TEXT,
    current_publisher          TEXT,
    current_path               TEXT,
    current_architecture       TEXT,
    resolution_confidence      TEXT CHECK (resolution_confidence IN ('exact','high')),
    first_seen_at              TIMESTAMPTZ NOT NULL,
    last_seen_at               TIMESTAMPTZ NOT NULL,
    removed_at                 TIMESTAMPTZ,
    latest_observation_id      BIGINT REFERENCES software_observations(id) ON DELETE SET NULL,
    provenance                 TEXT NOT NULL CHECK (provenance IN ('inventory_payload','backfill_current_snapshot')),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (alias_id, product_id)
        REFERENCES software_product_aliases(id, product_id) ON DELETE RESTRICT,
    UNIQUE (device_id, identity_fingerprint),
    CHECK ((product_id IS NULL AND alias_id IS NULL AND resolution_confidence IS NULL)
        OR (product_id IS NOT NULL AND alias_id IS NOT NULL AND resolution_confidence IS NOT NULL)),
    CHECK (removed_at IS NULL OR removed_at >= last_seen_at)
);
CREATE INDEX software_installations_tenant_active_idx
    ON software_installations (tenant_id, current_name)
    WHERE removed_at IS NULL;
CREATE INDEX software_installations_product_active_idx
    ON software_installations (product_id, tenant_id)
    WHERE removed_at IS NULL AND product_id IS NOT NULL;

-- Evidence rows may be removed by the established tenant/device retention
-- cascades, but their content cannot be rewritten in place and the table
-- cannot be truncated accidentally, including by its owning application role.
CREATE FUNCTION reject_software_observation_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_observations evidence is immutable: UPDATE is not permitted on row id=%', OLD.id;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_software_observations_reject_update
    BEFORE UPDATE ON software_observations
    FOR EACH ROW EXECUTE FUNCTION reject_software_observation_update();

CREATE FUNCTION reject_software_observation_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_observations evidence cannot be truncated';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_software_observations_reject_truncate
    BEFORE TRUNCATE ON software_observations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_software_observation_truncate();

COMMENT ON TABLE software_products IS
    'Curated software governance identity. Deliberately independent of package, installer, catalogue, deployment, and remediation records.';
COMMENT ON TABLE software_product_aliases IS
    'Reviewed platform identity mappings. A signer or Team ID alone is vendor evidence and is never a supported identity_kind.';
COMMENT ON TABLE software_observations IS
    'Immutable observed software evidence from one inventory run. Resolution is stored separately so curation never rewrites the evidence.';
COMMENT ON TABLE software_installations IS
    'Current and historical device presence derived from observations. Absence is recorded only under an explicit authoritative scope.';

-- PAT-1461 review fix (P1): the device_apps backfill used to run in this same
-- transaction as the DDL above. On a production-sized device_apps table that
-- held DDL locks on the new tables for the whole backfill scan, risking
-- statement timeout and replication lag. The backfill now runs as its own
-- idempotent migration — see 0112_software_observation_backfill.sql — so this
-- migration stays schema-only and fast.

GRANT SELECT, INSERT, UPDATE ON software_products TO patched;
GRANT SELECT, INSERT, UPDATE ON software_product_aliases TO patched;
GRANT SELECT, INSERT ON software_inventory_runs TO patched;
GRANT SELECT, INSERT ON software_observations TO patched;
GRANT SELECT, INSERT, UPDATE ON software_observation_resolutions TO patched;
GRANT SELECT, INSERT, UPDATE ON software_installations TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_observations_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0111_software_observation_domain')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
