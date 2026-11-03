-- patched.im — 0123_msgraph_device_snapshots.sql
-- PAT-1654: ingest Entra device objects and Intune managed devices via the
-- msgraph client (PAT-1653) and store both sides of the device ledger as
-- timestamped, append-only snapshots per tenant.
--
-- Keyed by the Entra tenant id (msgraph.TenantConfig.TenantID — a GUID or
-- verified domain string, never our internal tenants.id) since this is a
-- standalone ledger-reconciliation pull with no wiring yet to a specific
-- patched customer row; that mapping is a later ticket's concern, not this
-- one's.
--
-- Append-only by design: a re-run inserts a new snapshot row rather than
-- updating the previous one, so raw_body always has full history to settle
-- a later reconciliation dispute against.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0123_msgraph_device_snapshots.sql
BEGIN;

-- ============================================================================
-- MSGRAPH_DEVICE_SNAPSHOTS — one row per fetch of one collection for one
-- tenant. raw_body is the exact set of items Graph returned (after paging to
-- exhaustion, before any parsing) — the source of truth if a customer
-- disputes a reconciliation number later.
-- ============================================================================
CREATE TABLE msgraph_device_snapshots (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT NOT NULL,
    collection   TEXT NOT NULL CHECK (collection IN ('entra_devices', 'intune_managed_devices')),
    pulled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    record_count INTEGER NOT NULL,
    raw_body     JSONB NOT NULL
);

CREATE INDEX idx_msgraph_device_snapshots_tenant_collection
    ON msgraph_device_snapshots(tenant_id, collection, pulled_at DESC);

COMMENT ON TABLE msgraph_device_snapshots IS
    'Append-only per-tenant, per-collection Graph pull snapshots. Never updated in place; re-running the pull always inserts a new row.';

-- ============================================================================
-- MSGRAPH_ENTRA_DEVICES — parsed rows from one entra_devices snapshot.
-- ============================================================================
CREATE TABLE msgraph_entra_devices (
    id                                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id                        UUID NOT NULL REFERENCES msgraph_device_snapshots(id) ON DELETE CASCADE,
    tenant_id                          TEXT NOT NULL,
    device_id                          TEXT NOT NULL,
    display_name                       TEXT,
    operating_system                   TEXT,
    operating_system_version           TEXT,
    approximate_last_sign_in_date_time TIMESTAMPTZ,
    account_enabled                    BOOLEAN,
    trust_type                         TEXT,
    is_managed                         BOOLEAN
);

CREATE INDEX idx_msgraph_entra_devices_snapshot ON msgraph_entra_devices(snapshot_id);
CREATE INDEX idx_msgraph_entra_devices_device_id ON msgraph_entra_devices(tenant_id, device_id);

-- ============================================================================
-- MSGRAPH_INTUNE_MANAGED_DEVICES — parsed rows from one
-- intune_managed_devices snapshot. azure_ad_device_id is nullable and may be
-- empty or an all-zero GUID (some management agents never populate it) —
-- that is expected and handled by the join, not rejected here.
-- ============================================================================
CREATE TABLE msgraph_intune_managed_devices (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id               UUID NOT NULL REFERENCES msgraph_device_snapshots(id) ON DELETE CASCADE,
    tenant_id                 TEXT NOT NULL,
    managed_device_id         TEXT NOT NULL,
    azure_ad_device_id        TEXT,
    device_name               TEXT,
    operating_system          TEXT,
    os_version                TEXT,
    last_sync_date_time       TIMESTAMPTZ,
    enrolled_date_time        TIMESTAMPTZ,
    compliance_state          TEXT,
    managed_device_owner_type TEXT,
    management_agent          TEXT,
    device_registration_state TEXT
);

CREATE INDEX idx_msgraph_intune_managed_devices_snapshot ON msgraph_intune_managed_devices(snapshot_id);
CREATE INDEX idx_msgraph_intune_managed_devices_azure_ad_device_id
    ON msgraph_intune_managed_devices(tenant_id, azure_ad_device_id);

-- ============================================================================
-- MSGRAPH_DEVICE_JOIN_RESULTS — the computed join between one
-- entra_devices snapshot and one intune_managed_devices snapshot for a
-- tenant. status is one of:
--   joined       — matched on azureADDeviceId / deviceId
--   entra_only   — Entra device with no corresponding managed device
--   intune_only  — managed device with a real azureADDeviceId that matched
--                  no Entra device
--   unjoinable   — managed device whose azureADDeviceId is missing or an
--                  all-zero GUID; never dropped, always surfaced as its own
--                  row.
-- ============================================================================
-- entra_device_id / managed_device_id are the business keys (deviceId / id)
-- rather than surrogate row FKs, so a join result stands on its own and can
-- be traced back to msgraph_entra_devices / msgraph_intune_managed_devices
-- via (snapshot_id, device_id) / (snapshot_id, managed_device_id) without
-- this table needing to know row UUIDs its callers didn't otherwise need.
CREATE TABLE msgraph_device_join_results (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          TEXT NOT NULL,
    entra_snapshot_id  UUID REFERENCES msgraph_device_snapshots(id) ON DELETE SET NULL,
    intune_snapshot_id UUID REFERENCES msgraph_device_snapshots(id) ON DELETE SET NULL,
    computed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    status             TEXT NOT NULL CHECK (status IN ('joined', 'entra_only', 'intune_only', 'unjoinable')),
    join_key           TEXT, -- the raw azureADDeviceId used/attempted, "" preserved as recorded for unjoinable rows
    entra_device_id    TEXT, -- device.deviceId, set for joined/entra_only rows
    managed_device_id  TEXT  -- managedDevice.id, set for joined/intune_only/unjoinable rows
);

CREATE INDEX idx_msgraph_device_join_results_tenant ON msgraph_device_join_results(tenant_id, computed_at DESC);
CREATE INDEX idx_msgraph_device_join_results_status ON msgraph_device_join_results(status) WHERE status = 'unjoinable';

-- Append-only tables: the application role only ever SELECTs and INSERTs,
-- never UPDATEs or DELETEs a row (see the header comment above).
GRANT SELECT, INSERT ON msgraph_device_snapshots TO patched;
GRANT SELECT, INSERT ON msgraph_entra_devices TO patched;
GRANT SELECT, INSERT ON msgraph_intune_managed_devices TO patched;
GRANT SELECT, INSERT ON msgraph_device_join_results TO patched;

INSERT INTO schema_migrations (version) VALUES ('0123_msgraph_device_snapshots')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
