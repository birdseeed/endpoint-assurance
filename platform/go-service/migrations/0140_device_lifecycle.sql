-- patched.im — 0140_device_lifecycle.sql
-- PAT-1595: device lifecycle and reconciliation — platform layer.
--
-- Patched cannot see the customer's MDM. It is never the authority on what
-- devices exist, only on what it has itself observed and when (root
-- AGENTS.md "Absence requires authority"). This migration adds the tables
-- that let a customer-supplied device list be reconciled against the
-- agent's own observed devices (`devices`, unchanged) without ever letting
-- an absence of agent evidence read as proof either way.
--
-- Two tables land in this vertical slice — upload + reconciliation + the
-- six-state classification (PAT-1595 items 1-3). The disposition-record
-- table (item 4: decommissioned/on-leave/lost/unaccounted, append-only,
-- correction-as-new-row) and the automatic reappearance rule (item 5) that
-- depends on it are a deferred follow-up — see the implementer's PAT-1595
-- report for why, and PAT-1609 for the console that will eventually read
-- both. Nothing here forecloses adding device_dispositions later: the
-- "removed" state name is reserved in internal/devicelifecycle.State and its
-- ClassifyState signature already accepts an activeDisposition flag no
-- caller sets true yet.
--
--   device_upload_lists — one row per tenant PER UPLOAD, append-only, never
--     overwritten; re-uploadable at any time. "Latest upload wins" for live
--     coverage is a query concern (ORDER BY uploaded_at DESC LIMIT 1), not a
--     schema one — keeping every upload lets a later audit trail or issued
--     report show what list was live at a point in time. The device list
--     itself is JSONB, not a child table: reconciliation only needs to
--     match its entries against `devices` by serial/hw_uuid/hostname in one
--     read, never query the list's rows independently, so a child table
--     would add join cost with no read this ticket needs.
--
--   device_lifecycle_thresholds — tenant-overridable quiet/stale/dormant day
--     thresholds. Absence of a row for a tenant means the hardcoded
--     defaults apply (3 / 14 / 45 days — see
--     internal/devicelifecycle.DefaultThresholds, which must stay in sync
--     with the CHECK below). 14 days is deliberately the Cyber Essentials
--     v3.3 patching window, not an arbitrary pick.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0140_device_lifecycle.sql

BEGIN;

CREATE TABLE device_upload_lists (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    uploaded_by   TEXT         NOT NULL DEFAULT '',
    device_count  INT          NOT NULL,
    devices       JSONB        NOT NULL,
    CHECK (device_count >= 0)
);

CREATE INDEX idx_device_upload_lists_tenant_latest
    ON device_upload_lists (tenant_id, uploaded_at DESC);

GRANT SELECT, INSERT ON TABLE device_upload_lists TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_upload_lists_id_seq TO patched;

COMMENT ON TABLE device_upload_lists IS
    'PAT-1595: one row per customer device-list upload, append-only. The latest row per tenant (by uploaded_at) is the live list for reconciliation; older rows are kept for audit and for a later issued report to point back at. Never UPDATEd or DELETEd by application code.';
COMMENT ON COLUMN device_upload_lists.devices IS
    'JSON array of {"external_id":.., "serial":.., "hw_uuid":.., "hostname":..}. Matched against devices.serial / devices.hw_uuid / devices.hostname by internal/devicelifecycle.Reconcile, strongest identifier first — same "no fuzzy fallback" rule PAT-1801''s protected_software matching uses.';

CREATE TABLE device_lifecycle_thresholds (
    tenant_id     UUID         PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    quiet_days    INT          NOT NULL DEFAULT 3,
    stale_days    INT          NOT NULL DEFAULT 14,
    dormant_days  INT          NOT NULL DEFAULT 45,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by    TEXT         NOT NULL DEFAULT '',
    CHECK (quiet_days > 0 AND quiet_days < stale_days AND stale_days < dormant_days)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_lifecycle_thresholds TO patched;

COMMENT ON TABLE device_lifecycle_thresholds IS
    'PAT-1595: per-tenant override of the quiet/stale/dormant day thresholds used to classify device lifecycle state. No row for a tenant means the hardcoded defaults apply — 3/14/45 days, see internal/devicelifecycle.DefaultThresholds. stale_days defaults to 14, the Cyber Essentials v3.3 patching window, deliberately.';

INSERT INTO schema_migrations (version) VALUES ('0140_device_lifecycle')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
