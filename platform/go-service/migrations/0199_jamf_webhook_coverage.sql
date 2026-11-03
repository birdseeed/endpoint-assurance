-- patched.im - 0199_jamf_webhook_coverage.sql
-- PAT-2145: Jamf Pro webhook ingest and MDM coverage reconciliation.
--
-- A Jamf customer's Jamf Pro pushes webhooks to Patched, so Patched can say
-- which Macs Jamf manages that Patched has never seen, and which Macs Patched
-- sees that no MDM manages, without Patched ever holding a Jamf API
-- credential (PAT-1666 ruling). Intune is out of scope (Graph covers it).
--
-- 1. jamf_webhook_connectors: one row per tenant. webhook_id is the opaque,
--    random path segment of the tenant's endpoint
--    (POST /v1/webhooks/jamf/{webhook_id}); it is never the tenant UUID and
--    does not change when the token rotates. token_hash is SHA-256 of the
--    webhook token; the plaintext is shown to the portal admin once and never
--    stored. NULL token_hash means no usable token (revoked). Tenant data:
--    FK to tenants ON DELETE CASCADE so tenant purge removes it.
--
-- 2. jamf_webhook_audit: append-only record of every token create, rotate
--    and revoke and every event subscription change, with the verified
--    portal email of the admin who made it. Same shape and rules as
--    device_retirement_decisions (0193): no FK to tenants (a cascade DELETE
--    would hit the append-only trigger and break tenant purge, 0091/0096).
--    The trigger stops an accidental write, not the owning role `patched`
--    (AGENTS.md); do not describe it as tamper-proof.
--
-- 3. jamf_devices: one row per Mac Jamf has told Patched about, at most
--    50,000 per tenant (ingest refuses more, recorded as device_cap_reached).
--    Revoking a token deletes the rows first created under it; an admin
--    purge deletes them all. Both are audited with the row count. Identifiers
--    only: serial, UDID, Jamf ID, device name, model, OS version, event type
--    and time. The webhook handler drops every personal field (user, email,
--    IP, location, username, real name, phone, position, building,
--    department, room, MAC addresses) at the edge; there are deliberately no
--    columns that could hold them, and the raw body is never stored.
--    Jamf sends no delete event, so a row is never removed by ingest: a Mac
--    silent in Jamf is reported as "not heard from Jamf in N days", never as
--    removed or unmanaged. There is no backfill: rows exist only from the
--    first event after setup.
--
-- Additive only. Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0199_jamf_webhook_coverage.sql

BEGIN;

CREATE TABLE jamf_webhook_connectors (
    tenant_id                  UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    webhook_id                 TEXT        NOT NULL UNIQUE CHECK (webhook_id ~ '^[A-Za-z0-9_-]{32}$'),
    token_hash                 BYTEA       CHECK (token_hash IS NULL OR length(token_hash) = 32),
    -- When the connector (and its first token) was created, and when the
    -- current token was issued (equal to created_at until the first rotate).
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_issued_at            TIMESTAMPTZ,
    token_revoked_at           TIMESTAMPTZ,
    -- Incremented each time a token is issued (create or rotate). Each
    -- jamf_devices row records the generation it was created and last
    -- written under, so revoking a token can remove exactly the Macs that
    -- first appeared under it (a leaked token's fabrications).
    token_generation           INTEGER     NOT NULL DEFAULT 1 CHECK (token_generation >= 1),
    -- ComputerCheckIn is optional; the other three events are always
    -- subscribed. An event type the tenant has not subscribed to is refused.
    check_in_enabled           BOOLEAN     NOT NULL DEFAULT FALSE,
    first_event_at             TIMESTAMPTZ,
    last_event_at              TIMESTAMPTZ,
    -- Authenticated events refused for their content (bad schema, missing
    -- identifier, unsubscribed type). Unauthenticated requests write nothing.
    events_rejected            BIGINT      NOT NULL DEFAULT 0 CHECK (events_rejected >= 0),
    last_rejected_at           TIMESTAMPTZ,
    last_rejected_reason       TEXT        CHECK (last_rejected_reason IS NULL OR last_rejected_reason IN
                                   ('invalid_payload', 'missing_identifier', 'event_not_subscribed',
                                    'unsupported_event', 'invalid_instance_url', 'unsupported_media_type', 'body_too_large',
                                    'device_cap_reached')),
    -- The Jamf Pro instance the tenant's events claim (X-Patched-Jamf-Instance
    -- header, normalised to https://host[:port]). Jamf Pro payloads carry no
    -- server URL, so the claim comes from the header the setup page tells the
    -- admin to add. The first claim is pinned; a later event claiming a
    -- different instance sets jamf_instance_mismatch_at.
    jamf_instance_url          TEXT        CHECK (jamf_instance_url IS NULL OR char_length(jamf_instance_url) <= 300),
    jamf_instance_last_claimed TEXT        CHECK (jamf_instance_last_claimed IS NULL OR char_length(jamf_instance_last_claimed) <= 300),
    jamf_instance_mismatch_at  TIMESTAMPTZ,
    CHECK (token_hash IS NULL OR token_issued_at IS NOT NULL)
);

COMMENT ON TABLE jamf_webhook_connectors IS
    'PAT-2145: one Jamf Pro webhook connector per tenant. webhook_id is the opaque endpoint path segment (never the tenant id); token_hash is SHA-256 of the webhook token, plaintext never stored; NULL token_hash = revoked. Never holds a Jamf API credential.';

GRANT SELECT, INSERT, UPDATE ON TABLE jamf_webhook_connectors TO patched;

CREATE TABLE jamf_webhook_audit (
    id           BIGSERIAL   PRIMARY KEY,
    tenant_id    UUID        NOT NULL,
    action       TEXT        NOT NULL CHECK (action IN
                     ('token_created', 'token_rotated', 'token_revoked', 'check_in_enabled', 'check_in_disabled',
                      'instance_reset', 'devices_purged')),
    -- Jamf device rows deleted by this action (token_revoked, devices_purged).
    affected_rows INTEGER     CHECK (affected_rows IS NULL OR affected_rows >= 0),
    actor_email  TEXT        NOT NULL CHECK (btrim(actor_email) <> '' AND length(actor_email) <= 320),
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_jamf_webhook_audit_tenant ON jamf_webhook_audit (tenant_id, id DESC);

CREATE FUNCTION reject_jamf_webhook_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'jamf_webhook_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_jamf_webhook_audit_append_only
    BEFORE UPDATE OR DELETE ON jamf_webhook_audit
    FOR EACH ROW
    EXECUTE FUNCTION reject_jamf_webhook_audit_mutation();

CREATE FUNCTION reject_jamf_webhook_audit_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'jamf_webhook_audit is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_jamf_webhook_audit_append_only_truncate
    BEFORE TRUNCATE ON jamf_webhook_audit
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_jamf_webhook_audit_truncate();

COMMENT ON TABLE jamf_webhook_audit IS
    'PAT-2145: append-only audit of Jamf webhook token create/rotate/revoke and event subscription changes by portal admins. UPDATE, DELETE and TRUNCATE rejected by trigger (not tamper-proof: the owning role can disable it). No FK to tenants on purpose.';

GRANT SELECT, INSERT ON TABLE jamf_webhook_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE jamf_webhook_audit_id_seq TO patched;

CREATE TABLE jamf_devices (
    id                 BIGSERIAL   PRIMARY KEY,
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    serial             TEXT        CHECK (serial IS NULL OR char_length(serial) <= 255),
    -- Trimmed, upper case; NULL for a placeholder serial (internal/devicelist).
    serial_normalized  TEXT        CHECK (serial_normalized IS NULL OR char_length(serial_normalized) <= 255),
    udid               TEXT        CHECK (udid IS NULL OR char_length(udid) <= 255),
    -- Upper-case canonical UUID text; NULL unless the UDID is UUID-shaped.
    -- On a Mac, Jamf's computer UDID is the hardware UUID (devices.hw_uuid).
    udid_normalized    TEXT        CHECK (udid_normalized IS NULL OR udid_normalized ~ '^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$'),
    jamf_id            BIGINT      CHECK (jamf_id IS NULL OR jamf_id > 0),
    device_name        TEXT        CHECK (device_name IS NULL OR char_length(device_name) <= 255),
    model              TEXT        CHECK (model IS NULL OR char_length(model) <= 255),
    os_version         TEXT        CHECK (os_version IS NULL OR char_length(os_version) <= 255),
    -- enrolled: Jamf has sent a computer event (ComputerAdded,
    -- ComputerInventoryCompleted or ComputerCheckIn) for this Mac.
    -- dep_assigned: Jamf has sent DeviceAddedToDEP for it.
    enrolled           BOOLEAN     NOT NULL DEFAULT FALSE,
    dep_assigned       BOOLEAN     NOT NULL DEFAULT FALSE,
    -- jamf_webhook_connectors.token_generation when the row was created and
    -- when it was last written.
    first_token_generation INTEGER NOT NULL CHECK (first_token_generation >= 1),
    last_token_generation  INTEGER NOT NULL CHECK (last_token_generation >= 1),
    first_event_type   TEXT        NOT NULL CHECK (first_event_type IN ('ComputerAdded', 'ComputerInventoryCompleted', 'ComputerCheckIn', 'DeviceAddedToDEP')),
    last_event_type    TEXT        NOT NULL CHECK (last_event_type IN ('ComputerAdded', 'ComputerInventoryCompleted', 'ComputerCheckIn', 'DeviceAddedToDEP')),
    -- first_received_at / last_received_at: server receive time.
    -- last_event_at: Jamf's eventTimestamp, clamped to no later than receipt.
    first_received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_event_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (serial_normalized IS NOT NULL OR udid_normalized IS NOT NULL OR jamf_id IS NOT NULL)
);

CREATE UNIQUE INDEX uq_jamf_devices_serial ON jamf_devices (tenant_id, serial_normalized) WHERE serial_normalized IS NOT NULL;
CREATE UNIQUE INDEX uq_jamf_devices_udid   ON jamf_devices (tenant_id, udid_normalized)   WHERE udid_normalized IS NOT NULL;
CREATE UNIQUE INDEX uq_jamf_devices_jamfid ON jamf_devices (tenant_id, jamf_id)           WHERE jamf_id IS NOT NULL;

COMMENT ON TABLE jamf_devices IS
    'PAT-2145: Macs Jamf Pro has reported to Patched by webhook. Identifiers only (serial, UDID, Jamf ID, device name, model, OS version, event type and time); personal fields are dropped at the edge and the raw body is never stored. No backfill, and no delete event: rows are never removed by ingest.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE jamf_devices TO patched;
GRANT USAGE, SELECT ON SEQUENCE jamf_devices_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0199_jamf_webhook_coverage')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
