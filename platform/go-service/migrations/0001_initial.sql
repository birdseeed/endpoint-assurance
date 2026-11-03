-- patched.im — initial schema (six application tables + bookkeeping)
-- Applies to the patched database on patched-api-01.
--
-- Run with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0001_initial.sql

BEGIN;

-- Required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- TENANTS — one row per customer organisation
-- ============================================================================
CREATE TABLE tenants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    intune_tenant_id    UUID,                 -- customer's Entra tenant ID; set after Graph consent
    bearer_token_hash   BYTEA NOT NULL,       -- SHA-256 of the bearer token; plaintext never stored
    hmac_secret         BYTEA NOT NULL,       -- v1: stored as raw bytes; encryption-at-rest via volume only.
                                              -- v2 plan: envelope-encrypt with a KEK from /etc/patched-api/env.
                                              -- We cannot hash this — HMAC verification needs the raw secret.
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    notes               TEXT
);

CREATE INDEX idx_tenants_bearer_token_hash ON tenants(bearer_token_hash);
CREATE INDEX idx_tenants_intune_tenant_id  ON tenants(intune_tenant_id) WHERE intune_tenant_id IS NOT NULL;

COMMENT ON COLUMN tenants.bearer_token_hash IS 'SHA-256(bearer_token); compare against SHA-256(incoming Authorization header)';
COMMENT ON COLUMN tenants.hmac_secret       IS 'Raw HMAC secret; needed for HMAC-SHA256 signature verification. v1 plaintext, v2 envelope-encrypted.';

-- ============================================================================
-- DEVICES — per-tenant inventory of managed endpoints
-- ============================================================================
CREATE TABLE devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    serial              TEXT,                 -- macOS: IOPlatformSerialNumber; Windows: BIOS serial
    hw_uuid             UUID,                 -- macOS: IOPlatformUUID; Windows: SMBIOS UUID
    hostname            TEXT,
    computer_name       TEXT,                 -- separate from hostname (human-friendly)
    os                  TEXT NOT NULL,        -- "macOS" | "Windows"
    os_version          TEXT,
    os_build            TEXT,
    hw_model            TEXT,
    arch                TEXT,                 -- "arm64" | "x86_64" | "x86_64 arm64"
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, hw_uuid),
    UNIQUE (tenant_id, serial)
);

CREATE INDEX idx_devices_tenant_id ON devices(tenant_id);
CREATE INDEX idx_devices_last_seen ON devices(last_seen);

-- ============================================================================
-- DEVICE APPS — current installed-software state per device
-- ============================================================================
CREATE TABLE device_apps (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    version             TEXT,
    identifier          TEXT NOT NULL,        -- bundle_id (macOS); MSI product code or registry uninstall key (Windows)
    path                TEXT,
    size_bytes          BIGINT,
    sha256              TEXT,                 -- SHA-256 of the main executable
    signer              TEXT,                 -- codesign Authority (macOS); Authenticode publisher (Windows)
    team_id             TEXT,                 -- TeamIdentifier (macOS); publisher CN (Windows)
    architecture        TEXT,
    notarized           BOOLEAN,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, identifier, version)
);

CREATE INDEX idx_device_apps_device_id   ON device_apps(device_id);
CREATE INDEX idx_device_apps_identifier  ON device_apps(identifier);
CREATE INDEX idx_device_apps_sha256      ON device_apps(sha256) WHERE sha256 IS NOT NULL;

-- ============================================================================
-- COMPLIANCE SIGNALS — time-series of per-device compliance state
-- (Append-only; the auditor-ready report is built from this table.)
-- ============================================================================
CREATE TABLE compliance_signals (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key                 TEXT NOT NULL,        -- "filevault" | "sip" | "bitlocker" | "asr_block_office_macro" | ...
    value               TEXT NOT NULL,        -- "On" | "Off" | "enabled" | etc. — string-typed for flexibility
    severity            TEXT,                 -- "ok" | "warn" | "fail" | "info"
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_compliance_device_observed ON compliance_signals(device_id, observed_at DESC);
CREATE INDEX idx_compliance_key_severity    ON compliance_signals(key, severity) WHERE severity IN ('warn','fail');

-- ============================================================================
-- PATCHES — installed software updates per device
-- ============================================================================
CREATE TABLE patches (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    identifier          TEXT NOT NULL,        -- KB number (Windows) | package label (macOS)
    title               TEXT,
    installed_at        TIMESTAMPTZ,
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, identifier)
);

CREATE INDEX idx_patches_device_id ON patches(device_id);

-- ============================================================================
-- RAW PAYLOADS — immutable archive of every inbound POST
-- Partitioned monthly on received_at for cheap pruning / cold storage rotation.
-- ============================================================================
CREATE TABLE raw_payloads (
    id                  BIGSERIAL,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id           UUID REFERENCES devices(id) ON DELETE SET NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip           INET,
    user_agent          TEXT,
    body                JSONB NOT NULL,
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

-- Initial partitions — two months of runway (0036 adds the rest).
-- pg_partman or a cron job rotates these later; for MVP they're hand-created.
CREATE TABLE raw_payloads_2026_07 PARTITION OF raw_payloads
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE raw_payloads_2026_08 PARTITION OF raw_payloads
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

CREATE INDEX idx_raw_payloads_tenant_received ON raw_payloads(tenant_id, received_at DESC);
CREATE INDEX idx_raw_payloads_device_received ON raw_payloads(device_id, received_at DESC) WHERE device_id IS NOT NULL;

-- ============================================================================
-- SCHEMA MIGRATIONS — minimal bookkeeping (no external migration tool for MVP)
-- ============================================================================
CREATE TABLE schema_migrations (
    version             TEXT PRIMARY KEY,
    applied_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES ('0001_initial');

COMMIT;
