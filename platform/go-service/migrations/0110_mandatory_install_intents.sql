-- patched.im — 0110_mandatory_install_intents.sql
-- PAT-1399: durable, platform-neutral mandatory-install delivery state.
--
-- This migration creates control-plane intent and audit state only. It does
-- not add an installer, privileged command, or endpoint execution surface.
BEGIN;

-- PAT-1399 may infer Windows app absence only from an authenticated inventory
-- that explicitly declares a versioned, complete Winget enumeration. Existing
-- collectors default false and therefore fail closed until PAT-1401 ships the
-- endpoint marker. Per-app kind prevents MSI ProductCodes/display names from
-- being mistaken for canonical Winget IDs.
ALTER TABLE devices
    ADD COLUMN windows_winget_inventory_complete BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN windows_winget_inventory_schema SMALLINT;
ALTER TABLE device_apps
    ADD COLUMN identifier_kind TEXT
    CHECK (identifier_kind IS NULL OR identifier_kind IN ('winget','native'));

-- Owner/admin mandatory-install actions share the established append-only
-- ring configuration audit surface and its authenticated/claimed attribution.
ALTER TABLE ring_config_changes
    DROP CONSTRAINT IF EXISTS ring_config_changes_change_type_check;
ALTER TABLE ring_config_changes
    ADD CONSTRAINT ring_config_changes_change_type_check CHECK (change_type IN (
        'config_updated', 'device_override_set', 'device_override_cleared',
        'rollout_paused', 'rollout_resumed', 'rollout_skipped',
        'rollout_advanced', 'rollout_auto_paused', 'rollout_completed',
        'rollout_superseded', 'rollout_emergency_deploy', 'rollout_created',
        'mandatory_install_evaluated', 'mandatory_install_emergency',
        'mandatory_install_retried'
    )) NOT VALID;
ALTER TABLE ring_config_changes VALIDATE CONSTRAINT ring_config_changes_change_type_check;

-- Signed catalogue labels are installer/resolver keys (for example
-- "firefox"), not necessarily installed bundle/package identifiers.
ALTER TABLE catalogue_platform_targets
    ADD COLUMN mandatory_installed_identity TEXT
    CHECK (mandatory_installed_identity IS NULL OR
           (platform='macos' AND mandatory_installed_identity ~ '^bundle:.+$') OR
           (platform='windows' AND mandatory_installed_identity ~ '^winget:.+$'));

-- Windows mandatory policy identity is the exact Winget package id. Keep it
-- distinct from bundle_id (macOS CFBundleIdentifier / legacy Windows GUID).
ALTER TABLE tenant_app_policies ADD COLUMN winget_id TEXT;
ALTER TABLE tenant_app_policies DROP CONSTRAINT tenant_app_policies_has_identity;
ALTER TABLE tenant_app_policies ADD CONSTRAINT tenant_app_policies_has_identity CHECK (
    team_id IS NOT NULL OR bundle_id IS NOT NULL OR winget_id IS NOT NULL OR name IS NOT NULL
);
-- Keep the deployed binary's four-field ON CONFLICT arbiter throughout the
-- migration-first/binary-second rollout. The expanded writer uses its own
-- five-field arbiter. Until a later compatibility migration retires the old
-- index, distinct Winget-only rows for one tenant/platform are intentionally
-- refused rather than being ambiguously handled by an old writer.
CREATE UNIQUE INDEX tenant_app_policies_tenant_identity_v2_uniq
    ON tenant_app_policies (tenant_id, COALESCE(team_id,''), COALESCE(bundle_id,''),
                            COALESCE(winget_id,''), COALESCE(lower(name),''), platform);

CREATE TABLE mandatory_install_intents (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id             BIGINT REFERENCES tenant_app_policies(id) ON DELETE SET NULL,
    device_id             UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    catalogue_product_id  UUID NOT NULL REFERENCES catalogue_products(id) ON DELETE RESTRICT,
    catalogue_target_id   UUID NOT NULL REFERENCES catalogue_platform_targets(id) ON DELETE RESTRICT,
    rollout_id            UUID REFERENCES ring_version_approvals(id) ON DELETE SET NULL,
    platform              TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    label                 TEXT NOT NULL CHECK (btrim(label) <> ''),
    installed_identity    TEXT NOT NULL CHECK (
        (platform='macos' AND installed_identity ~ '^bundle:.+$') OR
        (platform='windows' AND installed_identity ~ '^winget:.+$')),
    target_version        TEXT NOT NULL CHECK (btrim(target_version) <> ''),
    verified_sha256       TEXT NOT NULL CHECK (verified_sha256 ~ '^[0-9a-f]{64}$'),
    verified_signer       TEXT NOT NULL CHECK (btrim(verified_signer) <> ''),
    catalogue_content_hash TEXT NOT NULL CHECK (catalogue_content_hash ~ '^[0-9a-f]{64}$'),
    catalogue_generated_at TIMESTAMPTZ NOT NULL,
    verified_at           TIMESTAMPTZ NOT NULL,
    rollout_ring          SMALLINT NOT NULL CHECK (rollout_ring BETWEEN 0 AND 3),
    emergency             BOOLEAN NOT NULL DEFAULT false,
    reason                TEXT NOT NULL CHECK (btrim(reason) <> '' AND octet_length(reason) <= 1024),
    state                 TEXT NOT NULL DEFAULT 'queued' CHECK (state IN (
                              'queued','delivered','received','installing',
                              'succeeded','failed','cancelled')),
    delivery_id           UUID,
    delivery_attempt      INTEGER NOT NULL DEFAULT 0 CHECK (delivery_attempt >= 0),
    delivered_at          TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    completed_at          TIMESTAMPTZ,
    last_error            TEXT CHECK (last_error IS NULL OR octet_length(last_error) <= 1024),
    operator_recovery_reason TEXT CHECK (operator_recovery_reason IS NULL OR octet_length(operator_recovery_reason) <= 1024),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mandatory_install_delivery_complete CHECK ((
        state IN ('queued','cancelled') AND delivery_id IS NULL AND delivered_at IS NULL AND expires_at IS NULL
    ) OR (
        state IN ('delivered','received','installing','succeeded','failed')
        AND delivery_id IS NOT NULL AND delivered_at IS NOT NULL AND expires_at IS NOT NULL
    ))
);

-- Cancelled rows are durable history, not the current intent. This partial
-- key keeps concurrent evaluation idempotent while allowing a later policy
-- re-enable to create a fresh intent with its own event history. Failed and
-- succeeded rows intentionally remain in the key: failed work uses the
-- explicit reasoned retry action, while ticket-scoped repeated evaluation must
-- never infer a same-version reinstall from lagging/missing inventory after a
-- success. A future removal/reinstall contract needs authoritative fresh
-- removal evidence and a separate explicit action.
CREATE UNIQUE INDEX mandatory_install_intents_current_uq
    ON mandatory_install_intents (device_id, catalogue_target_id, target_version)
    WHERE state <> 'cancelled';
CREATE INDEX mandatory_install_intents_device_active_idx
    ON mandatory_install_intents (device_id, created_at)
    WHERE state IN ('queued','delivered','received','installing');
CREATE INDEX mandatory_install_intents_tenant_state_idx
    ON mandatory_install_intents (tenant_id, state, updated_at DESC);

CREATE TABLE mandatory_install_intent_events (
    id              BIGSERIAL PRIMARY KEY,
    intent_id       UUID NOT NULL REFERENCES mandatory_install_intents(id) ON DELETE CASCADE,
    report_id       UUID,
    delivery_id     UUID,
    from_state      TEXT,
    to_state        TEXT NOT NULL CHECK (to_state IN (
                          'queued','delivered','received','installing',
                          'succeeded','failed','cancelled')),
    attempt         INTEGER NOT NULL CHECK (attempt >= 0),
    source          TEXT NOT NULL CHECK (source IN ('evaluation','delivery','device','policy','emergency','retry')),
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX mandatory_install_intent_events_report_uq
    ON mandatory_install_intent_events (intent_id, report_id)
    WHERE report_id IS NOT NULL;
CREATE INDEX mandatory_install_intent_events_intent_idx
    ON mandatory_install_intent_events (intent_id, recorded_at);

GRANT SELECT, INSERT, UPDATE ON mandatory_install_intents TO patched;
GRANT SELECT, INSERT ON mandatory_install_intent_events TO patched;
GRANT USAGE, SELECT ON SEQUENCE mandatory_install_intent_events_id_seq TO patched;
GRANT UPDATE (mandatory_installed_identity) ON catalogue_platform_targets TO patched;

INSERT INTO schema_migrations (version) VALUES ('0110_mandatory_install_intents');
COMMIT;
