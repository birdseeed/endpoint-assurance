-- patched.im — 0015_agent_config.sql
-- Per-tenant agent configuration store for GET /v1/agent-config (PAT-281).
--
-- One row per tenant — created here for all existing tenants (default config)
-- and by CreateTenantHandler for new tenants going forward.
--
-- config_version is a monotonic integer that the agent uses for anti-rollback:
-- the agent rejects any config whose version is lower than the last it accepted.
-- The server bumps it on every PUT /admin/agent-config/{tenantID}.
--
-- body JSONB holds the config content: tier, proxy, and reserved keys
-- (catalog_scope, scan_cadence, os_update_policy, per_app_patch). The signing
-- key and signature are NOT stored here — the handler re-signs on every GET.
-- Key rotation is therefore transparent: update AGENT_CONFIG_SIGNING_KEY and
-- the next GET response carries the new key_id automatically.
--
-- Rollback: migrations/0015_agent_config_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0015_agent_config.sql
-- Note: 0014_device_hardware.sql must have been applied first.

BEGIN;

CREATE TABLE agent_config (
    id             BIGSERIAL    PRIMARY KEY,
    tenant_id      UUID         NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    config_version INTEGER      NOT NULL DEFAULT 1,
    body           JSONB        NOT NULL DEFAULT '{}',
    issued_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by     TEXT         NOT NULL DEFAULT 'system'
);

CREATE INDEX idx_agent_config_tenant ON agent_config(tenant_id);

COMMENT ON TABLE agent_config IS
    'Per-tenant agent configuration served by GET /v1/agent-config. One row per tenant. config_version is monotonic — bump on every write. body is the signable config content (tier, proxy, reserved keys). Signature is computed on the fly at read time; do not store it here.';
COMMENT ON COLUMN agent_config.config_version IS
    'Monotonic integer; bumped on every PUT /admin/agent-config/{tenantID}. The agent uses this for anti-rollback — it rejects configs with a lower version than the last accepted.';
COMMENT ON COLUMN agent_config.body IS
    'Config content: {"tier": "report_deploy"|"patch", "proxy": {...}, "catalog_scope": null, "scan_cadence": null, "os_update_policy": null, "per_app_patch": null}. tier and proxy are the live fields; the rest are reserved for future workstreams.';
COMMENT ON COLUMN agent_config.updated_by IS
    'Identity of the actor who last wrote this row: email address, API key label, or "system" / "migration".';

-- Backfill default config for all existing tenants.
-- tier = "report_deploy" is the safe default for any tenant already in prod —
-- they are not yet patch-capable. proxy.mode = "system" means use OS proxy.
INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
SELECT
    id,
    1,
    '{"tier": "report_deploy", "proxy": {"mode": "system", "bypass_when_off_corp": false, "type": null, "host": null, "port": null, "pac_url": null, "auth_ref": null}, "catalog_scope": null, "scan_cadence": null, "os_update_policy": null, "per_app_patch": null}'::jsonb,
    now(),
    'migration'
FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON TABLE agent_config TO patched;
GRANT USAGE, SELECT ON SEQUENCE agent_config_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0015_agent_config');

COMMIT;
