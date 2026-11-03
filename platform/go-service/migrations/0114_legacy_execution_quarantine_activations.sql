-- PAT-1481: durable process activations for monotonic legacy execution quarantine.
--
-- This table deliberately starts empty. The contained API records its random
-- process activation only on an authenticated agent-config GET, in the same
-- transaction that advances agent_config.config_version. Applying this
-- migration before replacing the binary therefore gives the old binary no new
-- generation at which it can sign an execution-capable payload.
BEGIN;

CREATE TABLE agent_config_legacy_execution_activations (
    tenant_id      UUID        NOT NULL REFERENCES agent_config(tenant_id) ON DELETE CASCADE,
    activation_id  TEXT        NOT NULL CHECK (activation_id ~ '^[0-9a-f]{64}$'),
    config_version INTEGER     NOT NULL CHECK (config_version > 0),
    activated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, activation_id)
);

COMMENT ON TABLE agent_config_legacy_execution_activations IS
    'One row per tenant and contained API process activation. The first GET from each process atomically records its nonce and advances agent_config.config_version; repeated GETs from that process reuse the resulting monotonic floor.';

COMMENT ON COLUMN agent_config.legacy_execution_quarantine_version IS
    'The latest config_version issued by a contained API process activation. NULL until the first contained GET; monotonically advances once per distinct process activation for this tenant.';

GRANT SELECT, INSERT ON TABLE agent_config_legacy_execution_activations TO patched;

INSERT INTO schema_migrations (version) VALUES ('0114_legacy_execution_quarantine_activations')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
