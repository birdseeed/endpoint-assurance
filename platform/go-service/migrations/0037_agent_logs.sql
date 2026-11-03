-- patched.im — 0037_agent_logs.sql
-- PAT-286: on-demand agent log ingest — storage + retention.
--
-- agent_logs stores gzipped JSON-lines bundles uploaded by agents in response
-- to a log_request directive in their signed agent config. One row per
-- (tenant, device, request_id). The request_id is the idempotency key issued
-- by the platform in the log_request directive; re-uploads with the same
-- request_id are silently ignored (ON CONFLICT DO NOTHING).
--
-- Retention: rows older than log_retention_days (default 30) should be purged
-- periodically. There is no background goroutine in patched-api for this yet;
-- run the purge SQL manually or via a cron job:
--   DELETE FROM agent_logs WHERE received_at < now() - make_interval(days => 30);
--
-- Per-tenant size ceiling: the POST /v1/agent-logs handler enforces a default
-- ceiling (see agentLogsCeilingBytes constant) by summing existing bundle sizes
-- for the tenant before inserting. No DB-stored per-tenant override yet.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0037_agent_logs.sql
-- Note: 0035_drop_dashboard_tables.sql must have been applied first.

BEGIN;

CREATE TABLE agent_logs (
    id                  BIGSERIAL    PRIMARY KEY,
    tenant_id           UUID         NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,
    device_id           UUID         NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    request_id          UUID         NOT NULL,
    received_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    bundle_bytes        BYTEA        NOT NULL,
    bundle_size_bytes   BIGINT       NOT NULL,
    UNIQUE (tenant_id, device_id, request_id)
);

CREATE INDEX idx_agent_logs_tenant_received ON agent_logs (tenant_id, received_at DESC);
CREATE INDEX idx_agent_logs_device          ON agent_logs (device_id);

COMMENT ON TABLE agent_logs IS
    'Gzipped JSON-lines log bundles uploaded by the Patched agent on demand (PAT-286). '
    'Keyed by (tenant_id, device_id, request_id) — request_id is the idempotency key from the log_request directive. '
    'bundle_bytes is the raw compressed payload; bundle_size_bytes is its byte length (compressed). '
    'Rows older than 30 days should be purged periodically.';

GRANT SELECT, INSERT ON TABLE agent_logs TO patched;
GRANT USAGE, SELECT ON SEQUENCE agent_logs_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0037_agent_logs');

COMMIT;
