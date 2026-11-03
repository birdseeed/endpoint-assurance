-- 0062: agent log ingest — grant update (PAT-651).
--
-- The agent_logs table was created by migration 0037 (PAT-286) with only
-- SELECT + INSERT grants. The purge endpoint (POST /admin/agent-logs/purge)
-- and the idempotent re-upload path need DELETE and UPDATE access respectively.
-- This migration adds the missing grants idempotently.
--
-- The handler (POST /v1/agent-logs), admin list/fetch endpoints, agent-config
-- log_request contract, and AgentConfigBody.LogRequest field were all
-- implemented in prior sessions; this migration closes the permissions gap.

BEGIN;

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_logs TO patched;

INSERT INTO schema_migrations (version) VALUES ('0062_agent_log_requests')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
