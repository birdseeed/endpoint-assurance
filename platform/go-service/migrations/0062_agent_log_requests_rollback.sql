-- Rollback for 0062_agent_log_requests (PAT-651).
-- Reverts the grant extension; the agent_logs table itself (created in 0037)
-- is left in place — rolling back the table would drop all stored log bundles.

BEGIN;

REVOKE UPDATE, DELETE ON agent_logs FROM patched;

DELETE FROM schema_migrations WHERE version = '0062_agent_log_requests';

COMMIT;
