-- patched.im — 0015_agent_config_rollback.sql
-- Rolls back migration 0015_agent_config.sql.

BEGIN;

DROP TABLE IF EXISTS agent_config;

DELETE FROM schema_migrations WHERE version = '0015_agent_config';

COMMIT;
