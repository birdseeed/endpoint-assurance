-- Roll back PAT-1481's durable legacy-execution quarantine generation marker.
BEGIN;

ALTER TABLE agent_config
    DROP CONSTRAINT IF EXISTS agent_config_legacy_execution_quarantine_version_check,
    DROP COLUMN IF EXISTS legacy_execution_quarantine_version;

DELETE FROM schema_migrations
WHERE version = '0113_legacy_execution_quarantine_generation';

COMMIT;
