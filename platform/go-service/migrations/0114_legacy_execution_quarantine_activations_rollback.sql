-- Roll back PAT-1481's durable contained-process activation records.
BEGIN;

DROP TABLE IF EXISTS agent_config_legacy_execution_activations;

COMMENT ON COLUMN agent_config.legacy_execution_quarantine_version IS
    'The config_version first issued with PAT-1481 legacy execution containment. NULL until the contained GET path atomically advances the tenant generation once; retained thereafter so ordinary GETs never advance it again.';

DELETE FROM schema_migrations
WHERE version = '0114_legacy_execution_quarantine_activations';

COMMIT;
