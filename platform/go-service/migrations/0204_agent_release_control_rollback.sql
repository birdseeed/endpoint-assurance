-- Roll binaries back first. Export release evidence/audit before this explicitly
-- destructive schema rollback; unlike derived inventory it cannot be rebuilt.
BEGIN;
DROP TABLE IF EXISTS agent_release_p0_activations, agent_release_p0_notices, agent_release_promotions, agent_release_evidence,
    agent_release_cohorts, agent_release_observations, agent_release_audit,
    agent_release_settings, agent_device_channels;
DROP FUNCTION IF EXISTS reject_agent_release_mutation();
DELETE FROM schema_migrations WHERE version = '0204_agent_release_control';
COMMIT;
