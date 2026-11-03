-- Roll back binaries before removing the additive update-channel observation.
BEGIN;
DROP TABLE IF EXISTS agent_update_channel_observations;
DELETE FROM schema_migrations WHERE version='0205_agent_update_channel_observations';
COMMIT;
