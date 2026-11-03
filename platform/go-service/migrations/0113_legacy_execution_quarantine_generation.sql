-- PAT-1481: durable one-time anti-rollback generation for legacy execution quarantine.
--
-- The column starts NULL deliberately. The contained GET path atomically bumps
-- agent_config.config_version and records the resulting generation on its first
-- request after the quarantining binary is active. Backfilling or bumping here
-- would let the pre-quarantine binary serve an executable payload at the new
-- version during the migration-first deployment window.
BEGIN;

ALTER TABLE agent_config
    ADD COLUMN legacy_execution_quarantine_version INTEGER;

ALTER TABLE agent_config
    ADD CONSTRAINT agent_config_legacy_execution_quarantine_version_check CHECK (
        legacy_execution_quarantine_version IS NULL OR
        (legacy_execution_quarantine_version > 0 AND
         legacy_execution_quarantine_version <= config_version)
    );

COMMENT ON COLUMN agent_config.legacy_execution_quarantine_version IS
    'The config_version first issued with PAT-1481 legacy execution containment. NULL until the contained GET path atomically advances the tenant generation once; retained thereafter so ordinary GETs never advance it again.';

INSERT INTO schema_migrations (version) VALUES ('0113_legacy_execution_quarantine_generation')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
