BEGIN;

-- Intent and event rows are durable audit/provenance. A rollback may remove
-- an unused schema, but must never silently destroy evidence from a live or
-- completed delivery lifecycle. Exporting that evidence is an explicit
-- operator action outside this migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM mandatory_install_intents LIMIT 1)
       OR EXISTS (SELECT 1 FROM mandatory_install_intent_events LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back 0110: durable mandatory install intent/event evidence exists';
    END IF;
END $$;

ALTER TABLE device_apps DROP COLUMN IF EXISTS identifier_kind;
ALTER TABLE devices
    DROP COLUMN IF EXISTS windows_winget_inventory_schema,
    DROP COLUMN IF EXISTS windows_winget_inventory_complete;
DROP TABLE IF EXISTS mandatory_install_intent_events;
DROP INDEX IF EXISTS mandatory_install_intents_current_uq;
DROP TABLE IF EXISTS mandatory_install_intents;
DROP INDEX IF EXISTS tenant_app_policies_tenant_identity_v2_uniq;
ALTER TABLE tenant_app_policies DROP CONSTRAINT IF EXISTS tenant_app_policies_has_identity;
ALTER TABLE tenant_app_policies ADD CONSTRAINT tenant_app_policies_has_identity CHECK (
    team_id IS NOT NULL OR bundle_id IS NOT NULL OR winget_id IS NOT NULL OR name IS NOT NULL
);
-- Old binaries infer their ON CONFLICT arbiter from the pre-0110 four-field
-- identity. Preserve that writer contract when the retained Winget data can
-- be represented without conflating distinct reviewed policies. Otherwise
-- refuse rollback explicitly instead of deleting or corrupting identity.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM tenant_app_policies
        GROUP BY tenant_id, COALESCE(team_id,''), COALESCE(bundle_id,''),
                 COALESCE(lower(name),''), platform
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0110: distinct policies collide under the legacy tenant app policy identity';
    END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_app_policies_tenant_identity_uniq
    ON tenant_app_policies (tenant_id, COALESCE(team_id,''), COALESCE(bundle_id,''),
                            COALESCE(lower(name),''), platform);
-- winget_id deliberately remains as dormant rollback residue. Dropping it
-- would either destroy reviewed Windows policy identity or make this rollback
-- fail its restored identity constraint for a real Winget-only policy.
ALTER TABLE catalogue_platform_targets DROP COLUMN IF EXISTS mandatory_installed_identity;
-- Append-only audit evidence is retained, so its dormant action vocabulary
-- must remain admitted after the delivery schema is rolled back.
ALTER TABLE ring_config_changes DROP CONSTRAINT IF EXISTS ring_config_changes_change_type_check;
ALTER TABLE ring_config_changes ADD CONSTRAINT ring_config_changes_change_type_check CHECK (change_type IN (
    'config_updated', 'device_override_set', 'device_override_cleared',
    'rollout_paused', 'rollout_resumed', 'rollout_skipped',
    'rollout_advanced', 'rollout_auto_paused', 'rollout_completed',
    'rollout_superseded', 'rollout_emergency_deploy', 'rollout_created',
    'mandatory_install_evaluated', 'mandatory_install_emergency',
    'mandatory_install_retried'
)) NOT VALID;
ALTER TABLE ring_config_changes VALIDATE CONSTRAINT ring_config_changes_change_type_check;
DELETE FROM schema_migrations WHERE version = '0110_mandatory_install_intents';
COMMIT;
