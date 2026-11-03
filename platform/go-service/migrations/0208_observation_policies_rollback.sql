-- Rollback for 0208_observation_policies (PAT-2031).
--
-- Roll the API binary back first. This removes customer observation-policy
-- state only. The decision ledger is append-only, so rollback refuses once
-- an observation decision exists rather than disabling its guard or deleting
-- audit evidence. The derived presence rows are rebuilt by 0202's runner.

BEGIN;

DROP TRIGGER IF EXISTS trg_unapproved_presence_tooling_current ON tooling_current_entries;
DROP TRIGGER IF EXISTS trg_unapproved_presence_tooling_state_ins_del ON tooling_device_state;
DROP TRIGGER IF EXISTS trg_unapproved_presence_tooling_state_upd ON tooling_device_state;
DROP TRIGGER IF EXISTS trg_unapproved_presence_observation_policies_ins_del ON tenant_observation_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_observation_policies_upd ON tenant_observation_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_cask_link ON homebrew_cask_app_links;
DROP FUNCTION IF EXISTS software_unapproved_presence_cask_link_dirty_trg();

DELETE FROM software_unapproved_presence WHERE policy_kind = 'observation';
ALTER TABLE software_unapproved_presence
    DROP CONSTRAINT software_unapproved_presence_policy_kind_check;
ALTER TABLE software_unapproved_presence
    ADD CONSTRAINT software_unapproved_presence_policy_kind_check
    CHECK (policy_kind IN ('application', 'browser_extension', 'homebrew_formula', 'homebrew_cask'));
ALTER TABLE software_unapproved_presence
    DROP COLUMN observation_kind,
    DROP COLUMN observation_source;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM software_approval_decisions WHERE product_type = 'observation') THEN
        RAISE EXCEPTION '0208 rollback refuses to discard append-only observation approval decisions';
    END IF;
END $$;
ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_check1;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_check1
    CHECK ((product_type = 'application' AND platform IS NOT NULL AND browser IS NULL)
        OR (product_type = 'browser_extension' AND platform IS NULL AND team_id IS NULL AND browser IS NOT NULL)
        OR (product_type IN ('homebrew_formula', 'homebrew_cask')
            AND platform IS NULL AND team_id IS NULL AND browser IS NULL));
ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_product_type_check;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_product_type_check
    CHECK (product_type IN ('application', 'browser_extension', 'homebrew_formula', 'homebrew_cask'));
ALTER TABLE software_approval_decisions
    DROP COLUMN observation_kind,
    DROP COLUMN observation_source;

DROP TABLE IF EXISTS tenant_observation_policies;
DELETE FROM schema_migrations WHERE version = '0208_observation_policies';

COMMIT;
