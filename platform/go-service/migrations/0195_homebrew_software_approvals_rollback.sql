-- Rollback for 0195_homebrew_software_approvals (PAT-2058)
--
-- Roll the API binary back first: PortalSoftwareApprovalsPutHandler and the
-- Homebrew portal reads (internal/report/portal_homebrew.go) reference
-- tenant_homebrew_policies and the widened product_type/check1 constraints
-- once this migration is applied.
--
-- Dropping tenant_homebrew_policies loses every Homebrew approval decision.
-- Export it first if that matters:
--   psql ... -c "\copy tenant_homebrew_policies TO 'tenant_homebrew_policies.csv' CSV HEADER"
--
-- Any software_approval_decisions row already written with product_type
-- homebrew_formula/homebrew_cask must be removed before the CHECK
-- constraints can be narrowed back; those audit rows are lost too. Export
-- first if that matters:
--   psql ... -c "\copy (SELECT * FROM software_approval_decisions WHERE product_type IN ('homebrew_formula','homebrew_cask')) TO 'homebrew_approval_decisions.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0195_homebrew_software_approvals_rollback.sql

BEGIN;

DELETE FROM software_approval_decisions WHERE product_type IN ('homebrew_formula', 'homebrew_cask');

ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_check1;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_check1
    CHECK ((product_type = 'application' AND platform IS NOT NULL AND browser IS NULL)
        OR (product_type = 'browser_extension' AND platform IS NULL AND team_id IS NULL AND browser IS NOT NULL));

ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_product_type_check;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_product_type_check
    CHECK (product_type IN ('application', 'browser_extension'));

DROP TABLE IF EXISTS tenant_homebrew_policies;

DELETE FROM schema_migrations WHERE version = '0195_homebrew_software_approvals';

COMMIT;
