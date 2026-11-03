-- patched.im - 0201_app_policy_source.sql
-- PAT-2091: who set each application decision, operator or portal.
--
-- A customer can approve a Windows application through the portal by its
-- curated alias (e.g. Zoom.Zoom) before any device reports it. The portal's
-- mandatory check (mandatoryResolvesFor) only sees identities already
-- observed, so it cannot know the app will report the name an operator's
-- 'mandatory' row is keyed on. Once the app appears, the portal's
-- bundle-keyed row is more specific than the operator's name-keyed row and
-- won in the resolver, so reports showed the customer's state for a
-- mandatory app. With this column the resolver (apppolicy.Resolve) drops
-- portal rows whenever an operator mandatory row matches.
--
--   source   'operator'  the operator admin API
--                        (PUT /admin/tenants/{id}/app-policies), the Patched
--                        Agent auto-approval seed, and every row that
--                        predates the portal
--            'portal'    PUT /v1/portal/software-approvals
--
-- Each writer stamps its own value on insert and on update, so the column
-- records who set the row's CURRENT decision.
--
-- Backfill rule (the same as 0200's for extensions). The portal records each
-- change in software_approval_decisions (source = 'portal') in the same
-- transaction as the policy write, so decided_at equals the row's updated_at;
-- operator writes record nothing there and change updated_at. An existing
-- row is 'portal' exactly when a portal decision exists for the same tenant
-- and product_key (application:<platform>:<lower(bundle_id)>[:<TEAM_ID>], the
-- key the portal builds, for a row keyed on bundle_id and optionally team_id
-- with no winget_id or name) whose new_state is the row's current policy in
-- portal vocabulary ('unmanaged' is 'ignored') and whose decided_at equals
-- the row's updated_at. Equality is required: an operator
-- transaction may begin earlier yet acquire the policy lock and write later,
-- so transaction now() does not order those writes. Every other row is
-- 'operator'. The UPDATE is idempotent and can be re-run after the new
-- binary is live.
--
-- tenant_app_policies was created in 0032, below MIGRATION_FLOOR=56. This
-- migration adds a column and a constraint that reads only that column, and
-- the backfill reads team_id, bundle_id, winget_id, name, platform, policy
-- and updated_at (present since 0032, winget_id since 0110), so it does not
-- depend on any index or seed whose live shape could differ from the
-- migrations. Additive only: ADD COLUMN with a constant default is
-- catalogue-only (no rewrite). The previous binary never names the column,
-- so its inserts take the default and its updates leave the column alone.

BEGIN;

ALTER TABLE tenant_app_policies
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'operator';

ALTER TABLE tenant_app_policies
    DROP CONSTRAINT IF EXISTS tenant_app_policies_source_check,
    ADD CONSTRAINT tenant_app_policies_source_check
        CHECK (source IN ('operator', 'portal'));

UPDATE tenant_app_policies p
SET source = 'portal'
WHERE p.source <> 'portal'
  AND p.bundle_id IS NOT NULL
  AND p.winget_id IS NULL
  AND p.name IS NULL
  AND p.platform IN ('macos', 'windows')
  AND EXISTS (
    SELECT 1 FROM software_approval_decisions d
    WHERE d.tenant_id = p.tenant_id
      AND d.source = 'portal'
      AND d.product_type = 'application'
      AND d.product_key = 'application:' || p.platform || ':' || lower(p.bundle_id)
                          || COALESCE(':' || upper(p.team_id), '')
      AND d.new_state = CASE p.policy WHEN 'unmanaged' THEN 'ignored' ELSE p.policy END
      AND d.decided_at = p.updated_at);

COMMENT ON COLUMN tenant_app_policies.source IS
    'PAT-2091. Who set the current decision: operator (admin API, agent seed) or portal (customer portal admin). The resolver never lets a portal row outrank an operator mandatory row.';

INSERT INTO schema_migrations (version) VALUES ('0201_app_policy_source')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
