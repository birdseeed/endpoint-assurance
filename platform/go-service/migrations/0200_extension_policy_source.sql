-- patched.im - 0200_extension_policy_source.sql
-- PAT-2089: who set each browser-extension decision, operator or portal.
--
-- tenant_extension_policies holds both the operator's decisions (admin API,
-- /admin/tenants/{id}/extension-policies) and, since PAT-2007, the customer's
-- (PUT /v1/portal/software-approvals). Only the operator's may feed the signed
-- agent extension blocklist (dbGetExtensionBlocklist, gated on
-- tenants.app_control_enabled). Before this column the two were
-- indistinguishable, so a customer's Unapproved set while App Control was off
-- became browser enforcement the moment an operator switched App Control on,
-- and nobody had chosen that.
--
--   source   'operator'  set by the operator admin API (or any server path
--                        that is not the portal). Feeds the blocklist on an
--                        App Control tenant.
--            'portal'    set by a customer portal admin. Never feeds the
--                        blocklist; on an App Control tenant the operator sees
--                        it as a suggestion (GET .../extension-policies,
--                        portal_suggestions).
--
-- The column records who set the row's CURRENT decision: each writer stamps
-- its own value on insert and on update, so an operator who edits a portal
-- row adopts it, and vice versa.
--
-- Backfill rule. The portal write path records every change it makes in
-- software_approval_decisions (0182, source = 'portal') in the same
-- transaction as the policy write, so the decision's decided_at and the
-- row's updated_at are both that transaction's now() and are equal. Operator
-- writes record nothing there and set updated_at to their own timestamp.
-- So an existing row is 'portal' exactly when a portal decision exists for the
-- same tenant and the same product_key (browser_extension:<browser>:<id>, the
-- key the portal builds) whose new_state is the row's current policy and whose
-- decided_at equals the row's updated_at. Comparing >= is insufficient:
-- an operator transaction may start before a portal transaction but acquire
-- the policy lock later, so its now() can be earlier despite writing last.
-- Every other row is 'operator'.
-- The UPDATE is idempotent; re-running it after the new binary is live
-- closes the seconds-long window in which the previous binary's portal writes
-- take the 'operator' default.
--
-- tenant_extension_policies was created in 0071 (above MIGRATION_FLOOR=56).
-- Additive only: ADD COLUMN with a constant default is catalogue-only in
-- PG11+ (no rewrite). The previous binary never names the column, so its
-- inserts get the default and its updates leave the column alone.

BEGIN;

ALTER TABLE tenant_extension_policies
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'operator';

ALTER TABLE tenant_extension_policies
    DROP CONSTRAINT IF EXISTS tenant_extension_policies_source_check,
    ADD CONSTRAINT tenant_extension_policies_source_check
        CHECK (source IN ('operator', 'portal'));

UPDATE tenant_extension_policies p
SET source = 'portal'
WHERE p.source <> 'portal'
  AND EXISTS (
    SELECT 1 FROM software_approval_decisions d
    WHERE d.tenant_id = p.tenant_id
      AND d.source = 'portal'
      AND d.product_type = 'browser_extension'
      AND d.product_key = 'browser_extension:' || p.browser || ':' || p.extension_id
      AND d.new_state = p.policy
      AND d.decided_at = p.updated_at);

COMMENT ON COLUMN tenant_extension_policies.source IS
    'PAT-2089. Who set the current decision: operator (admin API) or portal (customer portal admin). Only operator rows feed the signed extension blocklist.';

INSERT INTO schema_migrations (version) VALUES ('0200_extension_policy_source')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
