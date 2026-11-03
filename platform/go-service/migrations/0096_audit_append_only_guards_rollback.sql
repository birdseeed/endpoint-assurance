-- patched.im — 0096_audit_append_only_guards_rollback.sql
-- Reverses 0096_audit_append_only_guards.sql.
--
-- No tables, columns, or rows are dropped by this rollback — the forward
-- migration only added triggers/functions and edited comments. The triggers
-- are dependent objects of their tables and would be dropped automatically
-- by a `DROP TABLE`, but this migration never drops a table, and the
-- functions backing the triggers are separate objects with no ownership
-- relationship to the table — DROP TRIGGER does not remove them either.
-- Both must be dropped explicitly (mirroring 0091_agent_decommission_rollback.sql's
-- pattern for trg_tenant_decommission_audit_append_only) or this rollback
-- would leave five orphaned pairs of functions behind with nothing
-- referencing them.
--
-- Table comments are reset to their pre-0096 text so a rollback fully
-- restores the pre-migration state, not just the enforcement behaviour.

BEGIN;

-- ============================================================================
-- tenant_platform_changes
-- ============================================================================

DROP TRIGGER IF EXISTS trg_tenant_platform_changes_append_only ON tenant_platform_changes;
DROP TRIGGER IF EXISTS trg_tenant_platform_changes_append_only_truncate ON tenant_platform_changes;
DROP FUNCTION IF EXISTS reject_tenant_platform_changes_mutation();
DROP FUNCTION IF EXISTS reject_tenant_platform_changes_truncate();

COMMENT ON TABLE tenant_platform_changes IS
    'Append-only audit trail of every tenants.macos_enabled / windows_enabled flip. Never UPDATE or DELETE rows here — use INSERT to record each change.';

-- ============================================================================
-- tenant_rule_changes
-- ============================================================================

DROP TRIGGER IF EXISTS trg_tenant_rule_changes_append_only ON tenant_rule_changes;
DROP TRIGGER IF EXISTS trg_tenant_rule_changes_append_only_truncate ON tenant_rule_changes;
DROP FUNCTION IF EXISTS reject_tenant_rule_changes_mutation();
DROP FUNCTION IF EXISTS reject_tenant_rule_changes_truncate();

COMMENT ON TABLE tenant_rule_changes IS
    'Append-only audit trail of every tenant_rules mutation. Never UPDATE or DELETE rows here — use INSERT to record each change.';

-- ============================================================================
-- tenant_app_policy_changes
-- ============================================================================

DROP TRIGGER IF EXISTS trg_tenant_app_policy_changes_append_only ON tenant_app_policy_changes;
DROP TRIGGER IF EXISTS trg_tenant_app_policy_changes_append_only_truncate ON tenant_app_policy_changes;
DROP FUNCTION IF EXISTS reject_tenant_app_policy_changes_mutation();
DROP FUNCTION IF EXISTS reject_tenant_app_policy_changes_truncate();

COMMENT ON TABLE tenant_app_policy_changes IS
    'Append-only audit trail of every app-update-policy mutation: per-app toggles (app_enabled/app_disabled/app_removed) and fleet-default flips (default_changed). Never UPDATE or DELETE rows here — use INSERT to record each change.';

-- ============================================================================
-- ring_config_changes
-- ============================================================================

DROP TRIGGER IF EXISTS trg_ring_config_changes_append_only ON ring_config_changes;
DROP TRIGGER IF EXISTS trg_ring_config_changes_append_only_truncate ON ring_config_changes;
DROP FUNCTION IF EXISTS reject_ring_config_changes_mutation();
DROP FUNCTION IF EXISTS reject_ring_config_changes_truncate();

COMMENT ON TABLE ring_config_changes IS
    'Append-only audit log for patching ring configuration and rollout state transitions.';

-- ============================================================================
-- enforcement_audit
-- ============================================================================

DROP TRIGGER IF EXISTS trg_enforcement_audit_append_only ON enforcement_audit;
DROP TRIGGER IF EXISTS trg_enforcement_audit_append_only_truncate ON enforcement_audit;
DROP FUNCTION IF EXISTS reject_enforcement_audit_mutation();
DROP FUNCTION IF EXISTS reject_enforcement_audit_truncate();

COMMENT ON TABLE enforcement_audit IS
    'Stores events emitted by agents when they remove an unauthorised local admin or block an unapproved app.';

-- ============================================================================
-- Comment corrections — restore pre-0096 text.
-- ============================================================================

COMMENT ON TABLE compliance_signals IS
    'Time-series of per-device compliance state (Append-only; the auditor-ready report is built from this table.)';

COMMENT ON TABLE raw_payloads IS
    'Immutable archive of every inbound POST, partitioned monthly on received_at.';

DELETE FROM schema_migrations WHERE version = '0096_audit_append_only_guards';

COMMIT;
