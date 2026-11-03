-- patched.im — 0091_agent_decommission_rollback.sql
-- Reverses 0091_agent_decommission.sql.
--
-- Data loss on rollback is expected and accepted for device_decommission_state
-- and tenant_decommission_audit (same as every other DROP rollback in this
-- directory) -- both are server-side bookkeeping with no archived source to
-- rebuild from (unlike raw_payloads-derived tables). tenant_decommission is
-- the one exception worth flagging explicitly: rolling this back DESTROYS
-- the tenant-wide decommission directive itself, including any tenant
-- currently mid-decommission. Re-applying the forward migration does NOT
-- restore it -- there is no archive to replay it from, only
-- tenant_decommission_audit, which this rollback also drops. Do not roll
-- this migration back on a box with any live directive without first
-- reading tenant_decommission and tenant_decommission_audit to capture
-- their contents.
BEGIN;

DROP TABLE IF EXISTS device_decommission_state;
-- The triggers on tenant_decommission_audit are dependent objects of the
-- table and would be dropped implicitly by DROP TABLE below, but the
-- functions backing them are separate objects with no ownership
-- relationship to the table and are NOT dropped automatically — drop them
-- explicitly (PAT-1108 fourth-round finding P2, fifth-round finding P1-C)
-- so this rollback leaves no orphaned function behind.
DROP TRIGGER IF EXISTS trg_tenant_decommission_audit_append_only ON tenant_decommission_audit;
DROP TRIGGER IF EXISTS trg_tenant_decommission_audit_append_only_truncate ON tenant_decommission_audit;
DROP TABLE IF EXISTS tenant_decommission_audit;
DROP FUNCTION IF EXISTS reject_tenant_decommission_audit_mutation();
DROP FUNCTION IF EXISTS reject_tenant_decommission_audit_truncate();
DROP TABLE IF EXISTS tenant_decommission;

DELETE FROM schema_migrations WHERE version = '0091_agent_decommission';

COMMIT;
