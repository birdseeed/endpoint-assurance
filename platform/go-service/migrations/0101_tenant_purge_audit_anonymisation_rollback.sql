-- patched.im - 0101_tenant_purge_audit_anonymisation_rollback.sql
-- Reverses 0101_tenant_purge_audit_anonymisation.sql.
--
-- Restores the pre-migration cascade behaviour and drops the new triggers
-- and functions this migration added, mirroring 0096_audit_append_only_
-- guards_rollback.sql's pattern.
--
-- LIMITATION, stated plainly rather than silently failing partway: if any
-- tenant has already been purged since 0101 applied, its
-- device_revocations.device_id / enrollment_token_audit.token_id rows may
-- now be NULL, and re-adding NOT NULL on those columns below will error
-- until those rows are dealt with by hand. Re-adding the tenant_id FKs will
-- likewise error if any anonymised row's tenant_id no longer resolves to a
-- tenants row (the exact state this migration exists to create). This
-- rollback does not attempt to silently paper over either case - a purge
-- that already ran cannot be un-anonymised, only the schema's forward
-- behaviour can be reverted for future purges.

BEGIN;

-- ============================================================================
-- catalogue_review_audit / provenance_records - comment-only forward
-- changes; restore prior text.
-- ============================================================================

COMMENT ON TABLE catalogue_review_audit IS
    'Append-only decision/revocation/migration trail.';

COMMENT ON TABLE provenance_records IS
    'Immutable audit trail of third-party app updates from the Patched Updater. One row per app action. body JSONB is the source of truth - never UPDATE or DELETE rows here.';

-- ============================================================================
-- tenant_decommission_audit - restore the pre-0101 guard function (no
-- anonymisation exception) and comment. Trigger itself is untouched by
-- either migration.
-- ============================================================================

CREATE OR REPLACE FUNCTION reject_tenant_decommission_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_decommission_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE tenant_decommission_audit IS
    'Append-only audit trail of every write to tenant_decommission (PAT-1108), mirroring tenant_platform_changes (0010). One row per PUT /admin/tenants/{tenantID}/decommission call, whether or not the resulting directive differs from the previous one. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_decommission_audit_append_only for UPDATE/DELETE, trg_tenant_decommission_audit_append_only_truncate for TRUNCATE -- PAT-1108 fourth/fifth-round findings P2/P1-C), not merely documented against -- this holds even for the owning role.';
COMMENT ON COLUMN tenant_decommission_audit.reason IS
    'Operator-supplied free text, recorded and surfaced for audit/operator visibility only. Must NEVER be evaluated as a control-flow input, here or on the agent.';

-- ============================================================================
-- The tenants BEFORE DELETE trigger and its function.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_tenants_anonymize_audit_before_purge ON tenants;
DROP FUNCTION IF EXISTS anonymize_tenant_audit_before_purge();

-- ============================================================================
-- enrollment_token_audit - drop the new guard, restore NOT NULL and the FK.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_enrollment_token_audit_append_only ON enrollment_token_audit;
DROP TRIGGER IF EXISTS trg_enrollment_token_audit_append_only_truncate ON enrollment_token_audit;
DROP FUNCTION IF EXISTS reject_enrollment_token_audit_mutation();
DROP FUNCTION IF EXISTS reject_enrollment_token_audit_truncate();

ALTER TABLE enrollment_token_audit
    ALTER COLUMN token_id SET NOT NULL;

ALTER TABLE enrollment_token_audit
    ADD CONSTRAINT enrollment_token_audit_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

COMMENT ON TABLE enrollment_token_audit IS
    'Append-only audit log of every admin/portal enrolment-token mint (PAT-453).';
COMMENT ON COLUMN enrollment_token_audit.tenant_id IS NULL;
COMMENT ON COLUMN enrollment_token_audit.token_id IS NULL;

-- ============================================================================
-- device_revocations - restore the FK. NOT NULL on device_id is NOT
-- restored (device_id was never guarded, and the pre-0101 schema already
-- required it NOT NULL only because nothing ever nulled it - restoring the
-- constraint here would fail if any anonymised row exists; leaving it
-- nullable is the safe rollback default).
-- ============================================================================

ALTER TABLE device_revocations
    ADD CONSTRAINT device_revocations_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

COMMENT ON TABLE device_revocations IS
    'Append-only audit trail of every device revocation (PAT-549). Never UPDATE or DELETE rows here.';
COMMENT ON COLUMN device_revocations.tenant_id IS NULL;
COMMENT ON COLUMN device_revocations.device_id IS NULL;

-- ============================================================================
-- tenant_tier_changes - drop the new guard, restore the FK.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_tenant_tier_changes_append_only ON tenant_tier_changes;
DROP TRIGGER IF EXISTS trg_tenant_tier_changes_append_only_truncate ON tenant_tier_changes;
DROP FUNCTION IF EXISTS reject_tenant_tier_changes_mutation();
DROP FUNCTION IF EXISTS reject_tenant_tier_changes_truncate();

ALTER TABLE tenant_tier_changes
    ADD CONSTRAINT tenant_tier_changes_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

COMMENT ON TABLE tenant_tier_changes IS
    'Append-only audit log of every subscription_tier transition. Written atomically by PUT /admin/tenant-tier/{tenantID} alongside the tenants UPDATE.';
COMMENT ON COLUMN tenant_tier_changes.tenant_id IS NULL;

DELETE FROM schema_migrations WHERE version = '0101_tenant_purge_audit_anonymisation';

COMMIT;
