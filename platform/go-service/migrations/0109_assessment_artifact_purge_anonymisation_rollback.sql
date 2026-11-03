-- PAT-1407 rollback. This can reverse the schema only before any tenant purge
-- has anonymised assessment audit rows; identifiers cannot be reconstructed.
BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM assessment_artifact_audit
         WHERE tenant_purge_anonymized_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0109: anonymised assessment audit rows exist';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS trg_assessment_artifact_audit_append_only_truncate ON assessment_artifact_audit;
DROP FUNCTION IF EXISTS assessment_artifact_audit_reject_truncate();
DROP TRIGGER IF EXISTS trg_assessment_artifact_audit_insert_shape ON assessment_artifact_audit;
DROP FUNCTION IF EXISTS assessment_artifact_audit_insert_shape();

CREATE OR REPLACE FUNCTION assessment_artifact_audit_append_only()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'assessment_artifact_audit is append-only';
END;
$$;

ALTER TABLE assessment_artifact_audit
    DROP CONSTRAINT IF EXISTS assessment_artifact_audit_action_shape_check,
    DROP CONSTRAINT IF EXISTS assessment_artifact_audit_check;

ALTER TABLE assessment_artifact_audit
    ADD CONSTRAINT assessment_artifact_audit_check CHECK (
        (action = 'approved' AND token_id IS NULL AND actor IS NOT NULL AND recipient_email IS NULL)
        OR
        (action = 'token_issued' AND token_id IS NOT NULL AND actor IS NOT NULL AND recipient_email IS NOT NULL)
        OR
        (action = 'downloaded' AND token_id IS NOT NULL AND actor IS NULL AND recipient_email IS NOT NULL)
    );

ALTER TABLE assessment_artifact_audit
    DROP COLUMN tenant_purge_anonymized_at;

CREATE OR REPLACE FUNCTION anonymize_tenant_audit_before_purge() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM set_config('patched.tenant_purge_anonymizing', 'on', true);

    UPDATE tenant_tier_changes SET claimed_actor = NULL, source_addr = NULL WHERE tenant_id = OLD.id;
    UPDATE device_revocations SET claimed_actor = NULL, source_addr = NULL, device_id = NULL WHERE tenant_id = OLD.id;
    UPDATE enrollment_token_audit SET token_id = NULL, actor_email = NULL, admin_note = NULL WHERE tenant_id = OLD.id;
    UPDATE tenant_decommission_audit SET claimed_actor = NULL, source_addr = NULL, reason = NULL WHERE tenant_id = OLD.id;

    RETURN OLD;
END;
$$;

COMMENT ON TABLE assessment_artifact_audit IS
    'Append-only audit trail for approved assessment artifacts, issued download tokens and successful downloads. Identifying actor and recipient fields are retained in their original action-specific shape.';

DELETE FROM schema_migrations WHERE version = '0109_assessment_artifact_purge_anonymisation';

COMMIT;
