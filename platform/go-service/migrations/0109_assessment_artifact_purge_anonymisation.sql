-- PAT-1407: retain assessment delivery governance events while removing
-- actor, recipient, and token identifiers during tenant purge.
BEGIN;

-- This marker is the durable, unambiguous record that 0109 irreversibly
-- removed identifiers from a row. Rollback must never infer that state from
-- nullable business columns, whose permitted shapes may evolve later.
ALTER TABLE assessment_artifact_audit
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;

-- 0108 created this deterministic PostgreSQL-generated name. Refuse to drop
-- an unexpected object with the same name, then normalize either first-run
-- or replay state to the single named 0109 constraint.
DO $$
DECLARE
    old_definition text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO old_definition
      FROM pg_constraint
     WHERE conrelid = 'assessment_artifact_audit'::regclass
       AND conname = 'assessment_artifact_audit_check'
       AND contype = 'c';
    IF old_definition IS NULL AND NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'assessment_artifact_audit'::regclass
           AND conname = 'assessment_artifact_audit_action_shape_check'
           AND contype = 'c'
    ) THEN
        RAISE EXCEPTION 'expected 0108 assessment_artifact_audit_check is absent';
    END IF;
    IF old_definition IS NOT NULL
       AND (position('approved' in old_definition) = 0
            OR position('token_issued' in old_definition) = 0
            OR position('downloaded' in old_definition) = 0
            OR position('token_id' in old_definition) = 0
            OR position('actor' in old_definition) = 0
            OR position('recipient_email' in old_definition) = 0) THEN
        RAISE EXCEPTION '0108 assessment_artifact_audit_check has unexpected definition: %', old_definition;
    END IF;
END;
$$;

ALTER TABLE assessment_artifact_audit
    DROP CONSTRAINT IF EXISTS assessment_artifact_audit_check,
    DROP CONSTRAINT IF EXISTS assessment_artifact_audit_action_shape_check;

ALTER TABLE assessment_artifact_audit
    ADD CONSTRAINT assessment_artifact_audit_action_shape_check CHECK (
        action IN ('approved','token_issued','downloaded') AND (
        (tenant_purge_anonymized_at IS NOT NULL
         AND actor IS NULL AND recipient_email IS NULL AND token_id IS NULL)
        OR
        (tenant_purge_anonymized_at IS NULL AND action = 'approved' AND token_id IS NULL AND actor IS NOT NULL AND recipient_email IS NULL)
        OR
        (tenant_purge_anonymized_at IS NULL AND action = 'token_issued' AND token_id IS NOT NULL AND actor IS NOT NULL AND recipient_email IS NOT NULL)
        OR
        (tenant_purge_anonymized_at IS NULL AND action = 'downloaded' AND token_id IS NOT NULL AND actor IS NULL AND recipient_email IS NOT NULL))
    );

-- Prove the relaxed CHECK itself accepts every valid anonymised action shape.
-- The real table's BEFORE INSERT trigger remains stricter for new events.
CREATE TEMP TABLE pat1407_assessment_audit_shape_probe
    (LIKE assessment_artifact_audit INCLUDING CONSTRAINTS) ON COMMIT DROP;
INSERT INTO pat1407_assessment_audit_shape_probe
    (id, tenant_id, artifact_id, action, actor, recipient_email, token_id, sha256, occurred_at, tenant_purge_anonymized_at)
VALUES
    (1, gen_random_uuid(), gen_random_uuid(), 'approved', NULL, NULL, NULL, decode(repeat('aa',32),'hex'), now(), now()),
    (2, gen_random_uuid(), gen_random_uuid(), 'token_issued', NULL, NULL, NULL, decode(repeat('bb',32),'hex'), now(), now()),
    (3, gen_random_uuid(), gen_random_uuid(), 'downloaded', NULL, NULL, NULL, decode(repeat('cc',32),'hex'), now(), now());

-- The relaxed table constraint admits retained anonymised rows. New events
-- still have to satisfy the original action-specific identity shape.
CREATE OR REPLACE FUNCTION public.assessment_artifact_audit_insert_shape()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.tenant_purge_anonymized_at IS NULL
       AND ((NEW.action = 'approved' AND NEW.token_id IS NULL AND NEW.actor IS NOT NULL AND NEW.recipient_email IS NULL)
         OR (NEW.action = 'token_issued' AND NEW.token_id IS NOT NULL AND NEW.actor IS NOT NULL AND NEW.recipient_email IS NOT NULL)
         OR (NEW.action = 'downloaded' AND NEW.token_id IS NOT NULL AND NEW.actor IS NULL AND NEW.recipient_email IS NOT NULL)) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'assessment_artifact_audit insert has invalid action identity shape';
END;
$$;

DROP TRIGGER IF EXISTS trg_assessment_artifact_audit_insert_shape ON assessment_artifact_audit;
CREATE TRIGGER trg_assessment_artifact_audit_insert_shape
    BEFORE INSERT ON assessment_artifact_audit
    FOR EACH ROW EXECUTE FUNCTION assessment_artifact_audit_insert_shape();

-- A caller-settable GUC is not sufficient authority. The exception is valid
-- only in the nested UPDATE fired from the tenants BEFORE DELETE trigger and
-- only when the three identifying fields are nulled while every governance
-- field remains byte-for-byte unchanged.
CREATE OR REPLACE FUNCTION public.assessment_artifact_audit_append_only()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND pg_trigger_depth() = 2
       AND current_setting('patched.tenant_purge_anonymizing', true) = 'on'
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.tenant_id IS NOT DISTINCT FROM OLD.tenant_id
       AND NEW.artifact_id IS NOT DISTINCT FROM OLD.artifact_id
       AND NEW.action IS NOT DISTINCT FROM OLD.action
       AND NEW.sha256 IS NOT DISTINCT FROM OLD.sha256
       AND NEW.occurred_at IS NOT DISTINCT FROM OLD.occurred_at
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor IS NULL
       AND NEW.recipient_email IS NULL
       AND NEW.token_id IS NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'assessment_artifact_audit is append-only';
END;
$$;

CREATE OR REPLACE FUNCTION public.assessment_artifact_audit_reject_truncate()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'assessment_artifact_audit is append-only: TRUNCATE is not permitted';
END;
$$;

DROP TRIGGER IF EXISTS trg_assessment_artifact_audit_append_only_truncate ON assessment_artifact_audit;
CREATE TRIGGER trg_assessment_artifact_audit_append_only_truncate
    BEFORE TRUNCATE ON assessment_artifact_audit
    FOR EACH STATEMENT EXECUTE FUNCTION assessment_artifact_audit_reject_truncate();

-- Durable replay precondition: 0109 may replace the shared PAT-1137 function
-- only if the installed predecessor still contains every established update.
-- This runs before replacement, so a later migration clobber cannot be hidden
-- by 0109 replaying its own expected definition.
DO $$
DECLARE predecessor text := pg_get_functiondef('public.anonymize_tenant_audit_before_purge()'::regprocedure);
BEGIN
    IF position('tenant_tier_changes' in predecessor) = 0
       OR position('device_revocations' in predecessor) = 0
       OR position('enrollment_token_audit' in predecessor) = 0
       OR position('tenant_decommission_audit' in predecessor) = 0 THEN
        RAISE EXCEPTION 'installed PAT-1137 purge function has an unexpected definition';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.anonymize_tenant_audit_before_purge() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM set_config('patched.tenant_purge_anonymizing', 'on', true);

    UPDATE public.tenant_tier_changes
       SET claimed_actor = NULL,
           source_addr = NULL
     WHERE tenant_id = OLD.id;

    UPDATE public.device_revocations
       SET claimed_actor = NULL,
           source_addr = NULL,
           device_id = NULL
     WHERE tenant_id = OLD.id;

    UPDATE public.enrollment_token_audit
       SET token_id = NULL,
           actor_email = NULL,
           admin_note = NULL
     WHERE tenant_id = OLD.id;

    UPDATE public.tenant_decommission_audit
       SET claimed_actor = NULL,
           source_addr = NULL,
           reason = NULL
     WHERE tenant_id = OLD.id;

    UPDATE public.assessment_artifact_audit
       SET token_id = NULL,
           actor = NULL,
           recipient_email = NULL,
           tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id;

    RETURN OLD;
END;
$$;

-- This CREATE OR REPLACE owns the shared PAT-1137 trigger function. Assert
-- every established survivor update remains present before committing 0109;
-- otherwise a future edit must fail migration rather than silently weakening
-- an older purge guarantee.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'tenants'::regclass
           AND tgname = 'trg_tenants_anonymize_audit_before_purge'
           AND tgfoid = 'anonymize_tenant_audit_before_purge()'::regprocedure
           AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 8) = 8
           AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'PAT-1137 tenants purge trigger is absent';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'assessment_artifact_audit'::regclass
           AND tgname = 'trg_assessment_artifact_audit_append_only'
           AND tgfoid = 'assessment_artifact_audit_append_only()'::regprocedure
           AND (tgtype & 1) = 1 AND (tgtype & 2) = 2
           AND (tgtype & 8) = 8 AND (tgtype & 16) = 16
           AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'assessment append-only row trigger attachment is absent or wrong';
    END IF;
END;
$$;

COMMENT ON TABLE assessment_artifact_audit IS
    'Append-only assessment delivery governance log. approved/token_issued/downloaded rows retain tenant_id, artifact_id, action, sha256 and occurred_at for 6 years by default pending PAT-112. Tenant purge nulls actor, recipient_email and token_id and records tenant_purge_anonymized_at through the nested tenants BEFORE DELETE trigger only; direct UPDATE, DELETE and TRUNCATE remain rejected (PAT-1407).';

COMMENT ON COLUMN assessment_artifact_audit.tenant_purge_anonymized_at IS
    'Non-null only after the PAT-1407 tenant-purge trigger irreversibly removes this row''s actor, recipient and token identifiers; the durable rollback-safety marker.';

COMMENT ON TRIGGER trg_tenants_anonymize_audit_before_purge ON tenants IS
    'PAT-1137/PAT-1407: before tenant deletion, anonymise identifying columns in retained governance audit tables, including assessment_artifact_audit, before tenant-owned rows cascade away.';

INSERT INTO schema_migrations (version) VALUES ('0109_assessment_artifact_purge_anonymisation')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
