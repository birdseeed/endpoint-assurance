-- Reverses 0228_audit_ledger_purge_redaction.sql (PAT-2403).
--
-- Only a schema rollback is possible, and only before any irreversible
-- redaction: a redacted actor, reason, hostname, serial, details object or
-- declaration snapshot cannot be reconstructed, and the restored NOT NULL
-- constraints could not hold. The marker column is the only evidence of that
-- state, so this refuses to run once any row in any of the seven ledgers
-- carries it.
BEGIN;
DO $$
DECLARE
    ledger text;
    marked boolean;
BEGIN
    FOREACH ledger IN ARRAY ARRAY[
        'software_approval_decisions', 'device_retirement_decisions', 'jamf_webhook_audit',
        'device_list_entry_deletions', 'agent_release_audit', 'software_declaration_decisions',
        'tenant_shadow_it_policy_changes'] LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE tenant_purge_anonymized_at IS NOT NULL)', ledger)
           INTO marked;
        IF marked THEN
            RAISE EXCEPTION 'cannot roll back 0228: anonymised % rows exist', ledger;
        END IF;
    END LOOP;
END;
$$;

DROP TRIGGER trg_tenants_redact_audit_ledgers_before_purge ON public.tenants;
DROP FUNCTION public.redact_audit_ledgers_before_tenant_purge();

-- tenant_shadow_it_policy_changes (0104)
CREATE OR REPLACE FUNCTION public.reject_tenant_shadow_it_policy_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_shadow_it_policy_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER trg_tenant_shadow_it_policy_changes_purge_marker_insert ON public.tenant_shadow_it_policy_changes;
ALTER TABLE public.tenant_shadow_it_policy_changes
    DROP CONSTRAINT tenant_shadow_it_policy_changes_purge_shape,
    DROP COLUMN tenant_purge_anonymized_at;

-- software_declaration_decisions: back to 0224's single statement-level guard.
DROP TRIGGER software_declaration_decisions_append_only_row ON public.software_declaration_decisions;
DROP FUNCTION public.reject_software_declaration_decision_row_mutation();
CREATE OR REPLACE FUNCTION public.reject_software_declaration_decision_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'software_declaration_decisions is append-only';
END;
$$;
DROP TRIGGER software_declaration_decisions_purge_marker_insert ON public.software_declaration_decisions;
ALTER TABLE public.software_declaration_decisions
    DROP CONSTRAINT software_declaration_decisions_purge_shape,
    ALTER COLUMN actor_email SET NOT NULL,
    ALTER COLUMN justification SET NOT NULL,
    DROP COLUMN tenant_purge_anonymized_at;
DROP FUNCTION public.software_declaration_purge_snapshot(jsonb);

-- agent_release_audit: back to 0204's shared guard function.
DROP TRIGGER agent_release_audit_immutable ON public.agent_release_audit;
CREATE TRIGGER agent_release_audit_immutable BEFORE UPDATE OR DELETE
    ON public.agent_release_audit
    FOR EACH ROW EXECUTE FUNCTION public.reject_agent_release_mutation();
DROP FUNCTION public.reject_agent_release_audit_mutation();
DROP TRIGGER agent_release_audit_purge_marker_insert ON public.agent_release_audit;
ALTER TABLE public.agent_release_audit
    DROP CONSTRAINT agent_release_audit_purge_shape,
    ALTER COLUMN actor SET NOT NULL,
    DROP COLUMN tenant_purge_anonymized_at;

-- device_list_entry_deletions (0214)
CREATE OR REPLACE FUNCTION public.reject_device_list_entry_deletions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_list_entry_deletions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER trg_device_list_entry_deletions_purge_marker_insert ON public.device_list_entry_deletions;
ALTER TABLE public.device_list_entry_deletions
    DROP CONSTRAINT device_list_entry_deletions_purge_shape,
    ALTER COLUMN actor_email SET NOT NULL,
    DROP COLUMN tenant_purge_anonymized_at;

-- jamf_webhook_audit (0199)
CREATE OR REPLACE FUNCTION public.reject_jamf_webhook_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'jamf_webhook_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER trg_jamf_webhook_audit_purge_marker_insert ON public.jamf_webhook_audit;
ALTER TABLE public.jamf_webhook_audit
    DROP CONSTRAINT jamf_webhook_audit_purge_shape,
    ALTER COLUMN actor_email SET NOT NULL,
    DROP COLUMN tenant_purge_anonymized_at;

-- device_retirement_decisions (0193)
CREATE OR REPLACE FUNCTION public.reject_device_retirement_decisions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_retirement_decisions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER trg_device_retirement_decisions_purge_marker_insert ON public.device_retirement_decisions;
ALTER TABLE public.device_retirement_decisions
    DROP CONSTRAINT device_retirement_decisions_purge_shape,
    ALTER COLUMN actor_email SET NOT NULL,
    DROP COLUMN tenant_purge_anonymized_at;

-- software_approval_decisions (0182)
CREATE OR REPLACE FUNCTION public.reject_software_approval_decisions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_approval_decisions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER trg_software_approval_decisions_purge_marker_insert ON public.software_approval_decisions;
ALTER TABLE public.software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_purge_shape,
    ALTER COLUMN actor_email SET NOT NULL,
    DROP COLUMN tenant_purge_anonymized_at;

DROP FUNCTION public.reject_tenant_purge_marker_on_insert();

DELETE FROM schema_migrations WHERE version = '0228_audit_ledger_purge_redaction';
COMMIT;
