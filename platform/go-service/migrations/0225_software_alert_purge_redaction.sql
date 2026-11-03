-- PAT-2380: retain event evidence, redact portal actor and free text on purge.
BEGIN;
ALTER TABLE public.software_unapproved_alert_transitions
    ADD COLUMN tenant_purge_anonymized_at TIMESTAMPTZ;
-- Locate only 0184's actor identity shape, leaving its enum/format checks intact.
DO $$
DECLARE shape_name name;
BEGIN
    SELECT conname INTO STRICT shape_name FROM pg_constraint
     WHERE conrelid = 'public.software_unapproved_alert_transitions'::regclass
       AND pg_get_constraintdef(oid) = 'CHECK (((actor_kind = ''portal_user''::text) = (actor IS NOT NULL)))';
    EXECUTE format('ALTER TABLE public.software_unapproved_alert_transitions DROP CONSTRAINT %I', shape_name);
END;
$$;
ALTER TABLE public.software_unapproved_alert_transitions
    ADD CONSTRAINT software_alert_actor_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND ((actor_kind = 'portal_user') = (actor IS NOT NULL)))
        OR (tenant_purge_anonymized_at IS NOT NULL AND actor IS NULL AND note IS NULL));

CREATE FUNCTION public.software_alert_insert_shape() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.tenant_purge_anonymized_at IS NOT NULL THEN
        RAISE EXCEPTION 'software alert purge marker is not permitted on INSERT';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_software_alert_insert_shape BEFORE INSERT
    ON public.software_unapproved_alert_transitions
    FOR EACH ROW EXECUTE FUNCTION public.software_alert_insert_shape();

CREATE OR REPLACE FUNCTION public.reject_software_unapproved_alert_transitions_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.software_alert_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor IS NULL AND NEW.note IS NULL
       AND (to_jsonb(NEW) - 'actor' - 'note' - 'tenant_purge_anonymized_at')
           IS NOT DISTINCT FROM (to_jsonb(OLD) - 'actor' - 'note' - 'tenant_purge_anonymized_at') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'software_unapproved_alert_transitions is append-only: % is not permitted', TG_OP;
END;
$$;
-- A separate tenant trigger preserves every older 0109 purge path. Definer
-- privileges allow the INSERT-only worker to purge without granting audit UPDATE.
CREATE FUNCTION public.redact_software_alert_before_tenant_purge() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE previous_scope text := current_setting('patched.software_alert_purge_tenant', true);
BEGIN
    IF TG_OP <> 'DELETE' OR TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'tenants'
       OR pg_trigger_depth() <> 1 THEN
        RAISE EXCEPTION 'software alert redaction requires the tenant DELETE trigger';
    END IF;
    PERFORM set_config('patched.software_alert_purge_tenant', OLD.id::text, true);
    UPDATE public.software_unapproved_alert_transitions
       SET actor = NULL, note = NULL, tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;
    PERFORM set_config('patched.software_alert_purge_tenant', coalesce(previous_scope, ''), true);
    RETURN OLD;
END;
$$;
REVOKE ALL ON FUNCTION public.redact_software_alert_before_tenant_purge() FROM PUBLIC;
CREATE TRIGGER trg_tenants_redact_software_alert_before_purge BEFORE DELETE ON public.tenants
    FOR EACH ROW EXECUTE FUNCTION public.redact_software_alert_before_tenant_purge();
COMMENT ON COLUMN public.software_unapproved_alert_transitions.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker; actor/note redacted, all other event fields retained. No automatic retention sweep.';
INSERT INTO schema_migrations (version) VALUES ('0225_software_alert_purge_redaction');
COMMIT;
