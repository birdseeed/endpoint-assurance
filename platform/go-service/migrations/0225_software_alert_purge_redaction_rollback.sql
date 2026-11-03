-- Only schema rollback is possible before any irreversible redaction.
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.software_unapproved_alert_transitions WHERE tenant_purge_anonymized_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0225: anonymised software alert audit rows exist';
    END IF;
END;
$$;
DROP TRIGGER trg_tenants_redact_software_alert_before_purge ON public.tenants;
DROP FUNCTION public.redact_software_alert_before_tenant_purge();
DROP TRIGGER trg_software_alert_insert_shape ON public.software_unapproved_alert_transitions;
DROP FUNCTION public.software_alert_insert_shape();
CREATE OR REPLACE FUNCTION public.reject_software_unapproved_alert_transitions_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'software_unapproved_alert_transitions is append-only: % is not permitted', TG_OP;
END;
$$;
ALTER TABLE public.software_unapproved_alert_transitions
    DROP CONSTRAINT software_alert_actor_purge_shape,
    ADD CONSTRAINT software_alert_actor_identity_shape CHECK ((actor_kind = 'portal_user') = (actor IS NOT NULL)),
    DROP COLUMN tenant_purge_anonymized_at;
DELETE FROM schema_migrations WHERE version = '0225_software_alert_purge_redaction';
COMMIT;
