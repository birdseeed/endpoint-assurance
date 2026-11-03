-- PAT-453: record who triggered each enrolment-token mint.
--
-- The admin mint (POST /admin/tenants/{id}/bootstrap-tokens) has no per-user
-- identity — admin auth is a shared token — so it always writes NULL here
-- (unchanged behaviour). The new customer-portal mint (POST
-- /v1/portal/enrolment) has a real verified identity (the CF Access JWT
-- email, via portalauth), so it records that as the actor. Nullable: every
-- existing row and every future admin-path row is NULL by design, not an
-- omission.

BEGIN;

ALTER TABLE enrollment_token_audit ADD COLUMN IF NOT EXISTS actor_email TEXT;

INSERT INTO schema_migrations (version) VALUES ('0077_enrollment_token_audit_actor')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
