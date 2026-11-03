-- 0057: catch-up GRANTs for the `patched` application role.
-- M-INFRA-3 (recurring prod incidents PAT-579 / PAT-603).
--
-- Several table/sequence-creating migrations shipped WITHOUT a
-- `GRANT ... TO patched` (e.g. 0001, 0005, 0016, 0017, 0018, 0022, 0023, 0025,
-- 0030, 0031, 0032, 0033, 0036_bootstrap_tokens, 0037_tenant_ca, 0038,
-- 0040_device_revocations, 0040_enrollment_audit_log, 0053, 0054, 0055). The
-- `patched` role then hit "permission denied" 500s in production. Twice.
--
-- Rather than rewrite already-applied migration history, this forward-only,
-- idempotent migration re-grants the full app-role privilege set across the
-- public schema, and sets default privileges so tables/sequences created by
-- future migrations (applied by the same role) are covered automatically.
--
-- Safe to re-run: GRANT is idempotent.

BEGIN;

GRANT USAGE ON SCHEMA public TO patched;

-- App role needs full CRUD on the data tables and to advance BIGSERIAL/serial
-- sequences (nextval -> USAGE; currval -> SELECT), matching the per-table
-- pattern used by the migrations that did include grants.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO patched;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO patched;

-- Belt and braces against the recurring incident: auto-grant on objects created
-- in future by the current (migration-running) role. This only affects objects
-- created after this runs, so existing objects are handled by the grants above.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO patched;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO patched;

INSERT INTO schema_migrations (version) VALUES ('0057_grant_all_to_patched')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
