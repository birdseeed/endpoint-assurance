-- patched.im — 0100_audit_events_version_blocked.sql
-- PAT-1238: accept the blocked-version kill switch's durable audit event.
--
-- The agents and incident runbook already use event_type='version_blocked',
-- but migration 0098's closed CHECK constraint predates that value. The Go
-- handler accepting it without widening the database would turn a legitimate
-- endpoint report into a 500/SQLSTATE 23514, so the constraint and handler must
-- ship together. This is additive only; existing rows are untouched.
--
-- Apply BEFORE deploying the binary that accepts version_blocked:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0100_audit_events_version_blocked.sql

BEGIN;

ALTER TABLE audit_events DROP CONSTRAINT audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check
    CHECK (event_type IN (
        'verification_passed',
        'verification_failed',
        'install_completed',
        'install_failed',
        'posture_warning',
        'allowlist_tamper_detected',
        'version_blocked'
    ));

INSERT INTO schema_migrations (version) VALUES ('0100_audit_events_version_blocked')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
