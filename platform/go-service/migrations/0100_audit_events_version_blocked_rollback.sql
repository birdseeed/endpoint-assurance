-- patched.im — 0100_audit_events_version_blocked_rollback.sql
-- Reverses 0100_audit_events_version_blocked.sql.
--
-- This deliberately does not delete or rewrite version_blocked rows. If any
-- have been ingested, restoring the narrower constraint fails safely until an
-- operator makes an explicit retention decision; rollback must never destroy
-- append-only audit evidence as a side effect.

BEGIN;

ALTER TABLE audit_events DROP CONSTRAINT audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check
    CHECK (event_type IN (
        'verification_passed',
        'verification_failed',
        'install_completed',
        'install_failed',
        'posture_warning',
        'allowlist_tamper_detected'
    ));

DELETE FROM schema_migrations WHERE version = '0100_audit_events_version_blocked';

COMMIT;
