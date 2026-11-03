-- patched.im — 0098_audit_events_rollback.sql
-- Reverses 0098_audit_events.sql.
--
-- Drops the table outright (unlike 0096's rollback, which only removed
-- triggers/functions and restored comments on PRE-EXISTING tables): this
-- migration created audit_events from nothing, so undoing it undoes the
-- whole table, not just the append-only guard. DROP TABLE cascades to its
-- own indexes and row-level trigger automatically, but the two trigger
-- FUNCTIONS are separate objects with no ownership relationship to the
-- table (same point 0096's rollback makes) — DROP TABLE does not remove
-- them, so they are dropped explicitly here.
--
-- Safe only if no row has been written yet, or the data loss is accepted:
-- this is a hard DROP, not a soft disable. Given audit_events is a fresh
-- table with no downstream readers deployed until PAT-1022's admin endpoint
-- ships, that is the expected case — call out explicitly if this is ever
-- run against a table that has already ingested real events.

BEGIN;

DROP TABLE IF EXISTS audit_events;

DROP FUNCTION IF EXISTS reject_audit_events_mutation();
DROP FUNCTION IF EXISTS reject_audit_events_truncate();

DELETE FROM schema_migrations WHERE version = '0098_audit_events';

COMMIT;
