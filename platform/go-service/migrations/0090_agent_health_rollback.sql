-- patched.im — 0090_agent_health_rollback.sql
-- Reverses 0090_agent_health.sql: drops device_agent_health and
-- device_agent_health_watermark.
-- Data loss on rollback is expected and accepted (same as every other DROP
-- rollback in this directory) — raw_payloads.body is the immutable archive
-- and device_agent_health is entirely derived from it. Re-applying the
-- forward migration and re-running extraction rebuilds every
-- degraded-capability row from the archived payloads.
-- device_agent_health_watermark has no archived source (it is not derived
-- from any payload field the agent sends; it is the server's own bookkeeping
-- of "how recent is the data we've accepted for this device"), so it simply
-- restarts empty on the next forward-migration apply — the first
-- agent_health payload for each device after that will seed its watermark
-- row fresh, exactly as it would for a device seen for the very first time.
BEGIN;

DROP TABLE IF EXISTS device_agent_health_watermark;
DROP TABLE IF EXISTS device_agent_health;

DELETE FROM schema_migrations WHERE version = '0090_agent_health';

COMMIT;
