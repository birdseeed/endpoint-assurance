-- patched.im — 0147_device_os_update_checked_at.sql
-- PAT-1862: adds the checked_at column device_os_update (0144) was missing.
-- 0144's shape was guessed from the ticket description without the real
-- `updater` repo checked out; the real contract
-- (updater/contracts/update-status.schema.json) requires checked_at on every
-- os_update block the agent sends.
--
-- checked_at is the AGENT's own local computation time of this verdict (the
-- SOFA feed check on macOS / WUA COM check on Windows) — distinct from the
-- existing reported_at column, which is the PLATFORM's own timestamp of the
-- last ingest that carried this block. The two can differ significantly
-- when an agent uploads a cached verdict computed some time earlier (e.g. a
-- retry from a stale queued payload, or a check that ran hours before the
-- agent got a chance to phone home).
--
-- Nullable, no default, no backfill: existing rows predate this column and
-- have no agent-reported check time to reconstruct (this is new data going
-- forward, not a historical fact this migration can derive). Live ingestion
-- requires checked_at to be valid RFC3339. See upsertOSUpdate
-- (internal/extractor/upsert.go): extraction remains defensive for legacy or
-- replay payloads that bypassed the current validation, logging an
-- unparseable checked_at and storing NULL rather than failing the whole
-- os_update section, same posture as the existing deadline column.
--
-- Also relaxes device_os_update.latest_os from NOT NULL to nullable, a
-- second real gap found in the same contract-drift investigation: the real
-- contract (updater/contracts/update-status.schema.json) makes latest_os
-- optional and nullable — an agent sends it as null when its feed (SOFA on
-- macOS, WUA COM on Windows) was unreachable at check time. Under the old
-- NOT NULL constraint, upsertOSUpdate would fail the whole os_update
-- section's write with a real Postgres constraint violation the very first
-- time an agent reports a genuine SOFA/WUA outage — confirmed by writing a
-- DB-level test against this exact scenario, which failed with
-- "null value in column latest_os ... violates not-null constraint" before
-- this migration.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0147_device_os_update_checked_at.sql

BEGIN;

ALTER TABLE device_os_update ADD COLUMN checked_at TIMESTAMPTZ;
ALTER TABLE device_os_update ALTER COLUMN latest_os DROP NOT NULL;

COMMENT ON COLUMN device_os_update.checked_at IS
    'Agent-supplied timestamp of the agent''s own local computation of this verdict (SOFA feed check on macOS, WUA COM check on Windows; PAT-1862) — distinct from reported_at, which is the platform''s own ingest timestamp. Nullable for rows written before this column existed. Live ingestion requires RFC3339; the extractor stores NULL only when defensively replaying legacy payloads that bypassed current validation.';
COMMENT ON COLUMN device_os_update.latest_os IS
    'Latest release the agent''s feed reported (SOFA / WUA), verbatim. Nullable (PAT-1862): the real agent contract sends null when the feed was unreachable at check time — a real, expected condition, not a data-quality failure.';

INSERT INTO schema_migrations (version) VALUES ('0147_device_os_update_checked_at');

COMMIT;
