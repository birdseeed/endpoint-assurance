-- patched.im — 0128_devices_collection_status.sql
-- PAT-1732: makes a degraded top-level collection visible on the platform,
-- instead of the PAT-1720 precedent (hardware_health.collection_status),
-- which changed extractor behaviour but stored nothing queryable.
--
--   * devices.collection_status JSONB — latest per-section collection status
--     the agent reported, merged in place per ingest (a payload reporting
--     only some sections leaves the other stored keys untouched — see
--     internal/extractor/upsert.go upsertCollectionStatus, called from
--     extractor.go processRow alongside, but separately from, upsertDevice).
--     Nullable, no default, no backfill: NULL means the agent has never
--     reported any collection_status section at all, which is exactly the
--     old-agent case and must not be confused with an empty object (which
--     would falsely say every section was reported and complete).
--
-- Purely additive: ADD COLUMN with no default on an existing table takes a
-- brief ACCESS EXCLUSIVE lock to update the catalog only (no table rewrite,
-- no default backfill), and every existing row gets NULL. Safe to apply
-- before the new binary is deployed — the old binary neither reads nor
-- writes this column, so it is inert until the extractor that knows about it
-- ships.
--
-- No column-level GRANT needed — devices already has table-level GRANTs
-- from 0056_grant_all_to_patched.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0128_devices_collection_status.sql
--
-- Rollback: migrations/0128_devices_collection_status_rollback.sql

BEGIN;

ALTER TABLE devices
    ADD COLUMN collection_status JSONB;

COMMENT ON COLUMN devices.collection_status IS
    'Latest per-section collection status the agent reported (PAT-1732), merged in place per ingest. NULL means the agent has never reported any collection_status section at all. A key absent from the object means that section was not reported (this ingest, or ever) — the platform must not read an absent key as "complete"; only a present key with value "complete" means that. Normalised values only: an unrecognised wire value is stored as "unavailable", never as "complete" (see normaliseCollectionStatus). Shape: {"certificates": "complete"|"partial"|"unavailable", "hardware_health": {"battery": ..., "storage": ..., "disks": ...}}. Both top-level keys are independently optional and this shape grows as more sections gain a collection_status.';

INSERT INTO schema_migrations (version) VALUES ('0128_devices_collection_status')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
