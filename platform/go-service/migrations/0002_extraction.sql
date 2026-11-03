-- patched.im — 0002_extraction.sql
-- Schema changes that let the extraction worker turn raw_payloads rows into
-- typed rows in devices / device_apps / compliance_signals.
--
-- Adds:
--   * raw_payloads.extracted_at / extraction_attempts / extraction_error
--     Bookkeeping so the worker can claim, retry, and skip rows safely.
--   * devices.hardware           JSONB — schema_v2 hardware sub-object (cpu, ram, disk).
--   * devices.security_inventory JSONB — schema_v2 security_tools / system_extensions /
--     background_items / icloud bundled as one snapshot per device.
--   * Partial index on raw_payloads(received_at) WHERE extracted_at IS NULL —
--     keeps the worker's polling query O(unprocessed) rather than O(all).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0002_extraction.sql

BEGIN;

-- ============================================================================
-- RAW_PAYLOADS — extraction bookkeeping
-- ============================================================================

-- ADD COLUMN on a partitioned parent propagates to existing + future partitions
-- in PG14+. We're on PG16. No need to ALTER each partition individually.
ALTER TABLE raw_payloads
    ADD COLUMN extracted_at         TIMESTAMPTZ,
    ADD COLUMN extraction_attempts  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN extraction_error     TEXT;

COMMENT ON COLUMN raw_payloads.extracted_at IS
    'Set by the extraction worker on success. NULL = unprocessed.';
COMMENT ON COLUMN raw_payloads.extraction_attempts IS
    'Incremented on every claim. Worker stops retrying after a configurable cap.';
COMMENT ON COLUMN raw_payloads.extraction_error IS
    'Last error message from extraction. Cleared on success.';

-- Worker poll path: WHERE extracted_at IS NULL ORDER BY received_at.
-- Partial index keeps this scan tight as the unprocessed backlog stays small
-- while the historical archive grows.
CREATE INDEX idx_raw_payloads_pending
    ON raw_payloads (received_at)
    WHERE extracted_at IS NULL;

-- ============================================================================
-- DEVICES — snapshot columns for v2 payload sections that don't yet have
-- typed homes. Each ingestion replaces the prior snapshot for that device.
-- ============================================================================

ALTER TABLE devices
    ADD COLUMN hardware           JSONB,
    ADD COLUMN security_inventory JSONB,
    ADD COLUMN agent_version      TEXT,
    ADD COLUMN schema_version     INTEGER;

COMMENT ON COLUMN devices.hardware IS
    'Latest schema_v2 hardware sub-object: cpu_model, cpu_cores, ram_gb, disk_total_gb, disk_free_gb.';
COMMENT ON COLUMN devices.security_inventory IS
    'Latest snapshot: {security_tools:[], system_extensions:[], background_items:[], icloud:{signed_in}}. v2-shape now; normalise into typed tables if query patterns demand it.';
COMMENT ON COLUMN devices.agent_version IS
    'Reported by the collector. Lets the extractor diverge behaviour across collector versions if needed.';
COMMENT ON COLUMN devices.schema_version IS
    'Payload schema_version from the most recent ingest. Worker rejects unknown versions.';

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0002_extraction');

COMMIT;
