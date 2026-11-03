-- PAT-2328: preserve per-app metering provenance independently of historical usage.
-- Existing rows remain NULL/not reported; no backfill can invent agent evidence.
BEGIN;
ALTER TABLE device_apps ADD COLUMN IF NOT EXISTS usage_evidence TEXT
    CHECK (usage_evidence IN ('recorded', 'no_record', 'unmapped', 'unavailable'));
ALTER TABLE device_apps ADD COLUMN IF NOT EXISTS usage_evidence_at TIMESTAMPTZ;
ALTER TABLE device_apps ADD COLUMN IF NOT EXISTS usage_evidence_complete BOOLEAN;
COMMENT ON COLUMN device_apps.usage_evidence IS 'Per-app usage state; NULL = not reported, conflicting shared scopes = unavailable. no_record never proves non-use.';
COMMENT ON COLUMN device_apps.usage_evidence_at IS 'Inventory receipt time of this app observation, including not-reported observations; never refreshed by an unrelated device report.';
COMMENT ON COLUMN device_apps.usage_evidence_complete IS 'Derived non-use authority: complete app scope and a timestamp in this observation; false cannot support non-use.';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS metering_user_hive_count INTEGER CHECK (metering_user_hive_count >= 0);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS metering_record_count INTEGER CHECK (metering_record_count >= 0);
INSERT INTO schema_migrations(version) VALUES ('0221_app_usage_evidence') ON CONFLICT DO NOTHING;
COMMIT;
