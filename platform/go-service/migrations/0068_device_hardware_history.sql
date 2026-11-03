-- 0068: battery-health trend history (PAT-686).
--
-- device_hardware is a snapshot table (one row per device, upserted on every
-- inventory extraction), so month-over-month battery trend has nothing to
-- read. This table appends the battery fields once per device per day: the
-- extractor upserts on (device_id, recorded_on), so repeated same-day
-- extractions just refresh that day's row and volume stays bounded at one
-- row per device per day.

BEGIN;

CREATE TABLE device_hardware_history (
    device_id                UUID    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recorded_on              DATE    NOT NULL DEFAULT CURRENT_DATE,
    battery_cycle_count      INTEGER,
    battery_condition        TEXT,
    battery_max_capacity_pct INTEGER,
    PRIMARY KEY (device_id, recorded_on)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_hardware_history TO patched;

INSERT INTO schema_migrations (version) VALUES ('0068_device_hardware_history')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
