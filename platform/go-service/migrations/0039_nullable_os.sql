-- PAT-548: devices.os is now optional at enrollment time.
-- The flat-format POST /v1/enrol does not carry an OS field;
-- os is populated on the first inventory upload.
ALTER TABLE devices ALTER COLUMN os DROP NOT NULL;
