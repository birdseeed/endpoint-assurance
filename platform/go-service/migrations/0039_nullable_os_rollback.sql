-- Rollback: restore NOT NULL constraint on devices.os.
-- NOTE: this will fail if any rows have os IS NULL; clean those first.
ALTER TABLE devices ALTER COLUMN os SET NOT NULL;
