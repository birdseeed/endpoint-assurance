-- Reverses 0218_lifecycle_rolling_release.sql (PAT-2171).
--
-- Roll the API binary back first, and 0219 before this file. Refuses while any
-- published mapping uses the rolling rule: dropping the column would put that
-- mapping back on the ordinary rule, and every current browser install would
-- read "Ending within 90 days" again. Roll 0219 back (or withdraw the mapping)
-- first. A proposed mapping's rolling setting is discarded with the column;
-- proposed rows change nothing a customer sees.
BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM lifecycle_mappings WHERE status = 'published' AND rolling_window_days IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0218 while a published lifecycle mapping uses the rolling rule: roll back 0219 or withdraw the mapping first';
    END IF;
END $$;

ALTER TABLE lifecycle_mappings DROP CONSTRAINT IF EXISTS lifecycle_mappings_rolling_window;
ALTER TABLE lifecycle_mappings DROP COLUMN IF EXISTS rolling_window_days;

DELETE FROM schema_migrations WHERE version = '0218_lifecycle_rolling_release';

COMMIT;
