-- Rollback of 0227 (PAT-2405). Roll the API binary back first: the PAT-2405
-- binary selects report_records.csv_path on every portal report list and
-- download.
--
-- Fails closed. Dropping the columns discards the only record of which stored
-- files are issued CSVs and their hashes, and the files stay on disk with
-- nothing pointing at them. Prefer leaving the additive columns in place.
BEGIN;
LOCK TABLE report_records IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM report_records WHERE csv_path IS NOT NULL OR csv_sha256 IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0227: report records with a CSV exist';
    END IF;
END $$;
ALTER TABLE report_records DROP CONSTRAINT IF EXISTS report_records_csv_sha256_hex;
ALTER TABLE report_records DROP COLUMN IF EXISTS csv_sha256, DROP COLUMN IF EXISTS csv_path;
DELETE FROM schema_migrations WHERE version = '0227_report_records_csv';
COMMIT;
