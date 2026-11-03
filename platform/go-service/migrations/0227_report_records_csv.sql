-- patched.im - 0227_report_records_csv.sql
-- PAT-2405: every customer catalogue report is also stored as a CSV.
--
-- Additive. Two nullable columns on report_records, no default, no rewrite:
--
--   csv_path    relative path of report.csv, beside the PDF in the same
--               <tenant>/<record>/ directory. NULL for every report generated
--               before this change and for any admin-source record: the portal
--               download answers 404 csv_not_available for those and the PDF
--               still downloads.
--   csv_sha256  lower-case hex SHA-256 of the CSV bytes, the same primitive as
--               pdf_sha256 / xlsx_sha256 (0126), so an auditor can prove a
--               downloaded CSV is the one that was issued.
--
-- Both are written by the single finalising UPDATE that sets issued_at
-- (handlers.storeReportRecord). Migration 0126's trigger compares the whole row
-- once issued_at is set, so a column added here is frozen at issuance with no
-- change to the trigger, and nothing may write them afterwards.
--
-- The 0126 hex CHECK is repeated for the new hash: a malformed digest reads as
-- verifiable evidence and is not. A CHECK on an all-NULL new column is
-- satisfied trivially; ADD COLUMN takes ACCESS EXCLUSIVE on report_records for
-- milliseconds.
--
-- report_records was created by 0052 (at or below the 0055 grandfather line),
-- so production's shape can differ from what the migrations say. Check it
-- read-only before deploy: \d report_records, and that it has no csv_path or
-- csv_sha256 already.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0227_report_records_csv.sql
--
-- DEPLOY ORDERING: apply this BEFORE the binary. The new binary selects
-- csv_path on every portal report list and download.

BEGIN;

ALTER TABLE report_records
    ADD COLUMN IF NOT EXISTS csv_path TEXT,
    ADD COLUMN IF NOT EXISTS csv_sha256 TEXT;

ALTER TABLE report_records
    DROP CONSTRAINT IF EXISTS report_records_csv_sha256_hex;
ALTER TABLE report_records
    ADD CONSTRAINT report_records_csv_sha256_hex
    CHECK (csv_sha256 IS NULL OR csv_sha256 ~ '^[0-9a-f]{64}$');

INSERT INTO schema_migrations (version) VALUES ('0227_report_records_csv')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
