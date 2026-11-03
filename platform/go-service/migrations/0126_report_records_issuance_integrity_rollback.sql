-- Roll back PAT-1613's report_records issuance integrity columns and guards.
--
-- Order matters: the immutability trigger must go before the columns, because
-- dropping issued_at out from under the function would leave a trigger that
-- errors on every UPDATE to the table.
--
-- Dropping issued_at discards the record of which reports were issued, and
-- dropping the hash columns discards the only proof the stored files were not
-- altered. That evidence is not recoverable by re-running anything: a
-- regenerated report is a new document, not the issued one. Roll back only to
-- unblock a broken deploy, and expect to re-issue rather than restore.
BEGIN;

DROP TRIGGER IF EXISTS trg_report_records_reject_issued_update ON report_records;
DROP TRIGGER IF EXISTS trg_report_records_reject_truncate ON report_records;
DROP FUNCTION IF EXISTS reject_issued_report_record_update();
DROP FUNCTION IF EXISTS reject_report_record_truncate();

DROP INDEX IF EXISTS report_records_supersedes_uq;
DROP INDEX IF EXISTS idx_report_records_issued_at;

ALTER TABLE report_records
    DROP CONSTRAINT IF EXISTS report_records_pdf_sha256_hex,
    DROP CONSTRAINT IF EXISTS report_records_xlsx_sha256_hex,
    DROP CONSTRAINT IF EXISTS report_records_no_self_supersession;

ALTER TABLE report_records
    DROP COLUMN IF EXISTS pdf_sha256,
    DROP COLUMN IF EXISTS xlsx_sha256,
    DROP COLUMN IF EXISTS issued_at,
    DROP COLUMN IF EXISTS coverage_snapshot,
    DROP COLUMN IF EXISTS supersedes_report_id,
    DROP COLUMN IF EXISTS superseded_by_report_id;

DELETE FROM schema_migrations
WHERE version = '0126_report_records_issuance_integrity';

COMMIT;
