-- Rollback for 0058_report_token_hash.

BEGIN;

DROP INDEX IF EXISTS idx_rdt_token_hash;

ALTER TABLE report_download_tokens
    DROP COLUMN IF EXISTS token_hash;

DELETE FROM schema_migrations WHERE version = '0058_report_token_hash';

COMMIT;
