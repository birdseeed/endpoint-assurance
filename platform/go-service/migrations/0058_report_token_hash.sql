-- 0058: hash report download tokens at rest (PAT-687 security review).
--
-- report_download_tokens.token is a plaintext UUID. Anyone with read access to
-- the table (a DB dump, a backup, an errant SELECT) can redeem any unexpired,
-- unused report-download link. This migration adds a SHA-256 hash column so the
-- application can store only the hash on issue and look up by hash on redeem.
--
-- DUAL-READ WINDOW: the plaintext `token` column is intentionally retained for
-- now. Existing rows have token_hash = NULL; the redeem handler falls back to a
-- plaintext match for those. A follow-up migration (Andy's call) should backfill
-- token_hash for unexpired rows and then drop the plaintext `token` column.
--
-- Forward-only, transaction-wrapped, idempotent.

BEGIN;

ALTER TABLE report_download_tokens
    ADD COLUMN IF NOT EXISTS token_hash BYTEA;   -- SHA-256(token), 32 bytes

-- Lookup index for the hash read path.
CREATE INDEX IF NOT EXISTS idx_rdt_token_hash
    ON report_download_tokens (token_hash);

-- Belt-and-braces: the table-level grant from 0052 already covers new columns,
-- but re-assert it (idempotent) to match the project's grant hygiene (0057).
GRANT SELECT, INSERT, UPDATE, DELETE ON report_download_tokens TO patched;

INSERT INTO schema_migrations (version) VALUES ('0058_report_token_hash')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
