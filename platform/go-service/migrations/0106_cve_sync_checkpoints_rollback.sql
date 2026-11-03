-- patched.im — 0106_cve_sync_checkpoints_rollback.sql
-- Reverses 0106_cve_sync_checkpoints.sql (PAT-1375).
--
-- Safe to drop unconditionally: the table only ever holds in-flight resume
-- state for patched-cve-sync, never data anything else reads. Losing it
-- just means the next sync (if one is mid-run) restarts its page walk from
-- 0 instead of resuming — code degrades to this same behaviour on its own
-- if the table is simply absent (see loadNVDCheckpoint's 42P01 handling).

BEGIN;

DROP TABLE IF EXISTS cve_sync_checkpoints;

DELETE FROM schema_migrations WHERE version = '0106_cve_sync_checkpoints';

COMMIT;
