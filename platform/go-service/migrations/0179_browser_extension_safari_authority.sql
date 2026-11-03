-- 0179: Safari extension absence authority (PAT-2067)
--
-- PAT-2064 stores macOS Safari app-extension rows in
-- device_browser_extensions (browser = 'safari'). browser_extensions_status
-- (0177) only speaks for chrome, edge and firefox, so no report could prove a
-- Safari extension gone and a removed one stayed present forever.
--
-- The payload's collection_status.safari_extensions now says whether the
-- agent walked every Safari app-extension location. Two nullable columns on
-- the existing per-device state table record it:
--
--   safari_reported_at  the payload received_at of the newest report that
--                       carried a safari_extensions value. Forward-only, so
--                       an older replay never stamps authority over a newer
--                       report.
--   safari_complete_at  the device_browser_extensions.last_seen stamp of the
--                       newest report that said "complete" (schema v3,
--                       uncapped, consistent). Never set by "partial" or
--                       "unavailable"; each trusted complete sets its own
--                       stamp. A Safari row counts
--                       as gone only when this is strictly after its
--                       last_seen (internal/extpresence).
--
-- Both NULL for every existing row: no Safari authority until an agent sends
-- the signal, which is exactly today's behaviour. Chrome, Edge and Firefox
-- authority (last_complete_at and the per-pair table) is untouched.
--
-- Additive only: ADD COLUMN with no default is a catalogue-only change. The
-- table already has its GRANTs (0177). Safe to apply before the binary.
--
-- Applied by deploy/api-01/deploy.sh (as the patched role, which owns the
-- table from 0177) before the binaries are swapped.
--
-- Rollback: migrations/0179_browser_extension_safari_authority_rollback.sql

BEGIN;

ALTER TABLE browser_extension_device_state
    ADD COLUMN safari_reported_at TIMESTAMPTZ,
    ADD COLUMN safari_complete_at TIMESTAMPTZ;

INSERT INTO schema_migrations (version) VALUES ('0179_browser_extension_safari_authority')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
