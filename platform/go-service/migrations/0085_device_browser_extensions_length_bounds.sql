-- patched.im — 0085_device_browser_extensions_length_bounds.sql
-- PAT-933 gate round 7: bound LEGACY device_browser_extensions rows, not just
-- new ones. Also bounds user_account/profile (added on correctness review
-- after the initial round-7 fix — see the note before step 1b below).
--
-- The round-6 commit ("fix(PAT-933): bound extension field lengths at
-- ingestion", this branch) fixed round 6 by truncating
-- browser/extension_id/name/version to 32/128/256/64 characters at ingestion
-- time, in upsertBrowserExtensions (internal/extractor/upsert.go), before any
-- future write. Round 7 correctly pointed out that fix is write-path-only:
-- device_browser_extensions is a live table that has been collecting browser
-- extension telemetry since migration 0018, so any row written before that
-- fix shipped could still hold unbounded-length text in these columns. The
-- GROUP BY (ident CTE) and ORDER BY (LOWER(i.name), ...) in
-- internal/report/portal_extensions.go's FetchPortalExtensions operate on
-- the raw stored columns, ahead of the output-side LEFT() truncation — so
-- pre-existing oversized rows would still force Postgres to group/sort on
-- arbitrarily large text values, undoing the round-6 fix for every row that
-- predates it.
--
-- This migration closes that gap two ways:
--
--   1. Backfill: truncate any EXISTING row whose browser/extension_id/name/
--      version exceeds the same caps upsert.go now enforces going forward
--      (extMaxBrowserLen=32 / extMaxIDLen=128 / extMaxNameLen=256 /
--      extMaxVersionLen=64 — internal/extractor/upsert.go). The WHERE clause
--      only touches rows that actually need it, so this is not a full-table
--      rewrite.
--
--   2. Defense-in-depth: CHECK constraints enforcing the same bounds at the
--      DB level, so any future write path that bypasses upsertBrowserExtensions
--      (a script, a different ingestion path, a bug) cannot silently
--      reintroduce unbounded text into this table. Added AFTER the backfill,
--      since a CHECK constraint must hold against existing data at ADD time.
--
-- Collision risk on the backfill (worse than the ingestion-time truncation
-- round 6 added): extension_id AND browser are both part of the table's
-- UNIQUE(device_id, browser, user_account, profile, extension_id) index
-- (device_browser_extensions_unique, migration 0018), and this backfill
-- truncates both columns. If two EXISTING rows for the same (device_id,
-- user_account, profile) already have distinct extension_id values sharing
-- an identical first-128-character prefix, truncating both to
-- LEFT(extension_id, 128) would make them identical; the same is true,
-- independently, if two rows instead share an identical first-32-character
-- browser prefix (e.g. two junk/abusive `browser` values, since the real
-- value space is just 'chrome' | 'edge' | 'firefox'). Either collision
-- would fail the UPDATE with a unique-violation on
-- device_browser_extensions_unique.
--
-- Note on user_account/profile (added on correctness review, same day):
-- these are the OTHER two columns in the composite unique index
-- (device_browser_extensions_unique: device_id, browser, user_account,
-- profile, extension_id) and are NOT NULL exactly like browser/
-- extension_id, but the original round-7 fix above only backfilled/
-- constrained browser/extension_id/name/version, leaving these two legacy
-- rows still unbounded. Bounded here too, same 128-char cap as
-- internal/extractor/upsert.go's extMaxUserAccountLen/extMaxProfileLen (no
-- read-side display counterpart for these two — see that file's comment).
-- Same collision-risk profile as extension_id/browser above: real macOS
-- login names and browser profile directory names are realistically far
-- under 128 characters, so a genuine two-distinct-values collision after
-- truncation is practically impossible; if this UPDATE fails on a
-- unique-violation, use the same diagnose-then-decide procedure described
-- above, substituting user_account/profile for extension_id/browser in the
-- diagnostic SELECTs.
--
-- Deliberately NOT guarded with a pre-check DO block (contrast migration
-- 0080, which RAISEs before adding a new UNIQUE index): this UPDATE runs as
-- a single statement inside this migration's transaction, so if it does hit
-- a collision, Postgres itself aborts the statement (and the whole
-- migration, since nothing has committed) and reports the exact conflicting
-- key via the constraint-violation error — that is already a clear,
-- actionable signal, and per this repo's own migration convention
-- (AGENTS.md: "Migrations are SQL applied with psql. No migration tool at
-- MVP.") these are applied manually and watched, not run unattended. A real
-- collision here is judged exceptionally unlikely for the same reason
-- upsert.go's round-6 comment gives: real extension IDs are short,
-- fixed-format strings (Chrome/Edge: exactly 32 lowercase a-p characters;
-- Firefox: a UUID or an `id@domain` string, typically well under 100 chars)
-- and real browser values are one of three short literals — nothing in a
-- legitimate browser's extension ecosystem produces two distinct IDs (or
-- two distinct browser strings) sharing an identical cap-length prefix. If
-- this UPDATE ever does fail: do NOT retry it as-is. Run BOTH of the
-- following (the error message names which constraint/column triggered it,
-- but check both if that's ambiguous):
--   SELECT device_id, browser, user_account, profile, extension_id, length(extension_id)
--   FROM device_browser_extensions WHERE length(extension_id) > 128
--   ORDER BY device_id, browser, user_account, profile, LEFT(extension_id, 128);
--
--   SELECT device_id, browser, user_account, profile, extension_id, length(browser)
--   FROM device_browser_extensions WHERE length(browser) > 32
--   ORDER BY device_id, user_account, profile, extension_id, LEFT(browser, 32);
-- to find the colliding pair, inspect both rows (they are almost certainly
-- junk/abusive data, not two genuine extensions), and manually decide
-- disposition (e.g. delete the stale/abusive one) before re-running this
-- migration.
--
-- Lock note on step 2 below: ADD CONSTRAINT ... CHECK (without NOT VALID)
-- takes ACCESS EXCLUSIVE on device_browser_extensions for the duration of
-- validating the new constraints against every existing row — and per this
-- file's own round-4/6 reasoning (see internal/report/portal_extensions.go's
-- doc comment, part (b)), this table's row count has no structural upper
-- bound and grows for a tenant's entire lifetime. At this project's current
-- (pre-launch) scale that scan is expected to be fast, but if this migration
-- is applied later against a materially larger table, consider splitting
-- step 2 into `ADD CONSTRAINT ... CHECK (...) NOT VALID` (near-instant,
-- doesn't scan) followed by a separate `VALIDATE CONSTRAINT` statement run
-- in its OWN transaction during low traffic (VALIDATE CONSTRAINT only needs
-- SHARE UPDATE EXCLUSIVE, which doesn't block concurrent reads/writes) —
-- note this split only helps if the two statements are in separate
-- transactions; doing both within this same migration's single BEGIN/COMMIT
-- would still hold ACCESS EXCLUSIVE for the whole thing and provide no
-- benefit. Not done here by default to keep this a single, simple,
-- atomically-applied migration matching this repo's existing convention
-- (see 0080/0082) while the table is still small; operator judgement call
-- if the table has grown by the time this is actually applied.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0085_device_browser_extensions_length_bounds.sql
BEGIN;

-- DEPLOY ORDERING: apply after the upsert.go truncation ("fix(PAT-933): bound
-- extension field lengths at ingestion") has shipped, so no new oversized
-- rows are written between backfill and the
-- CHECK constraints below. Safe to apply on its own regardless — the
-- backfill only touches rows already violating the caps, and the CHECK
-- constraints simply codify the bound both the Go code and this backfill
-- already enforce.

-- 1. Backfill legacy rows. Same caps as upsert.go's
--    extMaxBrowserLen/extMaxIDLen/extMaxNameLen/extMaxVersionLen (32/128/256/64)
--    and extMaxUserAccountLen/extMaxProfileLen (128/128). version is
--    nullable (0018); NULL versions are left alone by the length(version) >
--    64 guard short-circuiting on NULL. user_account/profile are NOT NULL
--    (0018), same as browser/extension_id/name.
UPDATE device_browser_extensions
SET extension_id = LEFT(extension_id, 128),
    browser      = LEFT(browser, 32),
    name         = LEFT(name, 256),
    version      = LEFT(version, 64),
    user_account = LEFT(user_account, 128),
    profile      = LEFT(profile, 128)
WHERE length(extension_id) > 128
   OR length(browser) > 32
   OR length(name) > 256
   OR (version IS NOT NULL AND length(version) > 64)
   OR length(user_account) > 128
   OR length(profile) > 128;

-- 2. Defense-in-depth: enforce the same bounds at the DB level going
--    forward, for every write path, not just upsertBrowserExtensions.
--    browser/extension_id/name/user_account/profile are NOT NULL (0018);
--    version is nullable, so its check allows NULL explicitly.
ALTER TABLE device_browser_extensions
    ADD CONSTRAINT device_browser_extensions_extension_id_len CHECK (length(extension_id) <= 128),
    ADD CONSTRAINT device_browser_extensions_browser_len CHECK (length(browser) <= 32),
    ADD CONSTRAINT device_browser_extensions_name_len CHECK (length(name) <= 256),
    ADD CONSTRAINT device_browser_extensions_version_len CHECK (version IS NULL OR length(version) <= 64),
    ADD CONSTRAINT device_browser_extensions_user_account_len CHECK (length(user_account) <= 128),
    ADD CONSTRAINT device_browser_extensions_profile_len CHECK (length(profile) <= 128);

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0085_device_browser_extensions_length_bounds')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
