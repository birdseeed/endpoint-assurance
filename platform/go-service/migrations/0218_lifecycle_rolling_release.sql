-- 0218: a per-mapping rolling-release rule for the software lifecycle report
-- (PAT-2171, follows PAT-2147 / migration 0196).
--
-- endoflife.date dates every Chrome and Firefox major as ending when the next
-- major ships, two to four weeks out, so under the ordinary rule every current
-- browser install reads "Ending within 90 days". The 0196 seed therefore kept
-- the browser mappings proposed, out of customer output.
--
-- lifecycle_mappings.rolling_window_days opts a mapping into the rolling rule
-- (internal/lifecycle: RollingCycleState). NULL, the value of every existing
-- row, is the ordinary end of support rule, byte for byte:
--   * the latest released major reads Supported;
--   * the previous major reads Supported while the latest is under
--     rolling_window_days old, Unsupported from that many days on;
--   * every older major reads Unsupported;
--   * cycles the source flags is_lts (Firefox ESR) keep their own dates and the
--     ordinary rule.
-- 21 days is the default (lifecycle.DefaultRollingWindowDays): vendors stage a
-- new major over about two weeks and auto-update lands within about three.
--
-- The CHECK keeps the window between 1 and 90 days and off the operating
-- system mappings, whose version rules select a cycle by build or major and
-- have no notion of a latest release.
--
-- This migration only turns the rule on for the seeded Chrome and Firefox
-- rows, and only while they are still proposed. A proposed row changes nothing
-- a customer sees, so no audit row is written; publishing is 0219, which
-- audits it. A row staff already published or rejected is left alone.
--
-- Additive: one nullable column, one constraint, one UPDATE on unpublished
-- seed rows. The API binary that reads the column ships in the same deploy; an
-- older binary ignores it.
BEGIN;

ALTER TABLE lifecycle_mappings
    ADD COLUMN IF NOT EXISTS rolling_window_days INT; -- NULL = ordinary end of support rule

ALTER TABLE lifecycle_mappings
    DROP CONSTRAINT IF EXISTS lifecycle_mappings_rolling_window;
ALTER TABLE lifecycle_mappings
    ADD CONSTRAINT lifecycle_mappings_rolling_window
        CHECK (rolling_window_days IS NULL
               OR (rolling_window_days BETWEEN 1 AND 90 AND identity_kind <> 'os'));

COMMENT ON COLUMN lifecycle_mappings.rolling_window_days IS
    'PAT-2171: NULL is the ordinary end of support rule. A value opts the mapping into the rolling-release rule: latest major Supported, previous major Supported while the latest is under this many days old, older majors Unsupported, is_lts cycles (Firefox ESR) on their own dates. 1 to 90; application mappings only.';

UPDATE lifecycle_mappings
   SET rolling_window_days = 21, updated_at = now()
 WHERE proposed_by = 'migration:0196'
   AND status = 'proposed'
   AND identity_kind <> 'os'
   AND eol_slug IN ('chrome', 'firefox')
   AND rolling_window_days IS NULL;

INSERT INTO schema_migrations (version) VALUES ('0218_lifecycle_rolling_release')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
