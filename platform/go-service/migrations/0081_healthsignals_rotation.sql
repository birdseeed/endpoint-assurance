-- patched.im - 0081_healthsignals_rotation.sql
-- PAT-872: fix the health-signals 30-day rotation so it can actually fire
-- more than once, and give the dashboard-login counter a real window.
--
-- Root cause (see internal/healthsignals/recompute.go, recomputeOne):
--
--   1. The 30-day rotation gate compared time.Since(tenants.updated_at), but
--      the same function stamps updated_at = now() on EVERY nightly run for
--      EVERY tenant (rotated or not). So after the first run, updated_at is
--      always < 24h old and the >= 30 day gate can never be true again.
--      compliance_score_30d_ago freezes forever after run 1.
--
--   2. dashboard_logins_last_30d (0063) is documented as a rolling 30-day
--      window reset once per cycle by the recompute routine, but nothing
--      ever reset it: handlers/health_signals.go only increments it. Once
--      non-zero, the "no logins in 30 days" disengagement penalty could
--      never re-trigger.
--
-- Fix: a DEDICATED health_signals_last_rotated_at column, decoupled from the
-- general-purpose updated_at column that this same function also writes on
-- every run. Only the runs where rotation actually fires may stamp this
-- column with now(); recompute.go gates the 30-day check on it instead of
-- updated_at, and zeroes dashboard_logins_last_30d in the same rotation.
--
-- NULL means "never rotated" (new tenant created after this migration). The
-- Go code treats NULL like "eligible", falling back to created_at as the
-- rotation baseline, so the first rotation still waits a genuine 30 days
-- after the tenant started existing; see recomputeOne.
--
-- BACKFILL: every tenant that already exists at migration time is stamped
-- with now() below rather than left NULL. Without this, recomputeOne would
-- fall back to created_at for the whole existing tenant base, and since
-- essentially every existing tenant is already older than 30 days, that
-- would rotate ALL of them (and reset ALL dashboard_logins_last_30d
-- counters) simultaneously on the very first nightly run after this ships,
-- with no staggering. Stamping now() at migration time instead defers that
-- first rotation to 30 days after deploy, giving one clean cohort instead of
-- an instant one, and after that first cycle each tenant's own future
-- rotations continue to line up with this shared deploy-time cohort (an
-- accepted one-time transition artifact of introducing real rotation
-- tracking where none existed before). New tenants signing up after this
-- migration get NULL and stagger naturally from their own created_at.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0081_healthsignals_rotation.sql
BEGIN;

-- DEPLOY ORDERING: additive column + backfill, safe to apply anytime;
-- nothing existing depends on it. recompute.go must ship in the same
-- release (or later); shipping the column alone is a harmless no-op until
-- the Go code reads it.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS health_signals_last_rotated_at TIMESTAMPTZ;

UPDATE tenants
    SET health_signals_last_rotated_at = now()
    WHERE health_signals_last_rotated_at IS NULL;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0081_healthsignals_rotation')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
