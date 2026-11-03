-- patched.im - 0082_report_records_schedule_slot.sql
-- PAT-874: give scheduled portal reports a real idempotency key.
--
-- Root cause: internal/reportsched/sweeper.go's crash-recovery guard needs to
-- tell "the scheduler already generated a report for this exact slot" apart
-- from "a customer generated their own report around the same time" -- both
-- write report_records with source='portal' through the SAME generation path
-- (generatePortalReport), and until now nothing on the row said which case
-- produced it. A timestamp-window heuristic can't tell them apart: a
-- customer clicking "Generate report" in the portal shortly after a
-- scheduled slot becomes due would be indistinguishable from the scheduler's
-- own retry, and the sweeper would wrongly skip (or, worse, wrongly treat a
-- genuinely still-failing retry as already satisfied).
--
-- Fix: a dedicated, nullable column set ONLY by the scheduler
-- (reportsched.Sweeper -> handlers.PortalReportGenerator), holding the exact
-- portal_report_schedules.next_run_at value the row was generated for. NULL
-- for every ad-hoc/customer-triggered/admin report -- those never match an
-- equality lookup against a non-null slot, so there is no ambiguity.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0082_report_records_schedule_slot.sql
BEGIN;

-- DEPLOY ORDERING: additive column + index, safe to apply anytime; nothing
-- existing depends on it. Ship the Go change (sweeper.go + handlers/portal.go)
-- in the same release so the guard is live as soon as the column exists.

ALTER TABLE report_records
    ADD COLUMN IF NOT EXISTS schedule_slot TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_report_records_schedule_slot
    ON report_records (tenant_id, schedule_slot)
    WHERE schedule_slot IS NOT NULL;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0082_report_records_schedule_slot')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
