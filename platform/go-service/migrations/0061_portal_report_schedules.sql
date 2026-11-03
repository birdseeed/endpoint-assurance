-- 0061: customer-scheduled portal reports (PAT-703).
--
-- portal_report_schedules — ONE recurring report schedule per tenant, set by
-- the customer through PUT /v1/portal/reports/schedule (CF-Access-JWT-
-- authenticated; tenant derived server-side from portal_users). An in-process
-- ticker in patched-api claims due rows (enabled AND next_run_at <= now(),
-- FOR UPDATE SKIP LOCKED) and generates the customer-layout report into
-- report_records with source='portal' — the exact same path as the manual
-- POST /v1/portal/reports.
--
-- NOTE ON NAMING: the ticket says `report_schedules`, but that table already
-- exists (0052, PAT-370) as the ADMIN delivery-schedule config with a
-- different shape (multi-schedule, delivery contacts, quarterly/ad_hoc).
-- This customer-owned, one-per-tenant table is therefore named
-- portal_report_schedules, consistent with the portal_* prefix used by the
-- PAT-693 customer surface (portal_users, portal_access_log).
--
--   weekday    0=Sunday .. 6=Saturday (Go time.Weekday); required iff weekly.
--   month_day  1..31; required iff monthly. Days 29-31 clamp to the last day
--              of shorter months at run-time (scheduler month-end clamp).
--   hour_utc   0..23 — the UTC hour the report generates.
--   next_run_at is computed server-side (internal/reportsched.NextRun);
--   never accepted from the client.

BEGIN;

CREATE TABLE portal_report_schedules (
    tenant_id   UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    cadence     TEXT        NOT NULL CHECK (cadence IN ('daily','weekly','monthly')),
    weekday     INT         CHECK (weekday BETWEEN 0 AND 6),
    month_day   INT         CHECK (month_day BETWEEN 1 AND 31),
    hour_utc    INT         NOT NULL CHECK (hour_utc BETWEEN 0 AND 23),
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Cadence-shape coherence, enforced at the storage layer too (the API
    -- validates first; this keeps direct SQL writes honest).
    CONSTRAINT portal_report_schedules_cadence_shape CHECK (
        (cadence = 'daily'   AND weekday IS NULL     AND month_day IS NULL) OR
        (cadence = 'weekly'  AND weekday IS NOT NULL AND month_day IS NULL) OR
        (cadence = 'monthly' AND weekday IS NULL     AND month_day IS NOT NULL)
    )
);

-- The scheduler's claim query: WHERE enabled AND next_run_at <= now().
CREATE INDEX idx_portal_report_schedules_due
    ON portal_report_schedules (next_run_at)
    WHERE enabled;

-- ─── Grants (migration 0057 pattern; enforced by check-grants.sh) ─────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON portal_report_schedules TO patched;

INSERT INTO schema_migrations (version) VALUES ('0061_portal_report_schedules')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
