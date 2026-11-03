-- patched.im — 0162_local_admin_account_state.sql
-- PAT-1992: persist the built-in Administrator's enabled state on the
-- standing local-administrator roster (local_admin_accounts, migration 0159).
--
-- The Windows agent (Patched-LTD/updater PR #634, PAT-1988) reads the enabled
-- state of the built-in RID-500 Administrator and reports it as
-- local_admins.accounts[].account_state: "enabled" | "disabled" | "unknown".
-- This column stores it.
--
-- NULL is the absent key: an agent that predates the field, an entry the agent
-- never read (every non-built-in entry), or any macOS entry (macOS filters
-- root out of the roster, so it has no built-in entry to carry a state).
-- "unknown" is a read that was attempted and did not establish the state, and
-- is never equivalent to "disabled". NULL and "unknown" are kept distinct on
-- purpose, and neither is ever read as a pass or a fail on its own.
--
-- Additive and forward-only: a nullable column with no default, so no table
-- rewrite and no fabricated value on existing rows. The table-level grants
-- from 0159 already cover the new column.
--
-- Write semantics live in internal/extractor/upsert.go:upsertLocalAdmins
-- ("partial" never blanks a stored state); the consuming rule lives in
-- internal/report/local_admin.go.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0162_local_admin_account_state.sql

BEGIN;

ALTER TABLE local_admin_accounts
    ADD COLUMN account_state TEXT
        CHECK (account_state IN ('enabled', 'disabled', 'unknown'));

COMMENT ON COLUMN local_admin_accounts.account_state IS
    'PAT-1992: enabled state of the Windows built-in RID-500 Administrator as the agent read it. enabled | disabled | unknown (read attempted, not established; never treated as disabled). NULL = never reported (older agent, not the built-in account, or macOS).';

INSERT INTO schema_migrations (version) VALUES ('0162_local_admin_account_state')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
