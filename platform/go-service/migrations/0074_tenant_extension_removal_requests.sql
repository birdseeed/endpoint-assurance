-- 0074_tenant_extension_removal_requests.sql
-- Per-tenant browser-extension REMOVAL request queue (PAT-832, part of PAT-773).
--
-- Deliberately separate from tenant_extension_policies (0071): that table is the
-- policy plane (approve/unapprove/ignore) and drives the PAT-828 managed-policy
-- blocklist. Destructive removal is a distinct, explicit escalation — an operator
-- clicking "Remove now" — and must NEVER be implied by policy state alone. Mixing
-- the two in one enum would let an extension get destructively removed just because
-- someone toggled it to "unapproved", a much larger blast radius than intended
-- (blocklist first, removal as a deliberate escalation — PAT-773).
--
-- Closer in spirit to device_removal_tasks (0072): a queue of "please remove this",
-- projected into the signed agent-config's app_control.extension_removals block and
-- consumed by the PAT-829 agent removal primitive. The agent is idempotent (nothing
-- on disk to remove ⇒ no-op, no audit event), so a request may safely linger in the
-- config until an operator cancels it or ops marks it fulfilled.
--
-- scope bounds how widely the agent deletes the extension; narrow scopes MUST carry
-- their target context or the request is rejected (server-side + CHECK below), so a
-- malformed request can never silently widen blast radius:
--   one_profile  → user_account + profile required (delete only that one install)
--   one_user     → user_account required           (every profile of that user)
--   all_profiles → (no context)                    (every user + profile on device)
--   all_devices  → (no context)                    (fanned to every device server-side)
--
-- browser is a concrete browser only ('any' is intentionally NOT allowed): removal
-- is a precise, targeted action, unlike the browser-agnostic blocklist policy.
--
-- DO NOT APPLY — listed here for Andy to run on patched-api-01:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0074_tenant_extension_removal_requests.sql

BEGIN;

CREATE TABLE tenant_extension_removal_requests (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    browser       TEXT         NOT NULL
                      CHECK (browser IN ('chrome', 'edge', 'firefox')),
    extension_id  TEXT         NOT NULL,
    scope         TEXT         NOT NULL
                      CHECK (scope IN ('one_profile', 'one_user', 'all_profiles', 'all_devices')),
    user_account  TEXT,        -- required for one_profile / one_user; NULL otherwise
    profile       TEXT,        -- required for one_profile; NULL otherwise
    requested_by  TEXT         NOT NULL DEFAULT '',
    requested_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    fulfilled     BOOLEAN      NOT NULL DEFAULT FALSE,
    fulfilled_at  TIMESTAMPTZ,

    -- Scope/context integrity: a narrow scope must carry the context it targets,
    -- so a directive can never silently widen beyond what was explicitly asked.
    CONSTRAINT tenant_extension_removal_scope_context CHECK (
        (scope = 'one_profile'  AND user_account IS NOT NULL AND profile IS NOT NULL) OR
        (scope = 'one_user'     AND user_account IS NOT NULL) OR
        (scope IN ('all_profiles', 'all_devices'))
    )
);

-- Projection query filters by tenant + not-yet-fulfilled; index that access path.
CREATE INDEX idx_tenant_extension_removal_requests_pending
    ON tenant_extension_removal_requests (tenant_id)
    WHERE fulfilled = FALSE;

-- At most one live (unfulfilled) request per identical target, so a double-click
-- or re-issue can't stack duplicate directives. COALESCE folds the nullable
-- context columns so NULLs compare equal (a plain unique index treats NULL as
-- distinct and would let duplicates through).
CREATE UNIQUE INDEX idx_tenant_extension_removal_requests_active_uq
    ON tenant_extension_removal_requests
       (tenant_id, browser, extension_id, scope,
        COALESCE(user_account, ''), COALESCE(profile, ''))
    WHERE fulfilled = FALSE;

-- Grants (enforced by check-grants.sh; missing grants have caused prod 500s).
-- DELETE is granted: cancelling a still-pending request is a hard delete (it was
-- never sent to fulfilment); fulfilled requests are retained.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_extension_removal_requests TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_extension_removal_requests_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0074_tenant_extension_removal_requests')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
