-- patched.im — 0142_software_exceptions.sql
-- PAT-1824: software exception register (pinned version / accepted risk)
-- data model, feeding GET /v1/portal/exceptions — PAT-1785's portal page
-- consumes this contract already; it has been rendering the portal's
-- upstream-error page in production because the endpoint didn't exist.
--
-- Deliberately orthogonal to tenant_app_policies (0032, the
-- mandatory/approved/unapproved model) per PAT-1785's own ruling: an
-- exception records accepted risk for a specific pinned version, with an
-- acceptor, a review date and a dependency reason — fields no policy row
-- carries — and a product can be policy-unapproved while also carrying an
-- accepted exception. This migration does not touch tenant_app_policies.
--
-- A pinned version never suppresses a CVE finding for that product/version
-- (root AGENTS.md: absence requires authority) — device_cve_findings /
-- cve_feed_entries (0025) are untouched by this table. Any "update
-- available" noise suppression tied to a pinned version is separate,
-- deferred scope (see PAT-1785's own follow-up note), not built here.
--
-- Write path (12 Sept portal decision: "a customer asks, a specialist
-- records"): this is not a customer-facing write. Rows are created and
-- mutated only via the /admin/tenants/{id}/exceptions... routes, authed by
-- ADMIN_API_TOKEN on the internal listener — see internal/handlers/
-- software_exceptions.go. The portal route is read-only, like every other
-- /v1/portal/* endpoint.
--
-- Shape: one row per exception (tenant_software_exceptions), an append-only
-- decision log per exception (tenant_software_exception_changes — same
-- shape as tenant_shadow_it_policy_changes, 0104, named in the ticket as
-- good prior art), and a join table for the requesting device(s)
-- (tenant_software_exception_devices) since the portal contract's
-- "devices"/"device_count" is a list, not a single device.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0142_software_exceptions.sql

BEGIN;

CREATE TABLE tenant_software_exceptions (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    product       TEXT         NOT NULL,
    version       TEXT         NOT NULL,
    type          TEXT         NOT NULL DEFAULT 'application',
    depends_on    TEXT         NOT NULL DEFAULT '',
    requested_by  TEXT         NOT NULL DEFAULT '',
    requested_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- status is first-class, not absence-of-acceptance: 'unaccepted' is the
    -- row's starting and default state, the same status an accepted
    -- exception can never silently revert to (there is no un-accept path;
    -- see the handler doc comment for why).
    status        TEXT         NOT NULL DEFAULT 'unaccepted'
                       CHECK (status IN ('unaccepted', 'accepted')),
    acceptor      TEXT,
    accepted_at   TIMESTAMPTZ,
    -- review_date is a DATE, not a TIMESTAMPTZ: the contract's
    -- "review_date": "2026-12-01" is a calendar date with no time
    -- component, and review_overdue is computed server-side against
    -- today's date (see FetchPortalExceptions), never a client-supplied
    -- clock.
    review_date   DATE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT tenant_software_exceptions_accept_fields CHECK (
        (status = 'unaccepted' AND acceptor IS NULL AND accepted_at IS NULL) OR
        (status = 'accepted' AND acceptor IS NOT NULL AND accepted_at IS NOT NULL)
    )
);

CREATE INDEX idx_tenant_software_exceptions_tenant
    ON tenant_software_exceptions (tenant_id, status, product, version);

GRANT SELECT, INSERT, UPDATE ON TABLE tenant_software_exceptions TO patched;

-- ── Requesting device(s) ────────────────────────────────────────────────
-- Separate join table, not a device_id column on the exception row itself:
-- the portal contract's "devices"/"device_count" is a list (an exception
-- can be requested against more than one device running the same pinned
-- product/version), matching the shape GET /v1/portal/extensions already
-- exposes for its own per-row device drill-down.
CREATE TABLE tenant_software_exception_devices (
    exception_id  UUID  NOT NULL REFERENCES tenant_software_exceptions(id) ON DELETE CASCADE,
    device_id     UUID  NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (exception_id, device_id)
);

CREATE INDEX idx_tenant_software_exception_devices_device
    ON tenant_software_exception_devices (device_id);

GRANT SELECT, INSERT, DELETE ON TABLE tenant_software_exception_devices TO patched;

-- ── Append-only decision log ────────────────────────────────────────────
-- Same shape and append-only enforcement as tenant_shadow_it_policy_changes
-- (0104): evidence and decisions are separate (root AGENTS.md) — this
-- table is never updated to reflect a later acceptor change, only appended
-- to, so the full history (every "requested"/"accepted"/
-- "review_date_renewed" action) survives a later review-date renewal or
-- (if ever added) a re-acceptance by a different specialist.
CREATE TABLE tenant_software_exception_changes (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    exception_id  UUID         NOT NULL REFERENCES tenant_software_exceptions(id) ON DELETE CASCADE,
    action        TEXT         NOT NULL
                       CHECK (action IN ('requested', 'accepted', 'review_date_renewed')),
    actor         TEXT         NOT NULL DEFAULT '',
    reason        TEXT         NOT NULL DEFAULT '',
    at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenant_software_exception_changes_exception
    ON tenant_software_exception_changes (exception_id, at);
CREATE INDEX idx_tenant_software_exception_changes_tenant
    ON tenant_software_exception_changes (tenant_id, at DESC);

COMMENT ON TABLE tenant_software_exception_changes IS
    'Append-only decision log for tenant_software_exceptions — same convention as tenant_shadow_it_policy_changes (0104).';

CREATE FUNCTION reject_tenant_software_exception_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_software_exception_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_software_exception_changes_append_only
    BEFORE UPDATE OR DELETE ON tenant_software_exception_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_software_exception_changes_mutation();

CREATE FUNCTION reject_tenant_software_exception_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_software_exception_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_software_exception_changes_append_only_truncate
    BEFORE TRUNCATE ON tenant_software_exception_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_software_exception_changes_truncate();

GRANT SELECT, INSERT ON TABLE tenant_software_exception_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_software_exception_changes_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0142_software_exceptions')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
