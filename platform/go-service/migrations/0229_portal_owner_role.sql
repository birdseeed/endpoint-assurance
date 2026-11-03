-- patched.im - 0229_portal_owner_role.sql
-- PAT-1883: self-service organisation sign-up. This migration only widens what
-- existing tables accept; it creates no row and rewrites none.
--
-- 1. portal_users.role gains 'owner'. An owner can do everything an admin
--    can, and is the only role that may invite people, change a member's role
--    or disable a member (the /v1/portal/access routes). The first verified
--    person to create an organisation becomes its owner; an operator can also
--    designate one for an existing tenant with POST /admin/portal-users
--    {"role": "owner"}, which the route accepts only while
--    SELF_SERVICE_SIGNUP_ENABLED is on. No existing row changes role: an
--    operator-created tenant keeps its admins and has no owner until one is
--    designated. The default stays 'viewer'.
--
-- 2. feedback.reporter_role gains 'owner'. POST /v1/portal/feedback records
--    the reporter's portal role at submission time, and 0206 allowed only
--    'viewer' and 'admin', so an owner's feedback would have failed this
--    check with a 500. The check is found by what it says, not by its
--    generated name (0222 did the same: the name on patched-api-01 is not
--    proven to match a scratch database, PAT-2051).
--
-- 3. tenants.created_via records how the tenant came to exist: 'operator'
--    (POST /admin/tenants, and every tenant that exists when this runs) or
--    'self_service' (POST /v1/portal/signup/organisation). It is not
--    tenant_kind (0119), which says whether a tenant is a customer or an
--    internal fixture: a self-service tenant is a customer. It carries no
--    subscription or trial meaning; is_trial and trial_* (0064) are not set
--    by sign-up and belong to PAT-1886. The column is added with a constant
--    default, which PostgreSQL applies without rewriting the table.
--
-- 4. portal_users.disabled_by records who disabled a member: 'operator'
--    (DELETE /admin/portal-users/{email}) or 'owner'
--    (POST /v1/portal/access/members/{email}/disable). Both write the same
--    disabled_at, and without this an owner could enable again a member the
--    operator had disabled. An owner may enable only a member an owner
--    disabled; the operator may enable anyone, and doing so clears the
--    marker. It is NULL on an enabled row, and on a row that was disabled
--    before this column existed, which is read as the operator's. The CHECK
--    keeps it to those two values and off enabled rows. The column is
--    nullable with no default, so adding it does not rewrite the table, and
--    no existing row is changed.
--
--    One consequence for a binary rollback: an API build older than this
--    migration re-enables a member by clearing disabled_at alone. On a row
--    that carries a marker that UPDATE fails this CHECK, so
--    POST /admin/portal-users answers 500 for that address until the build
--    is rolled forward again or the marker is cleared by hand
--    (UPDATE portal_users SET disabled_by = NULL WHERE email = ...).
--
-- portal_users (0059) and feedback (0206) are above the MIGRATION_FLOOR drift
-- boundary. tenants (0001) is below it: this ALTER only adds a column and
-- depends on nothing about the table's live shape beyond its existence, the
-- same shape of change as 0119.
--
-- Locks. The ALTER TABLE steps take ACCESS EXCLUSIVE on portal_users,
-- feedback and tenants, each held until COMMIT. Once granted they are held
-- for milliseconds: every step is a catalogue change or a check of a small
-- table, and nothing is rewritten. The risk is the wait before that. An
-- ACCESS EXCLUSIVE request queues behind any open transaction that has so
-- much as read the table, and while it waits every later reader queues
-- behind it: portal_users is read on every portal sign-in and tenants on
-- every ingest request. lock_timeout stops the deploy rather than queueing
-- behind a long reader. After 30 seconds the waiting statement is cancelled,
-- the transaction rolls back with nothing applied, the requests that queued
-- behind it carry on, and the deploy can be retried (the same reasoning as
-- 0172 and 0173).
--
-- Replay-safe. Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0229_portal_owner_role.sql

BEGIN;

SET LOCAL lock_timeout = '30s';

-- Validate the new-column contract before replacing any constraints. An
-- unjournalled column is drift even if it looks compatible. On replay the
-- journal permits inspection, not repair: refuse incompatible catalogue state.
-- Holding the table locks makes the preflight and ALTERs one atomic decision.
LOCK TABLE portal_users, feedback, tenants IN ACCESS EXCLUSIVE MODE;
LOCK TABLE schema_migrations IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
    replay BOOLEAN;
    expected RECORD;
    col RECORD;
    check_count INTEGER;
BEGIN
    SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0229_portal_owner_role') INTO replay;
    FOR expected IN
        SELECT * FROM (VALUES
            ('tenants', 'created_via', TRUE, '''operator''::text', 'tenants_created_via_check',
             '(created_via = ANY (ARRAY[''operator''::text, ''self_service''::text]))'),
            ('portal_users', 'disabled_by', FALSE, NULL, 'portal_users_disabled_by_check',
             '((disabled_by IS NULL) OR ((disabled_by = ANY (ARRAY[''operator''::text, ''owner''::text])) AND (disabled_at IS NOT NULL)))')
        ) AS contract(table_name, column_name, not_null, default_expr, check_name, check_expr)
    LOOP
        SELECT a.attnum, a.atttypid, a.atttypmod, a.attnotnull, a.attidentity, a.attgenerated,
               pg_get_expr(d.adbin, d.adrelid) AS default_expr
          INTO col
          FROM pg_attribute a
          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
         WHERE a.attrelid = expected.table_name::regclass
           AND a.attname = expected.column_name AND NOT a.attisdropped;
        IF NOT replay THEN
            IF FOUND THEN
                RAISE EXCEPTION '0229: unexpected unjournalled %.%', expected.table_name, expected.column_name;
            END IF;
            CONTINUE;
        END IF;
        IF NOT FOUND OR col.atttypid IS DISTINCT FROM 'text'::regtype
            OR col.atttypmod IS DISTINCT FROM -1
            OR col.attnotnull IS DISTINCT FROM expected.not_null
            OR col.default_expr IS DISTINCT FROM expected.default_expr
            OR col.attidentity IS DISTINCT FROM '' OR col.attgenerated IS DISTINCT FROM '' THEN
            RAISE EXCEPTION '0229: % column contract mismatch (type, nullability or default)', expected.column_name;
        END IF;
        SELECT count(*) INTO check_count FROM pg_constraint
         WHERE conrelid = expected.table_name::regclass AND contype = 'c' AND col.attnum = ANY(conkey);
        IF check_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
             WHERE conrelid = expected.table_name::regclass AND contype = 'c'
               AND col.attnum = ANY(conkey) AND conname = expected.check_name
               AND convalidated AND NOT connoinherit
               AND pg_get_expr(conbin, conrelid) = expected.check_expr
        ) THEN
            RAISE EXCEPTION '0229: % CHECK contract mismatch (definition, name, validation or count)', expected.column_name;
        END IF;
    END LOOP;
END $$;

-- 1. portal_users.role
ALTER TABLE portal_users
    DROP CONSTRAINT portal_users_role_check,
    ADD CONSTRAINT portal_users_role_check CHECK (role IN ('owner', 'admin', 'viewer'));

COMMENT ON COLUMN portal_users.role IS
    'Customer portal role (PAT-2007, PAT-1883): owner and admin may write; only an owner manages who has access; viewer is read-only. Default viewer; rows existing at 0181 were backfilled to admin.';

-- 2. feedback.reporter_role
LOCK TABLE feedback IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE c RECORD; dropped INTEGER := 0;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'feedback'::regclass AND contype = 'c'
           AND pg_get_constraintdef(oid) LIKE '%reporter_role%'
    LOOP
        EXECUTE format('ALTER TABLE feedback DROP CONSTRAINT %I', c.conname);
        dropped := dropped + 1;
    END LOOP;
    -- Exactly one exists: the role list. Any other count means the live table
    -- is not what 0206 says; stop rather than guess which rule to keep.
    IF dropped <> 1 THEN
        RAISE EXCEPTION '0229: expected 1 feedback reporter_role constraint, found %', dropped;
    END IF;
END $$;

ALTER TABLE feedback
    ADD CONSTRAINT feedback_reporter_role_values_check
        CHECK (reporter_role IN ('viewer', 'admin', 'owner'));

-- 3. tenants.created_via
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS created_via TEXT NOT NULL DEFAULT 'operator'
        CONSTRAINT tenants_created_via_check CHECK (created_via IN ('operator', 'self_service'));

COMMENT ON COLUMN tenants.created_via IS
    'How the tenant was created (PAT-1883): operator (POST /admin/tenants) or self_service (POST /v1/portal/signup/organisation). Not tenant_kind, and carries no subscription or trial meaning.';

-- 4. portal_users.disabled_by
ALTER TABLE portal_users
    ADD COLUMN IF NOT EXISTS disabled_by TEXT;

ALTER TABLE portal_users
    DROP CONSTRAINT IF EXISTS portal_users_disabled_by_check,
    ADD CONSTRAINT portal_users_disabled_by_check CHECK (
        disabled_by IS NULL
        OR (disabled_by IN ('operator', 'owner') AND disabled_at IS NOT NULL));

COMMENT ON COLUMN portal_users.disabled_by IS
    'Who disabled this member (PAT-1883): operator or owner. NULL when the row is enabled, and on a row disabled before the column existed, which is read as operator. An owner may enable only a member an owner disabled.';

INSERT INTO schema_migrations (version) VALUES ('0229_portal_owner_role')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
