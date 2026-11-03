-- patched.im - 0181_portal_user_roles.sql
-- PAT-2007: customer portal roles, ruled by Andy on 2026-09-24.
--
-- portal_users gets a role: 'admin' or 'viewer'. Only an admin may write
-- software approval state through the portal (PUT /v1/portal/software-approvals);
-- a viewer is read-only. The role is enforced server-side on every portal
-- write that needs it and is never taken from the client.
--
-- Backfill: every row that exists when this runs becomes 'admin'. Those rows
-- are staff and pilot operators (3 on patched-api-01 on 2026-09-24), and
-- nobody may lose access they have today. The column is added with a
-- constant 'admin' default, which PostgreSQL applies to every existing row
-- without a table rewrite, and the default is then switched to 'viewer' for
-- every row inserted afterwards. Both steps run in one transaction, so no
-- row can be inserted between them.
--
-- A user matched only by email domain (tenant_email_domains, PAT-127) has no
-- portal_users row and therefore always resolves as 'viewer'.
--
-- The first admin of a tenant is granted by the operator through
-- POST /admin/portal-users {"role": "admin"}.
--
-- portal_users is from 0059, above the MIGRATION_FLOOR drift boundary, so
-- the live shape matches 0059 (email, tenant_id, created_at, disabled_at).
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0181_portal_user_roles.sql

BEGIN;

ALTER TABLE portal_users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin'
        CONSTRAINT portal_users_role_check CHECK (role IN ('admin', 'viewer'));

ALTER TABLE portal_users ALTER COLUMN role SET DEFAULT 'viewer';

COMMENT ON COLUMN portal_users.role IS
    'Customer portal role (PAT-2007): admin may write software approval state, viewer is read-only. Default viewer; rows existing at 0181 were backfilled to admin.';

INSERT INTO schema_migrations (version) VALUES ('0181_portal_user_roles')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
