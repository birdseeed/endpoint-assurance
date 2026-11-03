-- patched.im - 0189_tenant_app_policies_publisher_key.sql
-- PAT-2121: the Windows publisher an approval vouches for.
--
-- One nullable column on tenant_app_policies:
--
--   publisher_key   authenticode:<root thumbprint>:<normalised leaf Subject DN>
--                   (softwaregov.AuthenticodePublisherKey). Written only by the
--                   server, when a Windows application is set to approved
--                   through PUT /v1/portal/software-approvals or the operator
--                   PUT /admin/tenants/{id}/app-policies, and derived from
--                   this tenant's own stored evidence for that product: every
--                   installation's latest observation must be Authenticode
--                   valid, chain to a microsoft or public root, and agree on
--                   one key. Anything else stores NULL. Never accepted from a
--                   client. Cleared when the row leaves approved.
--
-- New software urgency reads a trusted Windows product whose key matches an
-- approved row's key, on a different product in the same tenant, as low (the
-- Windows twin of the macOS "Team ID already has approved products" rule).
--
-- NULL means no publisher is vouched for: every existing row (nothing is
-- backfilled; a pre-existing approval gains a key when it is next written as
-- approved: from another state through the portal, or by any operator PUT),
-- every macOS, 'any' platform or name-only row,
-- and every approval whose evidence did not agree on one public root key.
--
-- The CHECK pins the shape and the platform only. It deliberately does not
-- tie the key to policy = 'approved': the binary before this one updates
-- policy without knowing the column, and a CHECK on policy would turn its
-- approved -> unapproved write into a 500 after a binary-only rollback. A
-- stale key on a non-approved row is never read (urgency filters on
-- policy = 'approved').
--
-- tenant_app_policies was created in 0032 (below MIGRATION_FLOOR=56). This
-- migration only adds a column and a constraint that reads that column and
-- platform (present since 0032), so it does not depend on any index or seed
-- whose live shape could differ from the migrations.
--
-- Additive only. ADD COLUMN with no default is a catalogue-only change (no
-- table rewrite); the CHECK validates against an all-NULL column.
-- Lock: ACCESS EXCLUSIVE on tenant_app_policies for milliseconds plus one
-- validation scan of a small table. Deploy before the binaries.

BEGIN;

ALTER TABLE tenant_app_policies
    ADD COLUMN IF NOT EXISTS publisher_key TEXT;

ALTER TABLE tenant_app_policies
    DROP CONSTRAINT IF EXISTS tenant_app_policies_publisher_key_valid,
    ADD CONSTRAINT tenant_app_policies_publisher_key_valid
        CHECK (publisher_key IS NULL
               OR (platform = 'windows'
                   AND char_length(publisher_key) <= 600
                   AND publisher_key ~ '^authenticode:[0-9a-f]{64}:[^[:space:]]'));

COMMENT ON COLUMN tenant_app_policies.publisher_key IS
    'PAT-2121. Windows only: authenticode:<root SHA-256>:<leaf Subject DN, trimmed, whitespace runs collapsed to one space, case kept>. Server-derived from the tenant''s own evidence when the row is set to approved; never client-supplied. NULL = no publisher vouched for.';

INSERT INTO schema_migrations (version) VALUES ('0189_tenant_app_policies_publisher_key')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
