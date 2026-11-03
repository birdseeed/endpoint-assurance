-- 0178: allow 'safari' in tenant_extension_policies.browser (PAT-2071).
--
-- PAT-2064 started storing macOS Safari app-extension rows in
-- device_browser_extensions with browser='safari' (and user_account/profile
-- normalised to the '_system' sentinel, since a Safari extension lives in an
-- app bundle rather than a browser user profile). This table's CHECK
-- constraint (0071) only allowed 'chrome', 'edge', 'firefox' or the
-- browser-agnostic 'any', so an admin could not create a Safari-specific
-- policy row: the only entry that would ever match a Safari row was one
-- scoped 'any', which also applies to every other browser. This widens the
-- constraint to match the application layer (internal/handlers/extension_policies.go),
-- exactly as 0070 did for tenant_allowlists.enforcement.
--
-- tenant_extension_removal_requests (0074) is deliberately NOT widened here.
-- Safari app extensions ship with their host app; Patched does not actuate
-- removal for them, only records policy/approval state.
--
-- DO NOT APPLY — listed here for Andy to run on patched-api-01:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0178_tenant_extension_policies_safari.sql

BEGIN;

ALTER TABLE tenant_extension_policies
    DROP CONSTRAINT tenant_extension_policies_browser_check,
    ADD CONSTRAINT tenant_extension_policies_browser_check
        CHECK (browser IN ('chrome', 'edge', 'firefox', 'safari', 'any'));

INSERT INTO schema_migrations (version) VALUES ('0178_tenant_extension_policies_safari');

COMMIT;
