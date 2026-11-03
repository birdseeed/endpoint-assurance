-- patched.im - 0190_category_kind_rules_rollback.sql
-- Reverts 0190: drops 'kind' from software_category_rules.identifier_type.
--
-- Fails if any live row already has identifier_type = 'kind' (retire or
-- delete those rows first); that failure is deliberate rather than silently
-- orphaning data the constraint would then reject.

BEGIN;

ALTER TABLE software_category_rules
    DROP CONSTRAINT software_category_rules_identifier_type_check;
ALTER TABLE software_category_rules
    ADD CONSTRAINT software_category_rules_identifier_type_check
    CHECK (identifier_type IN (
        'macos_bundle_id', 'macos_team_id', 'windows_authenticode',
        'browser_extension', 'ide_extension', 'package', 'mcp_server'));

DELETE FROM schema_migrations WHERE version = '0190_category_kind_rules';

COMMIT;
