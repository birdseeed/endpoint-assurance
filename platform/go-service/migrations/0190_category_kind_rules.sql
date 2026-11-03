-- patched.im - 0190_category_kind_rules.sql
-- PAT-2094: a "kind" rule type for internal/categorytag, so a category rule
-- can match every observation of one named Observation.Kind instead of one
-- identifier value.
--
-- Why: the mcp_server rule type (identifier_type = 'mcp_server') matches the
-- server name the user chose in their own client config, so no product rule
-- can reliably catch an MCP server. Every MCP server is AI tooling by
-- definition -- it is what gives an AI tool access to local files and local
-- systems -- so PAT-2016's seed needs a rule that tags every mcp_server
-- observation regardless of name.
--
-- This is only a schema floor. internal/categorytag.NormalizeRule
-- (kindRuleKinds) is the real, minimal gate: identifier_type = 'kind' rules
-- are restricted in Go to identifier_value = 'mcp_server' only. This is not
-- a general "tag everything of kind X" mechanism -- extending the allowed
-- kind set is a Go code change and review, never just an admin API call with
-- a new value. The table is a few hundred rows (the PAT-2016 seed plus this
-- one), so the constraint is dropped and re-added validated in one
-- transaction rather than split NOT VALID / VALIDATE the way 0166/0167 did
-- for larger, higher-traffic tables.

BEGIN;

ALTER TABLE software_category_rules
    DROP CONSTRAINT software_category_rules_identifier_type_check;
ALTER TABLE software_category_rules
    ADD CONSTRAINT software_category_rules_identifier_type_check
    CHECK (identifier_type IN (
        'macos_bundle_id', 'macos_team_id', 'windows_authenticode',
        'browser_extension', 'ide_extension', 'package', 'mcp_server', 'kind'));

COMMENT ON CONSTRAINT software_category_rules_identifier_type_check ON software_category_rules IS
    'PAT-2094: kind is a kind-level rule type. internal/categorytag.kindRuleKinds is the real, narrower gate (currently mcp_server only) -- this CHECK is only the outer floor.';

INSERT INTO schema_migrations (version) VALUES ('0190_category_kind_rules')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
