-- Rollback for 0166_tooling_inventory (PAT-2021).
--
-- Removes the tooling side tables and every IDE extension, package, local
-- model, runtime installation and MCP server observation and installation
-- from the software seam (their category tags cascade), then restores the
-- 0163 tag constraints and the 0164 scope constraint. raw_payloads still
-- holds every block, so a re-apply plus re-extraction rebuilds what this
-- deletes. Without the deletes, pre-0166 code would read these installations
-- as applications and the macOS all_software closure would close them.
BEGIN;

DROP TABLE IF EXISTS tooling_current_entries;
DROP TABLE IF EXISTS tooling_device_state;
DROP TABLE IF EXISTS tooling_observation_details;
DROP FUNCTION IF EXISTS reject_tooling_observation_detail_update();
-- software_installations_kind_value_present_idx belongs to 0167; roll that
-- back first.

DELETE FROM software_installations
WHERE identity_kind IN (
    'ide_extension','ide_extension_unidentified',
    'npm_package','npm_package_unidentified','pip_package','pip_package_unidentified',
    'local_model','local_model_unidentified','local_model_runtime',
    'mcp_server','mcp_server_unnamed');
DELETE FROM software_observations
WHERE identity_kind IN (
    'ide_extension','ide_extension_unidentified',
    'npm_package','npm_package_unidentified','pip_package','pip_package_unidentified',
    'local_model','local_model_unidentified','local_model_runtime',
    'mcp_server','mcp_server_unnamed');

-- Any tag still carrying a new kind has lost its installation above; this
-- is belt and braces before the narrower constraints return.
DELETE FROM software_category_tags
WHERE observation_kind IN ('ide_extension','package','mcp_server','local_model');
ALTER TABLE software_category_tags
    DROP CONSTRAINT software_category_tags_check;
ALTER TABLE software_category_tags
    ADD CONSTRAINT software_category_tags_check
    CHECK ((observation_kind = 'app' AND installation_id IS NOT NULL AND browser_extension_id IS NULL)
        OR (observation_kind = 'browser_extension' AND browser_extension_id IS NOT NULL AND installation_id IS NULL));
ALTER TABLE software_category_tags
    DROP CONSTRAINT software_category_tags_observation_kind_check;
ALTER TABLE software_category_tags
    ADD CONSTRAINT software_category_tags_observation_kind_check
    CHECK (observation_kind IN ('app','browser_extension'));

ALTER TABLE software_inventory_runs
    DROP CONSTRAINT software_inventory_runs_authoritative_scopes_check;
UPDATE software_inventory_runs
SET authoritative_scopes = ARRAY(
        SELECT s FROM unnest(authoritative_scopes) AS s
        WHERE s IN ('all_software','windows_winget','homebrew'))
WHERE NOT (authoritative_scopes <@ ARRAY['all_software','windows_winget','homebrew']::TEXT[]);
ALTER TABLE software_inventory_runs
    ADD CONSTRAINT software_inventory_runs_authoritative_scopes_check
    CHECK (authoritative_scopes <@ ARRAY['all_software','windows_winget','homebrew']::TEXT[]);

DELETE FROM schema_migrations WHERE version = '0166_tooling_inventory';

COMMIT;
