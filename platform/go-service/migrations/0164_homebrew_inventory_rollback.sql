-- Rollback for 0164_homebrew_inventory (PAT-2013).
--
-- Removes the Homebrew side tables and every Homebrew observation and
-- installation from the software seam, then restores the pre-0164 scope
-- constraint. raw_payloads still holds every Homebrew block, so a later
-- re-apply plus re-extraction rebuilds what this deletes. Without the
-- deletes, pre-0164 code would read Homebrew installations as applications
-- and its macOS all_software closure would close them.
BEGIN;

DROP TABLE IF EXISTS homebrew_cask_app_links;
DROP TABLE IF EXISTS homebrew_device_state;
DROP TABLE IF EXISTS homebrew_observation_details;
DROP FUNCTION IF EXISTS reject_homebrew_observation_detail_update();

DELETE FROM software_installations
WHERE identity_kind IN ('homebrew_formula','homebrew_cask','homebrew_tap');
DELETE FROM software_observations
WHERE identity_kind IN ('homebrew_formula','homebrew_cask','homebrew_tap');

-- software_installations_id_tenant_device_uq belongs to 0163 (PAT-2015)
-- and is deliberately left in place.

ALTER TABLE software_inventory_runs
    DROP CONSTRAINT software_inventory_runs_authoritative_scopes_check;
UPDATE software_inventory_runs
SET authoritative_scopes = array_remove(authoritative_scopes, 'homebrew')
WHERE 'homebrew' = ANY (authoritative_scopes);
ALTER TABLE software_inventory_runs
    ADD CONSTRAINT software_inventory_runs_authoritative_scopes_check
    CHECK (authoritative_scopes <@ ARRAY['all_software','windows_winget']::TEXT[]);

DELETE FROM schema_migrations WHERE version = '0164_homebrew_inventory';

COMMIT;
