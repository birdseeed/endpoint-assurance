-- Rollback for PAT-2015 (0163_software_category_tags.sql).
--
-- Drops the category tag model. The global rules and their audit history are
-- lost with it, so export software_category_rules and software_category_audit
-- first if they hold reviewed content (PAT-2016's seed list). The tenant
-- matches in software_category_tags are derived and are rebuilt by publishing
-- the rules again. Deploy the previous binaries first: the extractor and API
-- from this change read and write these tables.

BEGIN;

DROP TABLE IF EXISTS software_category_tags;
DROP TABLE IF EXISTS software_category_audit;
DROP FUNCTION IF EXISTS reject_software_category_audit_mutation();
DROP TABLE IF EXISTS software_category_product_tags;
DROP TABLE IF EXISTS software_category_rules;
DROP TABLE IF EXISTS software_category_subtypes;
DROP TABLE IF EXISTS software_categories;

DROP INDEX IF EXISTS device_browser_extensions_lower_extension_id_idx;
DROP INDEX IF EXISTS software_installations_identity_value_present_idx;
ALTER TABLE device_browser_extensions
    DROP CONSTRAINT IF EXISTS device_browser_extensions_id_device_uq;
ALTER TABLE software_installations
    DROP CONSTRAINT IF EXISTS software_installations_id_tenant_device_uq;

DELETE FROM schema_migrations WHERE version = '0163_software_category_tags';

COMMIT;
