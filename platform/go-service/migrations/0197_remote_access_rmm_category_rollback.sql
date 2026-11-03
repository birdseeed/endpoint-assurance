-- patched.im - 0197_remote_access_rmm_category_rollback.sql
-- Reverts 0197: removes the seed rules, then the remote_access/rmm_agent
-- subtypes and categories, identified by
-- created_by = 'migration:0197_remote_access_rmm_category' so a rule an
-- admin has since edited or replaced through the real API (different
-- created_by from that point on) is left alone rather than silently
-- deleted. The corresponding software_category_audit rows are deliberately
-- retained: that table is append-only historical evidence, with no foreign
-- key to software_category_rules.
--
-- Fails (by FK) if any software_category_tags row still references one of
-- these rules or if any live rule/product tag still targets these category
-- keys -- retire those first. That is deliberate: this rollback removes only
-- what 0197 itself added.

BEGIN;

DELETE FROM software_category_rules WHERE created_by = 'migration:0197_remote_access_rmm_category';

DELETE FROM software_category_subtypes WHERE category_key IN ('remote_access', 'rmm_agent');
DELETE FROM software_categories WHERE key IN ('remote_access', 'rmm_agent');

DELETE FROM schema_migrations WHERE version = '0197_remote_access_rmm_category';

COMMIT;
