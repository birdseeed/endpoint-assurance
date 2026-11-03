-- patched.im - 0198_duplicate_tools_category_rollback.sql
-- Reverts 0198: removes the seed rules for the seven new categories,
-- identified by created_by = 'migration:0198_duplicate_
-- tools_category' so a rule an admin has since edited or replaced through
-- the real API (different created_by from that point on) is left alone;
-- clears product_key back to NULL on 0197's remote_access rules (undoing
-- the backfill, not the rules themselves, which 0197 owns); drops the
-- product_key column; then the new subtypes and categories.
-- The corresponding software_category_audit rows are deliberately retained:
-- that table is append-only historical evidence, with no foreign key to
-- software_category_rules.
--
-- Fails (by FK) if any software_category_tags row still references one of
-- the rules this migration added, or if any live rule/product tag still
-- targets these category keys -- retire those first. That is deliberate:
-- this rollback removes only what 0198 itself added.

BEGIN;

DELETE FROM software_category_rules WHERE created_by = 'migration:0198_duplicate_tools_category';

UPDATE software_category_rules SET product_key = NULL
    WHERE category_key = 'remote_access' AND product_key IS NOT NULL;

ALTER TABLE software_category_rules DROP COLUMN product_key;

DELETE FROM software_category_subtypes
    WHERE category_key IN ('pdf_editor', 'screen_recorder', 'vpn_client', 'password_manager',
                            'file_sync', 'video_conferencing', 'note_taking');
DELETE FROM software_categories
    WHERE key IN ('pdf_editor', 'screen_recorder', 'vpn_client', 'password_manager',
                  'file_sync', 'video_conferencing', 'note_taking');

DELETE FROM schema_migrations WHERE version = '0198_duplicate_tools_category';

COMMIT;
