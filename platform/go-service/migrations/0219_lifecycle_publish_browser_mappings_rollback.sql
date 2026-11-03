-- Reverses 0219_lifecycle_publish_browser_mappings.sql (PAT-2171).
--
-- Returns the mappings this migration published (and only those, still
-- published, still reviewed by migration:0219) to proposed, so the browsers
-- read Unknown ("no published lifecycle mapping") again. A mapping staff
-- rejected, or re-published under their own name, is left alone. The audit
-- table is append-only, so the return is recorded as a 'withdraw' row whose
-- after-state is proposed (actor migration:0219-rollback); the earlier
-- 'publish' row stays.
BEGIN;

WITH withdrawn AS (
    UPDATE lifecycle_mappings
       SET status = 'proposed', reviewed_by = NULL, reviewed_at = NULL, updated_at = now()
     WHERE status = 'published' AND reviewed_by = 'migration:0219'
    RETURNING id, eol_slug
)
INSERT INTO lifecycle_mapping_audit (mapping_id, action, actor, before, after)
SELECT id, 'withdraw', 'migration:0219-rollback',
       jsonb_build_object('status', 'published'),
       jsonb_build_object('status', 'proposed', 'eol_slug', eol_slug)
FROM withdrawn;

DELETE FROM schema_migrations WHERE version = '0219_lifecycle_publish_browser_mappings';

COMMIT;
