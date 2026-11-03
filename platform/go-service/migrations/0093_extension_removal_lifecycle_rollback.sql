-- Rollback for 0093_extension_removal_lifecycle.
-- Fail closed rather than discarding non-reconstructible lifecycle evidence.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM tenant_extension_removal_requests WHERE cancelled_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM tenant_extension_removal_targets WHERE completed_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM enforcement_audit
                  WHERE event_type IN ('extension_blocklist_pushed', 'extension_removed')) THEN
        RAISE EXCEPTION '0093 rollback refused: browser-extension lifecycle audit history exists';
    END IF;
END $$;

DROP TABLE IF EXISTS tenant_extension_removal_targets;

DROP INDEX IF EXISTS idx_tenant_extension_removal_requests_active_uq;
CREATE UNIQUE INDEX idx_tenant_extension_removal_requests_active_uq
    ON tenant_extension_removal_requests
       (tenant_id, browser, extension_id, scope,
        COALESCE(user_account, ''), COALESCE(profile, ''))
    WHERE fulfilled = FALSE;

ALTER TABLE tenant_extension_removal_requests DROP COLUMN IF EXISTS cancelled_at;

ALTER TABLE enforcement_audit DROP CONSTRAINT enforcement_audit_event_type_check;
ALTER TABLE enforcement_audit ADD CONSTRAINT enforcement_audit_event_type_check
    CHECK (event_type IN (
        'admin_removed', 'admin_removal_skipped',
        'app_blocked', 'app_block_skipped'
    ));

DELETE FROM schema_migrations WHERE version = '0093_extension_removal_lifecycle';

COMMIT;
