-- patched.im - 0093_extension_removal_lifecycle.sql
-- PAT-1169: evidence-backed browser-extension removal lifecycle.
--
-- The original queue stored only fulfilled=false and had no code path that
-- could ever set it true.  Capture the exact extension installs selected when
-- a request is created, then let authenticated extension_removed audit events
-- complete those targets one by one.  Existing active requests are backfilled
-- from the current inventory; if an install has already disappeared without
-- audit evidence, it deliberately remains unproven rather than being guessed
-- complete.

BEGIN;

ALTER TABLE tenant_extension_removal_requests
    ADD COLUMN cancelled_at TIMESTAMPTZ;

CREATE TABLE tenant_extension_removal_targets (
    request_id      BIGINT      NOT NULL REFERENCES tenant_extension_removal_requests(id) ON DELETE CASCADE,
    -- Snapshot identity, deliberately not an FK: normal device deletion must
    -- not erase the evidence obligation or make a partial job look complete.
    device_id       UUID        NOT NULL,
    user_account    TEXT        NOT NULL,
    profile         TEXT        NOT NULL,
    completed_at    TIMESTAMPTZ,
    audit_event_id  UUID        REFERENCES enforcement_audit(id),
    PRIMARY KEY (request_id, device_id, user_account, profile)
);

CREATE INDEX idx_extension_removal_targets_pending
    ON tenant_extension_removal_targets (request_id, device_id)
    WHERE completed_at IS NULL;

INSERT INTO tenant_extension_removal_targets
    (request_id, device_id, user_account, profile)
SELECT DISTINCT r.id, dbe.device_id, dbe.user_account, dbe.profile
FROM tenant_extension_removal_requests r
JOIN devices d
  ON d.tenant_id = r.tenant_id
JOIN device_browser_extensions dbe
  ON dbe.device_id = d.id
 AND dbe.browser = r.browser
 AND dbe.extension_id = r.extension_id
WHERE r.fulfilled = FALSE
  AND r.cancelled_at IS NULL
  AND (
       (r.scope = 'one_profile'
        AND lower(dbe.user_account) = lower(r.user_account)
        AND dbe.profile = r.profile)
    OR (r.scope = 'one_user'
        AND lower(dbe.user_account) = lower(r.user_account))
    OR r.scope IN ('all_profiles', 'all_devices')
  )
ON CONFLICT DO NOTHING;

DROP INDEX idx_tenant_extension_removal_requests_active_uq;
CREATE UNIQUE INDEX idx_tenant_extension_removal_requests_active_uq
    ON tenant_extension_removal_requests
       (tenant_id, browser, extension_id, scope,
        COALESCE(user_account, ''), COALESCE(profile, ''))
    WHERE fulfilled = FALSE AND cancelled_at IS NULL;

-- PAT-828/PAT-829 agents already emit these signed event types.  The original
-- PAT-603 allowlist and DB check constraint predated extension control and
-- rejected the entire batch, leaving durable agent retries stuck forever.
ALTER TABLE enforcement_audit DROP CONSTRAINT enforcement_audit_event_type_check;
ALTER TABLE enforcement_audit ADD CONSTRAINT enforcement_audit_event_type_check
    CHECK (event_type IN (
        'admin_removed', 'admin_removal_skipped',
        'app_blocked', 'app_block_skipped',
        'extension_blocklist_pushed', 'extension_removed'
    ));

GRANT SELECT, INSERT, UPDATE ON tenant_extension_removal_targets TO patched;

INSERT INTO schema_migrations (version) VALUES ('0093_extension_removal_lifecycle')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
