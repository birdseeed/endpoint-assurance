-- 0072: per-device app-removal task queue (PAT-781 / PAT-462).
--
-- Distinct from the TENANT-scoped allowlist uninstall mechanism
-- (tenant_allowlists.enforcement = 'marked_for_uninstall', migration 0023):
-- that flags an app for removal across the whole estate. This table tracks the
-- removal of ONE app from ONE specific device, with per-task execution state
-- reported by the updater agent.
--
-- Lifecycle:
--   queued       — operator queued the task (admin surface); agent has not run it
--   in-progress  — agent has picked the task up and is executing the uninstall
--   removed      — uninstall succeeded (terminal)
--   residual     — uninstalled but files/data remained (terminal)
--   manual       — cannot be removed unattended; needs manual action (terminal)
--   failed       — uninstall attempt failed (terminal)
-- Cancel is a soft-delete (cancelled_at set) so the trail is preserved; there
-- is deliberately no DELETE grant.
--
-- app_name matches the app-identity key used elsewhere (device_apps.name /
-- tenant_allowlists.name): the dashboard queues by display name and the agent
-- resolves the app on-device by name, exactly as the allowlist uninstall path
-- does.
--
-- tenant_id is denormalised from the device (like enforcement_audit) so the
-- agent-report path can write the enforcement_audit trail without re-joining.

BEGIN;

CREATE TABLE device_removal_tasks (
    task_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id    UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app_name     TEXT        NOT NULL,
    state        TEXT        NOT NULL DEFAULT 'queued'
                     CHECK (state IN ('queued','in-progress','removed','residual','manual','failed')),
    queued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at TIMESTAMPTZ
);

CREATE INDEX device_removal_tasks_device
    ON device_removal_tasks (device_id, queued_at DESC);

-- At most one live task (uncancelled, not yet terminal) per device+app, so a
-- double-click or re-queue can't stack duplicate work. Terminal/cancelled rows
-- are excluded from the index, so a device can be re-queued after a prior
-- attempt finished.
CREATE UNIQUE INDEX device_removal_tasks_active_uq
    ON device_removal_tasks (device_id, app_name)
    WHERE cancelled_at IS NULL AND state IN ('queued','in-progress');

-- No DELETE: cancel sets cancelled_at, terminal states are UPDATEs.
GRANT SELECT, INSERT, UPDATE ON device_removal_tasks TO patched;

INSERT INTO schema_migrations (version) VALUES ('0072_device_removal_tasks')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
