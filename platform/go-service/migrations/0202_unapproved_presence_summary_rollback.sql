-- patched.im - 0202_unapproved_presence_summary_rollback.sql
-- Reverses 0202. Every dropped row is derived and rebuildable; the episode
-- column only records the policy version an episode was opened at.
BEGIN;

DROP TRIGGER IF EXISTS trg_unapproved_presence_device_apps_ins_del ON device_apps;
DROP TRIGGER IF EXISTS trg_unapproved_presence_device_apps_upd ON device_apps;
DROP TRIGGER IF EXISTS trg_unapproved_presence_device_extensions_ins_del ON device_browser_extensions;
DROP TRIGGER IF EXISTS trg_unapproved_presence_device_extensions_upd ON device_browser_extensions;
DROP TRIGGER IF EXISTS trg_unapproved_presence_devices_upd ON devices;
DROP TRIGGER IF EXISTS trg_unapproved_presence_homebrew_current ON homebrew_current_entries;
DROP TRIGGER IF EXISTS trg_unapproved_presence_homebrew_state_ins_del ON homebrew_device_state;
DROP TRIGGER IF EXISTS trg_unapproved_presence_homebrew_state_upd ON homebrew_device_state;
DROP TRIGGER IF EXISTS trg_unapproved_presence_homebrew_details ON homebrew_observation_details;
DROP TRIGGER IF EXISTS trg_unapproved_presence_installations_ins_del ON software_installations;
DROP TRIGGER IF EXISTS trg_unapproved_presence_installations_upd ON software_installations;
DROP TRIGGER IF EXISTS trg_unapproved_presence_app_policies_ins_del ON tenant_app_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_app_policies_upd ON tenant_app_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_extension_policies_ins_del ON tenant_extension_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_extension_policies_upd ON tenant_extension_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_homebrew_policies_ins_del ON tenant_homebrew_policies;
DROP TRIGGER IF EXISTS trg_unapproved_presence_homebrew_policies_upd ON tenant_homebrew_policies;

DROP FUNCTION IF EXISTS software_unapproved_presence_policy_trg();
DROP FUNCTION IF EXISTS software_unapproved_presence_device_trg();
DROP FUNCTION IF EXISTS software_unapproved_presence_dirty_trg();
DROP FUNCTION IF EXISTS software_unapproved_presence_mark_dirty(UUID);

ALTER TABLE software_unapproved_episodes DROP COLUMN IF EXISTS policy_version;
DROP INDEX IF EXISTS software_unapproved_episodes_pending_batch_idx;
DROP TABLE IF EXISTS software_unapproved_runner_attempts;

DROP TABLE IF EXISTS software_unapproved_presence_state;
DROP INDEX IF EXISTS software_unapproved_detection_queue_order_idx;
DROP INDEX IF EXISTS software_unapproved_presence_dirty_order_idx;
DROP TABLE IF EXISTS software_unapproved_presence_dirty;
DROP TABLE IF EXISTS software_unapproved_detection_queue;
DROP TABLE IF EXISTS software_unapproved_presence_devices;
DROP STATISTICS IF EXISTS software_unapproved_presence_group_stats;
DROP TABLE IF EXISTS software_unapproved_presence;

DELETE FROM schema_migrations WHERE version = '0202_unapproved_presence_summary';

COMMIT;
