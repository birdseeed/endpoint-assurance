-- 0180: per-user application scopes (PAT-2075)
--
-- Per-user Windows installs register under HKU\<SID>\...\Uninstall, and a
-- user's hive is readable only while that user is logged in. Before this
-- migration every device_apps row belonged to one device-wide scope: a
-- report taken after a user logged off would, under collection_status.apps
-- = complete (PAT-2063), delete that user's apps and close their
-- installations and CVE findings.
--
-- device_apps stays the device projection, one row per (device_id,
-- identifier, version), so every existing reader (CVE matching, the nightly
-- CVE sync, reports, the portal) keeps its one-row-per-product semantics and
-- sees a per-user install exactly as it sees a machine-wide one. What is new
-- is who asserts each row:
--
--   device_apps.machine_wide   TRUE when the machine-wide scope (rows sent
--                              with no user_account) asserts the row. Every
--                              existing row, and every row an older binary
--                              writes, is machine-wide, which is exactly the
--                              pre-PAT-2075 meaning.
--   device_app_user_scopes     one row per (device_apps row, user) for each
--                              user whose per-user inventory listed it.
--                              last_seen is stamped only by that user's own
--                              report. identity_fingerprint is the software
--                              observation identity of the app as reported,
--                              so the installation closure can tell that a
--                              held per-user app is still installed.
--
-- A device_apps row is deleted only when no scope asserts it any more. The
-- machine-wide prune (collection_status.apps plus the PAT-2063 safety valve)
-- releases only the machine-wide assertion; a per-user scope row is pruned
-- only by a report whose collection_status.apps_users lists that user as
-- complete. A user missing from a report (logged off), or listed partial or
-- unavailable, keeps every row.
--
-- PROD DRIFT (AGENTS.md, PAT-2051): device_apps was created in 0001, below
-- MIGRATION_FLOOR. This file relies on only two properties of the live
-- table: device_apps.id is its bigint primary key (the foreign key below)
-- and there is no machine_wide column yet. Read \d device_apps on
-- patched-api-01 before deploying.
--
-- Additive only. ADD COLUMN with a constant default is a catalogue-only
-- change on PostgreSQL 11+, so no table rewrite.
--
-- Rollback: migrations/0180_device_app_user_scopes_rollback.sql

BEGIN;

ALTER TABLE device_apps
    ADD COLUMN machine_wide BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE device_app_user_scopes (
    device_app_id        BIGINT NOT NULL REFERENCES device_apps(id) ON DELETE CASCADE,
    device_id            UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- Bounded like device_browser_extensions.user_account, but never
    -- truncated: the extractor trims the row value and the apps_users value
    -- the same way and drops a longer value, so two users that share a
    -- 128-character prefix can never collapse into one scope.
    user_account         TEXT NOT NULL CHECK (char_length(user_account) BETWEEN 1 AND 128),
    identity_fingerprint TEXT NOT NULL,
    first_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_app_id, user_account)
);
CREATE INDEX device_app_user_scopes_device_user_idx
    ON device_app_user_scopes (device_id, user_account);
CREATE INDEX device_app_user_scopes_device_fingerprint_idx
    ON device_app_user_scopes (device_id, identity_fingerprint);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_app_user_scopes TO patched;

INSERT INTO schema_migrations (version) VALUES ('0180_device_app_user_scopes')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
