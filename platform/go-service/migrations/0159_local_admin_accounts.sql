-- patched.im — 0159_local_admin_accounts.sql
-- PAT-1974: standing local administrator roster (names, not just the count).
--
-- The updater half of PAT-1974 (Patched-LTD/updater #631, already merged)
-- adds a new top-level payload object, sibling to compliance/hardware_health:
--
--   "local_admins": {
--     "collection_status": "complete" | "partial" | "unavailable",
--     "accounts": [
--       { "name": "MYPC\\alice", "principal_type": "user", "builtin": false, "sid": "S-1-5-21-...-1001" }
--     ]
--   }
--
-- local_admin_count itself is UNCHANGED — it keeps flowing through the flat
-- compliance_signals bag exactly as before. This table holds the roster that
-- sits behind that count: the names the count has always been derived from
-- but never reported. Replace-on-each-complete-extraction semantics, the
-- same per-device roster shape device_apps and device_certificates already
-- use — see internal/extractor/upsert.go:upsertLocalAdmins for the exact
-- complete/partial/unavailable write behaviour (mirrors upsertCertificates
-- and upsertHardwareHealth's storage/disks branches).
--
-- No unique constraint on (device_id, name): matching this migration's own
-- precedent in device_storage_volume/device_disk (0014), which also match-
-- then-write inside the extractor's transaction rather than ON CONFLICT,
-- because a directory-sourced group name or an unresolved SID string is not
-- guaranteed unique enough across re-reads to trust as a hard constraint.
--
-- Local admins' own collection_status is NOT a new column here — it reuses
-- the existing devices.collection_status JSONB column (PAT-1732, migration
-- 0128) that hardware_health and certificates already merge into, adding a
-- new "local_admins" key alongside them. See upsertCollectionStatus.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0159_local_admin_accounts.sql

BEGIN;

CREATE TABLE local_admin_accounts (
    id              BIGSERIAL PRIMARY KEY,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,          -- "MACHINE\alice" / "CONTOSO\Domain Admins" (Windows); account short name (macOS); raw SID string for an unresolved entry
    principal_type  TEXT NOT NULL CHECK (principal_type IN ('user', 'group', 'unresolved')),
    builtin         BOOLEAN NOT NULL,        -- true for the Windows RID-500 Administrator; always false on macOS (root is filtered, never reported)
    sid             TEXT,                    -- Windows only; NULL on macOS
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_local_admin_accounts_device_id ON local_admin_accounts(device_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE local_admin_accounts TO patched;
GRANT USAGE, SELECT ON SEQUENCE local_admin_accounts_id_seq TO patched;

COMMENT ON TABLE local_admin_accounts IS
    'PAT-1974: standing local administrator roster per device, behind the local_admin_count compliance signal. Replace-on-complete-extraction; see upsertLocalAdmins.';
COMMENT ON COLUMN local_admin_accounts.principal_type IS
    'user = an individual account (local or directory-sourced). group = a directory-sourced group principal (e.g. Domain Admins); its own membership is opaque to the device and is never counted in local_admin_count. unresolved = a SID that could not be resolved to a name or kind; IS counted, because an unknown principal must never let a device pass a threshold it might actually fail.';
COMMENT ON COLUMN local_admin_accounts.builtin IS
    'True for the platform''s built-in administrator identity (Windows RID-500). Not excluded from the roster or the count — its enabled state is exactly the risk this signal exists to surface.';

INSERT INTO schema_migrations (version) VALUES ('0159_local_admin_accounts')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
