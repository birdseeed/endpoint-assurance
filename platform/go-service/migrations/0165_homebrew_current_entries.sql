-- 0165: Homebrew current-entry projection (PAT-2032)
--
-- The portal's "current" Homebrew list was computed on every request from
-- the whole detail history since the device's authority_at, keyed by
-- version. A Mac that only ever reports partial therefore showed every
-- version it had ever reported as installed, and each read scanned that
-- history.
--
-- homebrew_current_entries holds one row per (device, kind, prefix, name,
-- version_key): the newest report that listed that formula keg, cask or tap.
-- version_key is the keg version for a formula and '' for a cask or tap (a
-- cask's single record is read whole). A partial report only adds or
-- refreshes rows: it can list a formula without having read every keg (the
-- formula bound cuts mid-formula, the time check runs per keg, an unreadable
-- keg is skipped), so it never hides one. A complete or not_present report
-- drops every row it did not refresh; a failed report changes nothing
-- (absence requires authority). The extractor maintains it
-- (upsertHomebrewCurrentEntries) under a per-device lock on
-- homebrew_device_state, and the portal read also filters on authority_at.
--
-- Derived, not evidence: raw_payloads and homebrew_observation_details stay
-- the source of truth, and the backfill below rebuilds it from them.
BEGIN;

CREATE TABLE homebrew_current_entries (
    device_id          UUID NOT NULL,
    tenant_id          UUID NOT NULL,
    package_kind       TEXT NOT NULL CHECK (package_kind IN ('formula','cask','tap')),
    prefix             TEXT NOT NULL,
    name               TEXT NOT NULL,
    version_key        TEXT NOT NULL DEFAULT '',
    -- received_at of the newest report that listed this entry
    observed_at        TIMESTAMPTZ NOT NULL,
    inventory_run_id   UUID NOT NULL,
    PRIMARY KEY (device_id, package_kind, prefix, name, version_key),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (inventory_run_id, tenant_id, device_id)
        REFERENCES software_inventory_runs(id, tenant_id, device_id) ON DELETE CASCADE
);
CREATE INDEX homebrew_current_entries_tenant_idx
    ON homebrew_current_entries (tenant_id, device_id);

-- The join from a current entry to its report's detail rows.
CREATE INDEX homebrew_observation_details_run_entry_idx
    ON homebrew_observation_details (inventory_run_id, package_kind, prefix, name);

-- Backfill from existing evidence: per entry, the newest report at or after
-- the device's authority.
INSERT INTO homebrew_current_entries (
    device_id, tenant_id, package_kind, prefix, name, version_key, observed_at, inventory_run_id
)
SELECT DISTINCT ON (h.device_id, h.package_kind, h.prefix, h.name,
                    CASE WHEN h.package_kind = 'formula' THEN COALESCE(h.version, '') ELSE '' END)
       h.device_id, h.tenant_id, h.package_kind, h.prefix, h.name,
       CASE WHEN h.package_kind = 'formula' THEN COALESCE(h.version, '') ELSE '' END,
       h.observed_at, h.inventory_run_id
FROM homebrew_observation_details h
JOIN homebrew_device_state s ON s.device_id = h.device_id AND s.tenant_id = h.tenant_id
WHERE s.authority_at IS NULL OR h.observed_at >= s.authority_at
ORDER BY h.device_id, h.package_kind, h.prefix, h.name,
         CASE WHEN h.package_kind = 'formula' THEN COALESCE(h.version, '') ELSE '' END,
         h.observed_at DESC, h.observation_id DESC
ON CONFLICT DO NOTHING;

COMMENT ON TABLE homebrew_current_entries IS
    'PAT-2032: newest report per device Homebrew formula keg, cask or tap (kind, prefix, name, version_key). Only complete or not_present prunes. Derived; rebuilt from homebrew_observation_details.';

GRANT SELECT, INSERT, UPDATE, DELETE ON homebrew_current_entries TO patched;

INSERT INTO schema_migrations (version) VALUES ('0165_homebrew_current_entries')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
