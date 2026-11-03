-- patched.im - 0112_software_observation_backfill.sql
-- PAT-1461 review fix (P1): the device_apps -> software observation domain
-- backfill split out of 0111's DDL transaction. 0111 scans no rows and holds
-- its table/trigger locks only for the duration of DDL; this migration does
-- the (potentially large) device_apps scan on its own, separately-lockable
-- transaction, so a production-sized estate cannot turn schema creation into
-- an extended-lock, timeout-risking operation.
--
-- Idempotent by construction: every INSERT below targets a table already
-- protected by a UNIQUE constraint or index that exactly matches what this
-- backfill would otherwise duplicate, and every INSERT declares an explicit
-- ON CONFLICT ... DO NOTHING against that constraint. Re-running this file
-- after a partial or interrupted apply is safe -- it will not duplicate rows,
-- overwrite curated resolution state, or error.
BEGIN;

-- Backfill only the currently materialised legacy snapshot. It deliberately
-- uses last_seen for both ends of the initial episode and does not claim a raw
-- payload or historical first_seen that cannot be proven from device_apps.
-- Conflict target matches software_inventory_runs_backfill_device_uq (0111):
-- a partial UNIQUE index on (device_id) WHERE provenance =
-- 'backfill_current_snapshot'.
INSERT INTO software_inventory_runs (
    tenant_id, device_id, platform, received_at, provenance, coverage, authoritative_scopes
)
SELECT d.tenant_id,
       d.id,
       CASE WHEN lower(d.os) LIKE 'mac%' THEN 'macos' ELSE 'windows' END,
       COALESCE(MAX(da.last_seen), d.last_seen),
       'backfill_current_snapshot',
       jsonb_build_object('source', 'device_apps', 'historical', false),
       '{}'::TEXT[]
FROM devices d
JOIN device_apps da ON da.device_id = d.id
GROUP BY d.id, d.tenant_id, d.os, d.last_seen
ON CONFLICT (device_id) WHERE provenance = 'backfill_current_snapshot' DO NOTHING;

-- Scoped to backfill-provenance runs only, so a re-run (or a run that lands
-- after real inventory_payload extraction has already started writing to
-- these tables) never touches non-backfill evidence.
WITH source AS (
    SELECT sir.id AS run_id,
           d.tenant_id,
           d.id AS device_id,
           sir.platform,
           da.name,
           da.version,
           da.identifier,
           da.identifier_kind,
           da.publisher,
           da.signer,
           da.team_id,
           da.path,
           da.architecture,
           da.sha256,
           da.notarized,
           da.last_seen,
           row_number() OVER (PARTITION BY d.id ORDER BY da.id) - 1 AS ordinal,
           CASE
             WHEN sir.platform = 'macos' AND nullif(btrim(da.identifier),'') IS NOT NULL
                  AND nullif(btrim(da.team_id),'') IS NOT NULL THEN 'macos_bundle_team'
             WHEN sir.platform = 'macos' AND nullif(btrim(da.identifier),'') IS NOT NULL THEN 'macos_bundle'
             WHEN sir.platform = 'windows' AND da.identifier_kind = 'winget' THEN 'windows_winget'
             WHEN sir.platform = 'windows' AND nullif(btrim(da.identifier),'') IS NOT NULL
                  AND coalesce(nullif(btrim(da.signer),''), nullif(btrim(da.publisher),'')) IS NOT NULL THEN 'windows_native_publisher'
             WHEN sir.platform = 'windows' AND nullif(btrim(da.identifier),'') IS NOT NULL THEN 'windows_native'
             WHEN coalesce(nullif(btrim(da.publisher),''), nullif(btrim(da.signer),''), nullif(btrim(da.team_id),'')) IS NOT NULL THEN 'name_publisher'
             ELSE 'display_name'
           END AS normalised_kind,
           lower(btrim(CASE
             WHEN nullif(btrim(da.identifier),'') IS NOT NULL THEN da.identifier
             ELSE da.name
           END)) AS normalised_value,
           CASE
             WHEN sir.platform = 'macos' AND nullif(btrim(da.identifier),'') IS NOT NULL
                  AND nullif(btrim(da.team_id),'') IS NOT NULL THEN upper(btrim(da.team_id))
             WHEN sir.platform = 'windows' THEN lower(regexp_replace(btrim(coalesce(nullif(da.signer,''), da.publisher, '')), '\s+', ' ', 'g'))
             ELSE lower(regexp_replace(btrim(coalesce(nullif(da.publisher,''), nullif(da.signer,''), da.team_id, '')), '\s+', ' ', 'g'))
           END AS normalised_companion,
           CASE
             WHEN sir.platform = 'macos' AND nullif(btrim(da.identifier),'') IS NOT NULL
                  AND nullif(btrim(da.team_id),'') IS NOT NULL THEN 'exact'
             WHEN nullif(btrim(da.identifier),'') IS NOT NULL
                  AND coalesce(nullif(btrim(da.publisher),''), nullif(btrim(da.signer),''), nullif(btrim(da.team_id),'')) IS NOT NULL THEN 'medium'
             ELSE 'low'
           END AS identity_confidence
    FROM devices d
    JOIN device_apps da ON da.device_id = d.id
    JOIN software_inventory_runs sir ON sir.device_id = d.id
      AND sir.provenance = 'backfill_current_snapshot'
), keyed AS (
    SELECT source.*,
           encode(digest(concat_ws(chr(31), platform, normalised_kind, normalised_value, normalised_companion), 'sha256'), 'hex') AS fingerprint
    FROM source
)
INSERT INTO software_observations (
    inventory_run_id, tenant_id, device_id, ordinal, platform,
    observed_name, observed_version, observed_identifier, observed_identifier_kind,
    observed_publisher, observed_signer, observed_team_id, observed_path,
    observed_architecture, observed_sha256, observed_notarized,
    identity_kind, identity_value_normalized, companion_value_normalized,
    identity_confidence, identity_fingerprint, observed_at
)
SELECT run_id, tenant_id, device_id, ordinal, platform,
       name, version, identifier, identifier_kind,
       publisher, signer, team_id, path, architecture, sha256, notarized,
       normalised_kind, normalised_value, normalised_companion,
       identity_confidence, fingerprint, last_seen
FROM keyed
ON CONFLICT (inventory_run_id, ordinal) DO NOTHING;

-- Scoped to observations produced by backfill runs, so re-running never
-- clobbers resolution state (curated or otherwise) that has since been set
-- on real inventory_payload evidence.
INSERT INTO software_observation_resolutions (
    observation_id, tenant_id, resolution_state, resolution_method
)
SELECT so.id, so.tenant_id, 'unresolved', 'none'
FROM software_observations so
JOIN software_inventory_runs sir ON sir.id = so.inventory_run_id
WHERE sir.provenance = 'backfill_current_snapshot'
ON CONFLICT (observation_id) DO NOTHING;

-- Scoped the same way, and DO NOTHING on conflict: a device/identity pair
-- already present in software_installations (from a prior partial run of
-- this migration, or from real inventory_payload extraction that has since
-- run) is left exactly as-is rather than overwritten by backfill data.
INSERT INTO software_installations (
    tenant_id, device_id, platform, identity_kind, identity_value_normalized,
    companion_value_normalized, identity_fingerprint, current_name,
    current_version, current_publisher, current_path, current_architecture,
    first_seen_at, last_seen_at, latest_observation_id, provenance
)
SELECT DISTINCT ON (so.device_id, so.identity_fingerprint)
       so.tenant_id, so.device_id, so.platform, so.identity_kind, so.identity_value_normalized,
       so.companion_value_normalized, so.identity_fingerprint, so.observed_name,
       so.observed_version, so.observed_publisher, so.observed_path, so.observed_architecture,
       so.observed_at, so.observed_at, so.id, 'backfill_current_snapshot'
FROM software_observations so
JOIN software_inventory_runs sir ON sir.id = so.inventory_run_id
WHERE sir.provenance = 'backfill_current_snapshot'
ORDER BY so.device_id, so.identity_fingerprint, so.observed_at DESC, so.id DESC
ON CONFLICT (device_id, identity_fingerprint) DO NOTHING;

INSERT INTO schema_migrations (version) VALUES ('0112_software_observation_backfill')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
