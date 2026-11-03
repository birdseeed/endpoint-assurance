-- 0076: tenant-agnostic known-app-bundle-path table (PAT-806).
--
-- Distinct from the curated EULA/mirror Catalogue (mirror_eula_approvals,
-- migration 0073) -- that's a manually-reviewed redistribution/legal concern.
-- This table is auto-populated from every tenant's inventory scans and exists
-- purely to answer "where does this app's bundle usually live on disk", so
-- the macOS uninstall engine (endpoint/patched-uninstall.sh) can resolve a
-- display-name/bundle-filename mismatch (e.g. "Zoom" -> zoom.us.app, PAT-771)
-- even for apps that were never manually reviewed into the Catalogue.
--
-- Tenant-agnostic by design: a bundle path like /Applications/zoom.us.app is
-- identical across every customer, so there is no tenant_id column and no
-- per-tenant scoping.
--
-- Keyed by (name, platform), CASE-INSENSITIVELY on name -- device_apps spans
-- both macOS and Windows and their path shapes are unrelated, so the same
-- app name on both platforms must not collide. Case-insensitive because the
-- consuming query (GET /v1/allowlist/pending-removals) joins against
-- tenant_allowlists.name via LOWER() on both sides (admin-typed names and
-- collector-observed device_apps.name casing are not guaranteed to agree,
-- e.g. an admin queuing "zoom" against a device that reported "Zoom"). A
-- plain PRIMARY KEY (name, platform) is case-SENSITIVE in Postgres and would
-- let e.g. ('Zoom','macos') and ('zoom','macos') coexist as two distinct
-- rows -- which the case-insensitive join would then both match, returning
-- duplicate items for a single queued removal. The unique index below on
-- (LOWER(name), platform) prevents that at the write side instead.
--
-- No retention/expiry logic in v1 (deliberate): the consuming shell script
-- verifies the path exists on disk before trusting it, so a stale mapping
-- (e.g. after a vendor renames their bundle across a major version) just
-- silently fails to resolve rather than causing any harm.

BEGIN;

CREATE TABLE known_app_bundles (
    id            BIGSERIAL   PRIMARY KEY,
    name          TEXT        NOT NULL,
    platform      TEXT        NOT NULL CHECK (platform IN ('macos', 'windows')),
    app_path      TEXT        NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive on name (see rationale above); this is the ON CONFLICT
-- target for the upsert in internal/extractor/upsert.go.
CREATE UNIQUE INDEX known_app_bundles_name_platform_uq
    ON known_app_bundles (LOWER(name), platform);

-- Populated via upsert on every inventory ingest (internal/extractor/upsert.go);
-- read by GET /v1/allowlist/pending-removals (internal/handlers/allowlist_agent.go).
GRANT SELECT, INSERT, UPDATE ON known_app_bundles TO patched;

INSERT INTO schema_migrations (version) VALUES ('0076_known_app_bundles')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
