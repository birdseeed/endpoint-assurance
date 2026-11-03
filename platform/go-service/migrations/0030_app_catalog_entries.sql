-- patched.im — 0030_app_catalog_entries.sql
-- PAT-472: app catalog table — source of truth for known-good latest versions.
--
-- The updater publishes a catalog of verified-safe apps with their latest
-- audited version. This table is a server-side projection of that catalog,
-- kept separate from device_apps (what is installed) so the comparison is
-- always platform → catalog, never agent-supplied → platform.
--
-- One-way read: the platform reads this table; no agent can write it.
-- Populated by admin import (patched-catalog-sync worker, future PAT) or
-- manual INSERT; seeded below with the current catalog.json snapshot.
--
-- JOIN surface for GET /v1/posture updates:
--   device_apps.team_id = app_catalog_entries.verified_signer   (macOS)
--   OR device_apps.name = app_catalog_entries.name              (fallback / Windows)
--
-- DEPLOY ORDERING: apply before deploying the binary that reads it.
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0030_app_catalog_entries.sql
--
-- KNOWN LIMITATION (noted PAT-1561, 2026-09-11, not fixed here): this table
-- has had no automated refresh since it was seeded — it is still exactly the
-- catalog.json snapshot above, never refreshed since it was seeded.
-- grep -rn "INSERT INTO app_catalog_entries|UPDATE app_catalog_entries" across
-- the Go codebase returns zero write sites; "populated by admin import
-- (patched-catalog-sync worker, future PAT)" above was never built. It is
-- still read live by GET /v1/posture (fetchUpdateAvailability),
-- needs_attention.go, report.go and tenant_apps.go for "available update"
-- comparisons, so it cannot simply be dropped.
--
-- ADR-0011 §9 asks for this to become "a read-only projection of verified
-- global-catalogue releases" once the successor catalogue model exists. That
-- is not buildable yet: catalogue_platform_targets (the ADR-0011 successor
-- table PAT-1556 backfilled identity into) has no version-tracking field at
-- all — identity/delivery_mode/signer_provenance/state, none of them a
-- "latest known-good version". There is currently no live data source to
-- project latest_version from without inventing a new version-tracking
-- capability in the catalogue domain, which is a real feature, not a cleanup.
-- Left as an explicit, tracked gap rather than solved here.

BEGIN;

-- ============================================================================
-- SCHEMA

CREATE TABLE app_catalog_entries (
    id              BIGSERIAL    PRIMARY KEY,
    label           TEXT         NOT NULL UNIQUE,  -- Installomator label (macOS) / winget id (Windows)
    name            TEXT         NOT NULL,          -- display name; matches device_apps.name
    category        TEXT,
    platform        TEXT         NOT NULL DEFAULT 'macOS' CHECK (platform IN ('macOS', 'Windows')),
    verified_signer TEXT,                           -- Team ID (macOS) / Authenticode publisher (Windows)
    latest_version  TEXT         NOT NULL,          -- latest audited/known-good version
    source          TEXT         NOT NULL DEFAULT 'catalog' CHECK (source IN ('catalog', 'manual')),
    verified_at     TIMESTAMPTZ  NOT NULL,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Lookup by signer (precise macOS match) or by name (fallback / Windows).
CREATE INDEX app_catalog_entries_signer_idx   ON app_catalog_entries (verified_signer) WHERE verified_signer IS NOT NULL;
CREATE INDEX app_catalog_entries_name_idx     ON app_catalog_entries (name, platform);

-- ============================================================================
-- SEED — catalog.json snapshot (updater/menubar/dev-fixtures/catalog.json)

INSERT INTO app_catalog_entries (label, name, category, platform, verified_signer, latest_version, verified_at) VALUES
    ('googlechrome',   'Google Chrome',     'Browsers',     'macOS', 'EQHXZ8M8AV', '126.0.6478.127', '2026-08-10 09:00:00+00'),
    ('firefox',        'Mozilla Firefox',   'Browsers',     'macOS', '43AQ936H96', '127.0',           '2026-08-10 09:00:00+00'),
    ('slack',          'Slack',             'Productivity', 'macOS', 'BQR82RBBHL', '4.38.125',        '2026-08-10 09:00:00+00'),
    ('zoom',           'Zoom',              'Productivity', 'macOS', 'BJ4HAAB9B3', '6.1.6.41824',     '2026-08-10 09:00:00+00'),
    ('1password7',     '1Password 7',       'Security',     'macOS', '2BUA8C4S2C', '7.9.11',          '2026-08-10 09:00:00+00'),
    ('1password8',     '1Password 8',       'Security',     'macOS', '2BUA8C4S2C', '8.10.44',         '2026-08-10 09:00:00+00'),
    ('microsoftedge',  'Microsoft Edge',    'Browsers',     'macOS', 'UBF8T346G9', '126.0.2592.68',   '2026-08-10 09:00:00+00'),
    ('microsoftteams', 'Microsoft Teams',   'Productivity', 'macOS', 'UBF8T346G9', '24134.3004.2974', '2026-08-10 09:00:00+00'),
    ('microsoftword',  'Microsoft Word',    'Office',       'macOS', 'UBF8T346G9', '16.86.24061613',  '2026-08-10 09:00:00+00'),
    ('microsoftexcel', 'Microsoft Excel',   'Office',       'macOS', 'UBF8T346G9', '16.86.24061613',  '2026-08-10 09:00:00+00'),
    ('microsoftpowerpoint', 'Microsoft PowerPoint', 'Office', 'macOS', 'UBF8T346G9', '16.86.24061613', '2026-08-10 09:00:00+00'),
    ('microsoftoutlook', 'Microsoft Outlook', 'Office',     'macOS', 'UBF8T346G9', '16.86.24061613',  '2026-08-10 09:00:00+00'),
    ('vscodium',       'VSCodium',          'Development',  'macOS', 'DAFVSXLPR2', '1.90.0.24163',    '2026-08-10 09:00:00+00'),
    ('visualstudiocode', 'Visual Studio Code', 'Development', 'macOS', 'UBF8T346G9', '1.90.2',        '2026-08-10 09:00:00+00'),
    ('docker',         'Docker Desktop',    'Development',  'macOS', '9BNSXJN65R', '4.31.1',          '2026-08-10 09:00:00+00'),
    ('zoom_win',       'Zoom',              'Productivity', 'Windows', NULL,         '6.1.6.41824',    '2026-08-10 09:00:00+00')
ON CONFLICT (label) DO NOTHING;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0030_app_catalog_entries');

COMMIT;
