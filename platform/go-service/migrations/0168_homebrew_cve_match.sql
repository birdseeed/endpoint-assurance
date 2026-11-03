-- 0168: CVE matching for Homebrew formulae and casks (PAT-2023)
--
-- Homebrew has no CPE or OSV ecosystem, and a formula name or cask token is
-- package-namespace evidence, not a product identity. A Homebrew package
-- therefore reaches a CVE only through an explicit app_cpe_mappings row keyed
-- by its exact formula name or cask token.
--
--   app_cpe_mappings.source_type   'app_name' (every existing row: word-token
--                                  match against application display names,
--                                  unchanged), 'homebrew_formula' or
--                                  'homebrew_cask' (exact, case-insensitive
--                                  match on the formula name or cask token).
--                                  Every application-path reader filters on
--                                  source_type = 'app_name', so a Homebrew row
--                                  can never word-token match an app.
--   app_cpe_mappings.review_state  'curated' (entered or approved by a person)
--                                  or 'auto_seeded'. Only curated rows match.
--                                  Nothing writes 'auto_seeded'; it is kept in
--                                  the enum for the review work in PAT-2046.
--   device_cve_findings            optional Homebrew evidence columns. NULL on
--                                  application and OS findings, so the shared
--                                  finding shape is unchanged for them.
--   homebrew_cpe_review_queue      global review queue of formulae and casks
--                                  from homebrew/core or homebrew/cask with no
--                                  mapping. No tenant or device identifier;
--                                  never a package with no recorded tap or
--                                  from a third-party tap.
--
-- Deviation from PAT-2023 as written, for security (review 2026-09-23): the
-- ticket auto-accepts exact homepage / source URL matches as mappings. Those
-- URLs are endpoint-reported and a mapping applies to every tenant, so one
-- tenant's payload could re-map a formula estate-wide. An exact match is
-- stored only as suggested_cpe_key on the review row and produces no
-- finding until a person curates it (PAT-2046). The first-seen homepage,
-- source URL and suggestion are kept; a later disagreeing report sets
-- metadata_conflict and increments metadata_conflict_count.
--
-- Seed: curated mappings for official formulae whose NVD vendor:product was
-- checked against the NVD CPE API on 2026-09-23. curl maps to both haxx:curl
-- and haxx:libcurl because NVD files libcurl CVEs (CVE-2023-38545 among
-- them) under libcurl only, and the curl formula ships libcurl.
-- openssl@1.1 is deliberately not seeded: its letter releases (1.1.1t) are
-- beyond the numeric version comparator, which would under-report.
--
-- Additive only. Existing rows keep their meaning through the defaults.
BEGIN;

-- Reconcile patched-api-01 first (PAT-2051). Its app_cpe_mappings was built
-- from a pre-merge draft of 0025: no platform or notes column, and
-- UNIQUE(match_name). 0025 is recorded as applied there, so the merged
-- definition never ran. Bring the table to the migrations' shape before
-- anything below relies on it. Every step is a no-op on a database built
-- from the migrations. Nothing reads or conflicts on the match_name key, and
-- the seed below needs two curl rows.
ALTER TABLE app_cpe_mappings
    ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'any',
    ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_cpe_mappings_platform ON app_cpe_mappings (platform);
ALTER TABLE app_cpe_mappings DROP CONSTRAINT IF EXISTS app_cpe_mappings_match_name_key;

ALTER TABLE app_cpe_mappings
    ADD COLUMN source_type TEXT NOT NULL DEFAULT 'app_name'
        CONSTRAINT app_cpe_mappings_source_type_check
        CHECK (source_type IN ('app_name', 'homebrew_formula', 'homebrew_cask')),
    ADD COLUMN review_state TEXT NOT NULL DEFAULT 'curated'
        CONSTRAINT app_cpe_mappings_review_state_check
        CHECK (review_state IN ('curated', 'auto_seeded'));

-- One row per Homebrew key and CPE pair.
CREATE UNIQUE INDEX app_cpe_mappings_homebrew_uq
    ON app_cpe_mappings (source_type, lower(match_name), cpe_vendor, cpe_product)
    WHERE source_type <> 'app_name';

ALTER TABLE device_cve_findings
    ADD COLUMN package_source TEXT
        CONSTRAINT device_cve_findings_package_source_check
        CHECK (package_source IN ('homebrew_formula', 'homebrew_cask')),
    ADD COLUMN package_name TEXT,
    ADD COLUMN install_reason TEXT
        CONSTRAINT device_cve_findings_install_reason_check
        CHECK (install_reason IN ('on_request', 'dependency', 'unknown')),
    ADD COLUMN required_by TEXT[],
    ADD COLUMN mapping_basis TEXT
        CONSTRAINT device_cve_findings_mapping_basis_check
        CHECK (mapping_basis IN ('curated', 'auto_seeded')),
    ADD COLUMN confidence_tier TEXT
        CONSTRAINT device_cve_findings_confidence_tier_check
        CHECK (confidence_tier IN ('high', 'medium', 'low'));

COMMENT ON COLUMN device_cve_findings.package_source IS
    'PAT-2023: homebrew_formula or homebrew_cask for a Homebrew package finding; NULL for application and OS findings.';
COMMENT ON COLUMN device_cve_findings.install_reason IS
    'PAT-2023: on_request, dependency or unknown, from the Homebrew receipt. NULL outside Homebrew.';
COMMENT ON COLUMN device_cve_findings.required_by IS
    'PAT-2023: formulae on the same device whose receipts list this one as a runtime dependency. NULL outside Homebrew.';
COMMENT ON COLUMN device_cve_findings.confidence_tier IS
    'PAT-2023: high (curated mapping, version in NVD range) or low (version not confirmable: no range data, HEAD build, letter-suffixed or unparseable version). medium is reserved and never produced: only curated mappings match. NULL outside Homebrew.';

CREATE TABLE homebrew_cpe_review_queue (
    id                 BIGSERIAL PRIMARY KEY,
    package_kind       TEXT NOT NULL CHECK (package_kind IN ('formula', 'cask')),
    -- formula name or cask token, lowercased
    name               TEXT NOT NULL CHECK (btrim(name) <> '' AND name = lower(name)),
    homepage           TEXT,
    source_url         TEXT,
    status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'mapped', 'dismissed')),
    -- An exact NVD "vendor:product" key the first-seen metadata points at.
    -- A suggestion for a person, never a mapping.
    suggested_cpe_key  TEXT CHECK (suggested_cpe_key IS NULL OR suggested_cpe_key ~ '^[^:]+:[^:]+$'),
    metadata_conflict        BOOLEAN NOT NULL DEFAULT false,
    metadata_conflict_count  INT NOT NULL DEFAULT 0 CHECK (metadata_conflict_count >= 0),
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at        TIMESTAMPTZ,
    UNIQUE (package_kind, name)
);
CREATE INDEX homebrew_cpe_review_queue_status_idx
    ON homebrew_cpe_review_queue (status, last_seen_at DESC);

COMMENT ON TABLE homebrew_cpe_review_queue IS
    'PAT-2023: official-tap Homebrew formulae and casks with no CPE mapping, for review. Global; carries no tenant or device identifier.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE homebrew_cpe_review_queue TO patched;
GRANT USAGE, SELECT ON SEQUENCE homebrew_cpe_review_queue_id_seq TO patched;

INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
VALUES
    ('macos', 'openssl@3', 'openssl',  'openssl', 'PAT-2023 curated; NVD key verified 2026-09-23', 'homebrew_formula', 'curated'),
    ('macos', 'curl',      'haxx',     'curl',    'PAT-2023 curated; NVD key verified 2026-09-23', 'homebrew_formula', 'curated'),
    ('macos', 'curl',      'haxx',     'libcurl', 'PAT-2023 curated; the formula ships libcurl, whose CVEs NVD files under libcurl; verified 2026-09-23', 'homebrew_formula', 'curated'),
    ('macos', 'sqlite',    'sqlite',   'sqlite',  'PAT-2023 curated; NVD key verified 2026-09-23', 'homebrew_formula', 'curated'),
    ('macos', 'libxml2',   'xmlsoft',  'libxml2', 'PAT-2023 curated; NVD key verified 2026-09-23', 'homebrew_formula', 'curated'),
    ('macos', 'git',       'git-scm',  'git',     'PAT-2023 curated; NVD key verified 2026-09-23', 'homebrew_formula', 'curated')
ON CONFLICT DO NOTHING;

INSERT INTO schema_migrations (version) VALUES ('0168_homebrew_cve_match')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
