-- 0196: software lifecycle (end of support) data and reviewed product
-- mappings, for the SAM unsupported software report (PAT-2147, child of
-- PAT-2146).
--
-- NUMBERING: 0196 was chosen because other branches hold 0193 and 0194 at
-- the time of writing. Renumber at merge if 0195/0196 are taken; nothing in
-- Go refers to the number, only the schema_migrations row below.
--
--   lifecycle_products        one row per endoflife.date product slug the
--                             fetcher has tried: when it last succeeded
--                             (fetched_at, "last checked" on every report
--                             row), the last error, and the source URLs.
--                             Global: no tenant data.
--   lifecycle_cycles          the product's release cycles as last fetched
--                             (release date, end of support date or flag,
--                             end of active support, extended support,
--                             latest version). Replaced wholesale on a
--                             successful fetch, never partially.
--   lifecycle_mappings        a reviewed link from one canonical product
--                             identity (platform, identity kind, normalised
--                             identifier and companion, the same key
--                             software_installations carries) to an
--                             endoflife.date slug plus a version-to-cycle
--                             rule. proposed | published | rejected. Only
--                             published mappings drive customer output.
--   lifecycle_mapping_audit   append-only who/when/before/after for every
--                             mapping change.
--
-- The operating-system rows use identity_kind 'os' with the platform as the
-- identifier. They are seeded published: the device's own OS version (macOS
-- major version) or build number (Windows) selects the cycle
-- deterministically, see internal/lifecycle. Every application row is seeded
-- proposed and changes nothing a customer sees until staff publish it.
--
-- Additive only: new tables, no existing table touched.
BEGIN;

CREATE TABLE lifecycle_products (
    slug               TEXT PRIMARY KEY CHECK (slug ~ '^[a-z0-9][a-z0-9._+-]{0,99}$'),
    label              TEXT CHECK (label IS NULL OR char_length(label) <= 200),
    api_url            TEXT NOT NULL CHECK (api_url LIKE 'https://%' OR api_url LIKE 'http://%'),
    html_url           TEXT CHECK (html_url IS NULL OR html_url LIKE 'https://endoflife.date/%'),
    schema_version     TEXT CHECK (schema_version IS NULL OR char_length(schema_version) <= 20),
    api_last_modified  TEXT CHECK (api_last_modified IS NULL OR char_length(api_last_modified) <= 40),
    -- When the last successful fetch completed. NULL until one has.
    fetched_at         TIMESTAMPTZ,
    last_attempt_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error         TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 500),
    cycle_count        INT NOT NULL DEFAULT 0 CHECK (cycle_count >= 0),
    CHECK (fetched_at IS NOT NULL OR cycle_count = 0)
);

COMMENT ON TABLE lifecycle_products IS
    'PAT-2147: endoflife.date products the lifecycle fetcher has tried. fetched_at is the last successful fetch; data older than 7 days is stale and every report row using it reads Unknown. Global, no tenant data.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle_products TO patched;

CREATE TABLE lifecycle_cycles (
    slug                   TEXT NOT NULL REFERENCES lifecycle_products(slug) ON DELETE CASCADE,
    cycle                  TEXT NOT NULL CHECK (cycle <> '' AND char_length(cycle) <= 100),
    label                  TEXT CHECK (label IS NULL OR char_length(label) <= 200),
    release_date           DATE,
    -- End of (security) support: a date when the source gives one, and the
    -- source's own boolean as it stood at fetch time. A NULL date with
    -- is_eol false means "maintained, no end date announced".
    eol_date               DATE,
    is_eol                 BOOLEAN,
    -- End of active support, where the source separates it.
    support_date           DATE,
    -- End of paid extended support (for example Windows ESU), informational.
    extended_support_date  DATE,
    latest_version         TEXT CHECK (latest_version IS NULL OR char_length(latest_version) <= 100),
    is_lts                 BOOLEAN NOT NULL DEFAULT false,
    fetched_at             TIMESTAMPTZ NOT NULL,
    source_url             TEXT NOT NULL,
    PRIMARY KEY (slug, cycle)
);

COMMENT ON TABLE lifecycle_cycles IS
    'PAT-2147: release cycles for one endoflife.date product as last fetched. Replaced as a whole on each successful fetch.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle_cycles TO patched;

CREATE TABLE lifecycle_mappings (
    id                         BIGSERIAL PRIMARY KEY,
    platform                   TEXT NOT NULL CHECK (platform IN ('macos', 'windows')),
    -- software_installations.identity_kind, or 'os' for the operating system.
    identity_kind              TEXT NOT NULL CHECK (identity_kind IN (
                                   'os', 'macos_bundle_team', 'macos_bundle', 'windows_winget',
                                   'windows_native_publisher', 'windows_native',
                                   'homebrew_formula', 'homebrew_cask')),
    identity_value_normalized  TEXT NOT NULL CHECK (btrim(identity_value_normalized) <> ''
                                   AND char_length(identity_value_normalized) <= 512),
    -- Exact companion (Team ID, publisher, tap). '' when the identity has none.
    companion_value_normalized TEXT NOT NULL DEFAULT '' CHECK (char_length(companion_value_normalized) <= 512),
    eol_slug                   TEXT NOT NULL CHECK (eol_slug ~ '^[a-z0-9][a-z0-9._+-]{0,99}$'),
    version_rule               TEXT NOT NULL CHECK (version_rule IN (
                                   'major', 'major_minor', 'regex', 'macos_major', 'windows_build')),
    version_regex              TEXT CHECK (version_regex IS NULL OR char_length(version_regex) <= 200),
    status                     TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'published', 'rejected')),
    notes                      TEXT NOT NULL DEFAULT '' CHECK (char_length(notes) <= 1000),
    proposed_by                TEXT NOT NULL,
    proposed_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by                TEXT,
    reviewed_at                TIMESTAMPTZ,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT lifecycle_mappings_regex_rule
        CHECK ((version_rule = 'regex') = (version_regex IS NOT NULL)),
    CONSTRAINT lifecycle_mappings_os_rule CHECK (
        (identity_kind = 'os') = (version_rule IN ('macos_major', 'windows_build'))
        AND (identity_kind <> 'os' OR identity_value_normalized = platform)
        AND (version_rule <> 'macos_major' OR platform = 'macos')
        AND (version_rule <> 'windows_build' OR platform = 'windows')),
    CONSTRAINT lifecycle_mappings_platform_kind CHECK (
        (identity_kind NOT IN ('macos_bundle_team', 'macos_bundle', 'homebrew_formula', 'homebrew_cask') OR platform = 'macos')
        AND (identity_kind NOT IN ('windows_winget', 'windows_native_publisher', 'windows_native') OR platform = 'windows')),
    CONSTRAINT lifecycle_mappings_reviewed CHECK (
        (status = 'proposed') = (reviewed_at IS NULL)
        AND (reviewed_at IS NULL) = (reviewed_by IS NULL))
);
-- One live (proposed or published) mapping per canonical product identity.
CREATE UNIQUE INDEX lifecycle_mappings_live_uq
    ON lifecycle_mappings (platform, identity_kind, identity_value_normalized, companion_value_normalized)
    WHERE status <> 'rejected';
CREATE INDEX lifecycle_mappings_status_idx ON lifecycle_mappings (status, eol_slug);

COMMENT ON TABLE lifecycle_mappings IS
    'PAT-2147: reviewed canonical product identity -> endoflife.date slug + version-to-cycle rule. Only published rows affect customer output; proposed rows are refreshed by the fetcher so staff can review against real cycle data. Global, no tenant data.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle_mappings TO patched;
GRANT USAGE, SELECT ON SEQUENCE lifecycle_mappings_id_seq TO patched;

CREATE TABLE lifecycle_mapping_audit (
    id            BIGSERIAL PRIMARY KEY,
    mapping_id    BIGINT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('seed', 'propose', 'publish', 'reject', 'withdraw')),
    actor         TEXT NOT NULL,
    claimed_actor TEXT,
    source_addr   TEXT,
    before        JSONB,
    after         JSONB NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX lifecycle_mapping_audit_mapping_idx ON lifecycle_mapping_audit (mapping_id, at);

-- Same append-only shape, and the same known limitation, as
-- homebrew_review_audit (0176) and cpe_mapping_proposal_audit (0192): the
-- triggers stop an accidental write, not the owning role.
CREATE FUNCTION reject_lifecycle_mapping_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'lifecycle_mapping_audit is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_lifecycle_mapping_audit_reject_update
    BEFORE UPDATE OR DELETE ON lifecycle_mapping_audit
    FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_mapping_audit_mutation();
CREATE TRIGGER trg_lifecycle_mapping_audit_reject_truncate
    BEFORE TRUNCATE ON lifecycle_mapping_audit
    FOR EACH STATEMENT EXECUTE FUNCTION reject_lifecycle_mapping_audit_mutation();

COMMENT ON TABLE lifecycle_mapping_audit IS
    'PAT-2147: append-only audit of every lifecycle mapping change (seed, propose, publish, reject, withdraw).';

GRANT SELECT, INSERT ON lifecycle_mapping_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE lifecycle_mapping_audit_id_seq TO patched;

-- Seed. Slugs were checked against the live endoflife.date API
-- (https://endoflife.date/api/v1/products/<slug>/, schema_version 1.2.1) on
-- 2026-09-25; each one returned 200. Identifiers:
--   * macOS bundle identifier + Team ID: Team IDs as recorded with evidence
--     in cpe_vendor_aliases (0192): Google EQHXZ8M8AV, Mozilla 43AQ936H96.
--   * Windows winget package identifiers: each was checked to exist in
--     microsoft/winget-pkgs (manifests/<letter>/<publisher>/<package>) on
--     2026-09-25, and a sample of its version directories was read to pick
--     the rule (Corretto 8 versions read 1.8.0.x, hence its regex).
-- Not seeded, and why: Microsoft Edge, Adobe Acrobat, Zoom have no
-- endoflife.date product (404 on 2026-09-25). Microsoft Office has one
-- (slug 'office'), but Office 2019, 2021, 2024 and Microsoft 365 share
-- bundle and package identifiers and version strings, so no rule can pick
-- the cycle from the installed version.
INSERT INTO lifecycle_mappings
    (platform, identity_kind, identity_value_normalized, companion_value_normalized,
     eol_slug, version_rule, version_regex, status, notes, proposed_by, reviewed_by, reviewed_at)
VALUES
    -- Operating systems: published (deterministic from device OS data).
    ('macos', 'os', 'macos', '', 'macos', 'macos_major', NULL, 'published',
     'macOS major version selects the cycle (10.x uses major.minor, e.g. 10.15).',
     'migration:0196', 'migration:0196', now()),
    ('windows', 'os', 'windows', '', 'windows', 'windows_build', NULL, 'published',
     'Build number (10.0.BUILD) selects the feature release; the edition from the OS caption selects between the Enterprise/Education and Home/Pro cycles. Unknown when the edition is not reported and the editions'' dates differ.',
     'migration:0196', 'migration:0196', now()),
    -- Browsers.
    ('macos', 'macos_bundle_team', 'com.google.chrome', 'EQHXZ8M8AV', 'chrome', 'major', NULL, 'proposed',
     'Google Chrome for macOS. Chrome supports only its newest major release.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'google.chrome', '', 'chrome', 'major', NULL, 'proposed',
     'Google Chrome, winget Google.Chrome.', 'migration:0196', NULL, NULL),
    ('macos', 'macos_bundle_team', 'org.mozilla.firefox', '43AQ936H96', 'firefox', 'major', NULL, 'proposed',
     'Mozilla Firefox for macOS (rapid release; ESR has the same identifier and is not distinguished).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'mozilla.firefox', '', 'firefox', 'major', NULL, 'proposed',
     'Mozilla Firefox, winget Mozilla.Firefox.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'mozilla.firefox.en-gb', '', 'firefox', 'major', NULL, 'proposed',
     'Mozilla Firefox (en-GB), winget Mozilla.Firefox.en-GB.', 'migration:0196', NULL, NULL),
    -- Java distributions (winget identifiers are per major version).
    ('windows', 'windows_winget', 'eclipseadoptium.temurin.8.jdk', '', 'eclipse-temurin', 'major', NULL, 'proposed', 'Eclipse Temurin 8 JDK (versions 8.0.x).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'eclipseadoptium.temurin.11.jdk', '', 'eclipse-temurin', 'major', NULL, 'proposed', 'Eclipse Temurin 11 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'eclipseadoptium.temurin.17.jdk', '', 'eclipse-temurin', 'major', NULL, 'proposed', 'Eclipse Temurin 17 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'eclipseadoptium.temurin.21.jdk', '', 'eclipse-temurin', 'major', NULL, 'proposed', 'Eclipse Temurin 21 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'eclipseadoptium.temurin.25.jdk', '', 'eclipse-temurin', 'major', NULL, 'proposed', 'Eclipse Temurin 25 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'amazon.corretto.8.jdk', '', 'amazon-corretto', 'regex', '^1\.(8)\.', 'proposed', 'Amazon Corretto 8 JDK (versions 1.8.0.x map to cycle 8).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'amazon.corretto.11.jdk', '', 'amazon-corretto', 'major', NULL, 'proposed', 'Amazon Corretto 11 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'amazon.corretto.17.jdk', '', 'amazon-corretto', 'major', NULL, 'proposed', 'Amazon Corretto 17 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'amazon.corretto.21.jdk', '', 'amazon-corretto', 'major', NULL, 'proposed', 'Amazon Corretto 21 JDK.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'microsoft.openjdk.11', '', 'microsoft-build-of-openjdk', 'major', NULL, 'proposed', 'Microsoft Build of OpenJDK 11.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'microsoft.openjdk.17', '', 'microsoft-build-of-openjdk', 'major', NULL, 'proposed', 'Microsoft Build of OpenJDK 17.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'microsoft.openjdk.21', '', 'microsoft-build-of-openjdk', 'major', NULL, 'proposed', 'Microsoft Build of OpenJDK 21.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'microsoft.openjdk.25', '', 'microsoft-build-of-openjdk', 'major', NULL, 'proposed', 'Microsoft Build of OpenJDK 25.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'oracle.jdk.17', '', 'oracle-jdk', 'major', NULL, 'proposed', 'Oracle JDK 17.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'oracle.jdk.21', '', 'oracle-jdk', 'major', NULL, 'proposed', 'Oracle JDK 21.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'oracle.jdk.25', '', 'oracle-jdk', 'major', NULL, 'proposed', 'Oracle JDK 25.', 'migration:0196', NULL, NULL),
    -- Language runtimes.
    ('windows', 'windows_winget', 'python.python.3.10', '', 'python', 'major_minor', NULL, 'proposed', 'Python 3.10 (python.org).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'python.python.3.11', '', 'python', 'major_minor', NULL, 'proposed', 'Python 3.11 (python.org).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'python.python.3.12', '', 'python', 'major_minor', NULL, 'proposed', 'Python 3.12 (python.org).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'python.python.3.13', '', 'python', 'major_minor', NULL, 'proposed', 'Python 3.13 (python.org).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'python.python.3.14', '', 'python', 'major_minor', NULL, 'proposed', 'Python 3.14 (python.org).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'openjs.nodejs', '', 'nodejs', 'major', NULL, 'proposed', 'Node.js (current), winget OpenJS.NodeJS.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'openjs.nodejs.lts', '', 'nodejs', 'major', NULL, 'proposed', 'Node.js LTS, winget OpenJS.NodeJS.LTS.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'php.php.8.3', '', 'php', 'major_minor', NULL, 'proposed', 'PHP 8.3.', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'php.php.8.4', '', 'php', 'major_minor', NULL, 'proposed', 'PHP 8.4.', 'migration:0196', NULL, NULL),
    -- Other common software with an endoflife.date product.
    ('windows', 'windows_winget', 'microsoft.powershell', '', 'powershell', 'major_minor', NULL, 'proposed', 'PowerShell 7 (not Windows PowerShell 5.1).', 'migration:0196', NULL, NULL),
    ('windows', 'windows_winget', 'thedocumentfoundation.libreoffice', '', 'libreoffice', 'major_minor', NULL, 'proposed', 'LibreOffice.', 'migration:0196', NULL, NULL)
ON CONFLICT DO NOTHING;

INSERT INTO lifecycle_mapping_audit (mapping_id, action, actor, after)
SELECT id, 'seed', 'migration:0196',
       jsonb_build_object('status', status, 'eol_slug', eol_slug, 'version_rule', version_rule,
                          'platform', platform, 'identity_kind', identity_kind,
                          'identity_value_normalized', identity_value_normalized,
                          'companion_value_normalized', companion_value_normalized)
FROM lifecycle_mappings WHERE proposed_by = 'migration:0196';

INSERT INTO schema_migrations (version) VALUES ('0196_software_lifecycle')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
