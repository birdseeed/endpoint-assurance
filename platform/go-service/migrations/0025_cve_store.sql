BEGIN;

-- ─── CVE store — PAT-335 ─────────────────────────────────────────────────────
-- Three tables:
--   cve_feed_entries    — NVD CVE records synced by patched-cve-sync
--   app_cpe_mappings    — app name → CPE vendor/product lookup (seeded, curated)
--   device_cve_findings — pre-matched results; refreshed by patched-cve-sync
--
-- Matching strategy: word-token match against app display name → CPE product
-- prefilter (GIN index on cpe_patterns) → version-range gate
-- (cpe_ranges JSONB) → confidence: "version_confirmed" or "version_unverified".

CREATE TABLE cve_feed_entries (
    cve_id              TEXT PRIMARY KEY,              -- e.g. CVE-2024-12345
    description         TEXT NOT NULL DEFAULT '',
    cvss_v3_score       NUMERIC(4,1),                  -- NULL = no CVSS v3
    cvss_v3_vector      TEXT,
    severity            TEXT,                          -- CRITICAL/HIGH/MEDIUM/LOW/NONE
    cpe_patterns        TEXT[] NOT NULL DEFAULT '{}',  -- normalised "vendor:product" keys
    cpe_ranges          JSONB  NOT NULL DEFAULT '[]',  -- per-product version bounds array
    published_at        TIMESTAMPTZ,
    modified_at         TIMESTAMPTZ,
    synced_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cve_feed_severity   ON cve_feed_entries (severity);
CREATE INDEX idx_cve_feed_modified   ON cve_feed_entries (modified_at DESC);
CREATE INDEX idx_cve_feed_cpe_gin    ON cve_feed_entries USING GIN (cpe_patterns);

-- Curated mapping: app display name → NVD CPE vendor + product.
-- match_name is matched as word-tokens against device_apps.name
-- (substring matching intentionally avoided to prevent Box→Dropbox collisions).
-- One app may have multiple rows (e.g. different CPE vendor names across NVD).
CREATE TABLE app_cpe_mappings (
    id          BIGSERIAL PRIMARY KEY,
    platform    TEXT NOT NULL DEFAULT 'any',       -- macos / windows / any
    match_name  TEXT NOT NULL,                     -- word-token match key
    cpe_vendor  TEXT NOT NULL,
    cpe_product TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_cpe_mappings_platform ON app_cpe_mappings (platform);

-- Pre-computed match results — refreshed nightly or on demand.
-- Avoids repeated cross-joins for the API read path.
-- match_confidence distinguishes version-confirmed findings from unverified ones
-- where NVD lacks usable version-range data.
CREATE TABLE device_cve_findings (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cve_id              TEXT NOT NULL REFERENCES cve_feed_entries(cve_id) ON DELETE CASCADE,
    app_name            TEXT NOT NULL,
    app_version         TEXT NOT NULL DEFAULT '',
    cvss_v3_score       NUMERIC(4,1),
    severity            TEXT,
    match_confidence    TEXT NOT NULL DEFAULT 'version_unverified',
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, cve_id, app_name)
);

CREATE INDEX idx_dcvef_device      ON device_cve_findings (device_id);
CREATE INDEX idx_dcvef_cve         ON device_cve_findings (cve_id);
CREATE INDEX idx_dcvef_severity    ON device_cve_findings (severity);
CREATE INDEX idx_dcvef_confidence  ON device_cve_findings (match_confidence);

-- ─── Seed: app_cpe_mappings ───────────────────────────────────────────────────
-- macOS + Windows commercial apps commonly found in managed estates.
-- Source: NVD CPE dictionary (cpe.mitre.org).
-- match_name uses the full app display name to avoid substring collisions:
--   "Box" would substring-match "Dropbox" — so Dropbox has its own row.
--   "Git" would substring-match "GitHub Desktop" — so GitHub Desktop is explicit.

INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product) VALUES
-- Browsers
('any',     'Google Chrome',        'google',            'chrome'),
('any',     'Firefox',              'mozilla',           'firefox'),
('macos',   'Safari',               'apple',             'safari'),
('any',     'Microsoft Edge',       'microsoft',         'edge'),
('any',     'Brave Browser',        'brave',             'brave'),
('any',     'Opera',                'opera',             'opera_browser'),
-- Conferencing / comms
('any',     'Zoom',                 'zoom',              'zoom'),
('any',     'Microsoft Teams',      'microsoft',         'teams'),
('any',     'Slack',                'slack',             'slack'),
('any',     'Webex',                'cisco',             'webex'),
('any',     'Discord',              'discord',           'discord'),
-- Office / productivity
('windows', 'Microsoft Office',     'microsoft',         'office'),
('windows', 'Microsoft Word',       'microsoft',         'word'),
('windows', 'Microsoft Excel',      'microsoft',         'excel'),
('windows', 'Microsoft PowerPoint', 'microsoft',         'powerpoint'),
('windows', 'Microsoft Outlook',    'microsoft',         'outlook'),
('any',     'Adobe Acrobat',        'adobe',             'acrobat'),
('any',     'Adobe Reader',         'adobe',             'acrobat_reader'),
('any',     'Adobe Photoshop',      'adobe',             'photoshop'),
('any',     '1Password',            'agilebits',         '1password'),
-- Dev tools
('any',     'Visual Studio Code',   'microsoft',         'visual_studio_code'),
('any',     'IntelliJ IDEA',        'jetbrains',         'intellij_idea'),
('any',     'PyCharm',              'jetbrains',         'pycharm'),
('any',     'Docker Desktop',       'docker',            'docker_desktop'),
('any',     'Git',                  'git',               'git'),
('any',     'GitHub Desktop',       'github',            'github_desktop'),
('any',     'Node.js',              'nodejs',            'node.js'),
('any',     'Python',               'python',            'python'),
('any',     'OpenSSH',              'openbsd',           'openssh'),
-- Remote access
('any',     'TeamViewer',           'teamviewer',        'teamviewer'),
('any',     'AnyDesk',              'anydesk',           'anydesk'),
('any',     'Royal TSX',            'royalapplications', 'royal_tsx'),
-- Security
('any',     'Malwarebytes',         'malwarebytes',      'malwarebytes'),
-- Cloud storage
('any',     'Dropbox',              'dropbox',           'dropbox'),
('any',     'Box',                  'box',               'box'),
('any',     'OneDrive',             'microsoft',         'onedrive'),
('any',     'Google Drive',         'google',            'backup_and_sync_from_google'),
-- macOS OS components
('macos',   'macOS',                'apple',             'macos'),
('macos',   'macOS',                'apple',             'mac_os_x'),
-- Windows OS components
('windows', 'Windows',              'microsoft',         'windows_10'),
('windows', 'Windows',              'microsoft',         'windows_11'),
-- Java runtimes (high CVE surface)
('any',     'Java',                 'oracle',            'jre'),
('any',     'Java',                 'oracle',            'jdk'),
('any',     'OpenJDK',              'oracle',            'openjdk'),
-- VPN
('any',     'Cisco AnyConnect',     'cisco',             'anyconnect_secure_mobility_client'),
('any',     'GlobalProtect',        'paloaltonetworks',  'globalprotect'),
('any',     'Tunnelblick',          'tunnelblick',       'tunnelblick');

INSERT INTO schema_migrations (version) VALUES ('0025_cve_store');

COMMIT;
