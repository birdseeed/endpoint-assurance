-- patched.im - 0169_app_cpe_mappings_seed_parity.sql
-- PAT-2047, rescoped after discovering PAT-2051's finding: patched-api-01's
-- app_cpe_mappings was built from a pre-merge draft of 0025 (id/match_name/
-- cpe_vendor/cpe_product/created_at, UNIQUE(match_name)). 0025 is recorded
-- as applied there, so the merged 47-row seed never ran. Prod holds only 9
-- rows (audited 2026-09-23), so application CVE matching has covered only
-- those 9 products since it was seeded. 0168 (PAT-2051) reconciles the table shape;
-- this migration reconciles the data.
--
-- Idempotent by design: for every candidate row, insert it only if no row
-- already exists with the same (case-insensitive match_name, cpe_vendor,
-- cpe_product). On a migrations-built database (already carrying all of
-- 0025's 47 rows) this is a no-op except for adding the git-scm:git row
-- PAT-2047 already established is needed alongside git:git. On prod it adds
-- the missing rows plus whatever of prod's 9 existing keys need a
-- complementary (not replacing) key, per the NVD audit below.
--
-- Per-row decisions where prod's existing key differs from 0025's for the
-- same app (NVD API, confirmed 2026-09-23):
--   Git: prod already has git-scm:git (id 8), not 0025's git:git. Both keys
--     are real and only partly overlapping (git:git 205 CPE/13 CVE,
--     git-scm:git 1016 CPE/41 CVE) -- PAT-2047's original finding. The
--     candidate list below carries 0025's git:git row AND an explicit
--     git-scm:git row; NOT EXISTS keeps whichever this database is missing.
--   Zoom: prod has zoom:zoom_client_for_meetings (2 CVEs, Linux-specific:
--     CVE-2021-34419/34420, confirmed by reading the CVE's own cpeMatch
--     criteria, not just the CPE dictionary, which lists 0 for this exact
--     string). 0025's zoom:zoom is the broader key (813 CPE/66 CVE) and
--     covers different CVEs. Same shape as Git: both real, kept alongside
--     each other. 0025's zoom:zoom row is a plain candidate below.
--   Slack, GitHub Desktop: prod's existing rows (slack:slack,
--     github:github_desktop) are byte-identical to 0025's own seed for
--     those apps, and PAT-2047's audit found zero NVD CPE or CVE presence
--     for either key. Not carried as candidates: they would either be
--     skipped as already-present (Slack, GitHub Desktop) or add a key with
--     no evidence behind it. PAT-2049 owns finding a real key for these, if
--     one exists.
--   Firefox: prod's row is match_name 'Mozilla Firefox', 0025's is 'Firefox'
--     -- same vendor:product (mozilla:firefox, audit-confirmed real: 1199
--     CPE/3413 CVE). The NOT EXISTS key includes match_name, so 0025's
--     'Firefox' row inserts as an additional row on prod: harmless (matches
--     whichever display name a device actually reports), not a wrong-key
--     correction, so left to the mechanical rule rather than special-cased.
--   Chrome, Edge, Teams, Dropbox: byte-identical between prod and 0025;
--     NOT EXISTS skips them on both database shapes.
--
-- Excluded from the candidate list entirely (not "already present", never
-- offered): Slack (as above), Box, GitHub Desktop's github:github_desktop,
-- Google Drive (google:backup_and_sync_from_google) -- all four zero NVD CPE
-- and CVE presence, PAT-2047 audit -- and the four OS-part rows (macOS
-- apple:macos / apple:mac_os_x, Windows microsoft:windows_10/windows_11).
-- PAT-2049 covers all of these; inserting them here would add unaudited
-- rows to a data-correction migration.
--
-- Requires 0168 (PAT-2051): source_type and review_state must already
-- exist, and prod's UNIQUE(match_name) must already be dropped, or these
-- inserts fail on the platform column's absence or the duplicate match_name
-- Firefox/Zoom/Git rows would introduce.
BEGIN;

INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
SELECT v.platform, v.match_name, v.cpe_vendor, v.cpe_product, 'PAT-2047 seed parity', 'app_name', 'curated'
FROM (VALUES
    ('any',     'Google Chrome',        'google',            'chrome'),
    ('any',     'Firefox',              'mozilla',           'firefox'),
    ('macos',   'Safari',               'apple',             'safari'),
    ('any',     'Microsoft Edge',       'microsoft',         'edge'),
    ('any',     'Brave Browser',        'brave',             'brave'),
    ('any',     'Opera',                'opera',             'opera_browser'),
    ('any',     'Zoom',                 'zoom',              'zoom'),
    ('any',     'Microsoft Teams',      'microsoft',         'teams'),
    ('any',     'Webex',                'cisco',             'webex'),
    ('any',     'Discord',              'discord',           'discord'),
    ('windows', 'Microsoft Office',     'microsoft',         'office'),
    ('windows', 'Microsoft Word',       'microsoft',         'word'),
    ('windows', 'Microsoft Excel',      'microsoft',         'excel'),
    ('windows', 'Microsoft PowerPoint', 'microsoft',         'powerpoint'),
    ('windows', 'Microsoft Outlook',    'microsoft',         'outlook'),
    ('any',     'Adobe Acrobat',        'adobe',             'acrobat'),
    ('any',     'Adobe Reader',         'adobe',             'acrobat_reader'),
    ('any',     'Adobe Photoshop',      'adobe',             'photoshop'),
    ('any',     '1Password',            'agilebits',         '1password'),
    ('any',     'Visual Studio Code',   'microsoft',         'visual_studio_code'),
    ('any',     'IntelliJ IDEA',        'jetbrains',         'intellij_idea'),
    ('any',     'PyCharm',              'jetbrains',         'pycharm'),
    ('any',     'Docker Desktop',       'docker',            'docker_desktop'),
    ('any',     'Git',                  'git',               'git'),
    ('any',     'Git',                  'git-scm',           'git'),
    ('any',     'Node.js',              'nodejs',            'node.js'),
    ('any',     'Python',               'python',            'python'),
    ('any',     'OpenSSH',              'openbsd',           'openssh'),
    ('any',     'TeamViewer',           'teamviewer',        'teamviewer'),
    ('any',     'AnyDesk',              'anydesk',           'anydesk'),
    ('any',     'Royal TSX',            'royalapplications', 'royal_tsx'),
    ('any',     'Malwarebytes',         'malwarebytes',      'malwarebytes'),
    ('any',     'Dropbox',              'dropbox',           'dropbox'),
    ('any',     'OneDrive',             'microsoft',         'onedrive'),
    ('any',     'Java',                 'oracle',            'jre'),
    ('any',     'Java',                 'oracle',            'jdk'),
    ('any',     'OpenJDK',              'oracle',            'openjdk'),
    ('any',     'Cisco AnyConnect',     'cisco',             'anyconnect_secure_mobility_client'),
    ('any',     'GlobalProtect',        'paloaltonetworks',  'globalprotect'),
    ('any',     'Tunnelblick',          'tunnelblick',       'tunnelblick')
) AS v(platform, match_name, cpe_vendor, cpe_product)
WHERE NOT EXISTS (
    SELECT 1 FROM app_cpe_mappings m
    WHERE m.source_type = 'app_name'
      AND lower(m.match_name) = lower(v.match_name)
      AND m.cpe_vendor = v.cpe_vendor
      AND m.cpe_product = v.cpe_product
);

INSERT INTO schema_migrations (version) VALUES ('0169_app_cpe_mappings_seed_parity')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
