-- patched.im - 0175_google_drive_cpe_key.sql
-- PAT-2049, the two groups PAT-2047's audit (0169) left open.
--
-- ─── Group 1: no NVD presence under the seeded key (re-checked 2026-09-23) ──
-- NVD CPE dictionary (keywordSearch) and CVE API (virtualMatchString),
-- 7s between calls:
--
--   Slack (slack:slack): keywordSearch=Slack, 304 total CPE results across
--     every page -- jenkins:slack_notification, slackware:slackware_linux,
--     slack_archivebot_project:slack_archivebot, slack:wp_slacksync,
--     slack-chat_project:slack-chat, slack:nebula, jenkins:slack,
--     jenkins:slack_upload, atlassian:jira_server_for_slack,
--     slack_morphism_project:slack_morphism -- none is the Slack Technologies
--     desktop/web client. No real key exists. Row left alone.
--   Box (box:box): keywordSearch "Box Drive", "Box Sync", "Box, Inc", "Box
--     for Mac" all return 0 total. "Box Edit" returns 94, all unrelated
--     (BoxyStudio Cooked, Syslog-ng Store Box, AYS Pro Popup Box). No CPE
--     entry for Box the cloud-storage vendor exists under any product
--     spelling tried. No real key exists. Row left alone.
--   GitHub Desktop (github:github_desktop): keywordSearch "GitHub Desktop"
--     and "GitHub Inc" both return 0. cpe:2.3:a:github:desktop returns 0 CPE
--     and 0 CVE. cpe:2.3:a:github (2596 total, paged) surfaces only
--     github:gaug.es and github:github (GitHub Enterprise Server) as
--     distinct vendor:product pairs -- no "desktop" product under the github
--     vendor. No real key exists. Row left alone.
--   Google Drive (google:backup_and_sync_from_google): 0 CPE, 0 CVE under
--     the seeded key -- confirmed dead, same as 2026-09-23's audit found.
--     BUT cpe:2.3:a:google:drive has 43 CPE entries (Google Drive 26.1
--     through 65.0, Windows and Android builds, matching titles "Google
--     Drive <version>" / "Google Drive <version> for Windows/Android") and
--     1 CVE: CVE-2022-3421, CVSS v3.1 7.3, Drive for Desktop's macOS
--     installer pre-creating /Applications/Google Drive.app/Contents/MacOS
--     owned by a non-root user (privilege escalation), affecting versions
--     before 64.0 on macOS. This is a real, relevant key. Added below,
--     alongside the existing dead google:backup_and_sync_from_google row
--     (left in place, matching 0169's practice of adding a corrected key
--     rather than deleting the wrong one -- it produces zero findings on
--     its own, since NVD never indexed anything under it, so it is inert,
--     not wrong-and-firing).
--
-- ─── Group 2: the four OS-part rows (apple:macos, apple:mac_os_x,
-- microsoft:windows_10, microsoft:windows_11) ───────────────────────────────
-- Not touched by this migration. Re-checked against NVD as cpe:2.3:o: (the
-- earlier audit only queried cpe:2.3:a:):
--   apple:macos       178 CPE / 7055 CVE
--   apple:mac_os_x    216 CPE / 5562 CVE
--   microsoft:windows_10  59 CPE / 4057 CVE
--   microsoft:windows_11   6 CPE /  598 CVE
-- All four are real NVD entries under the :o: part; the seeded rows are
-- correct, just filed under a part the first audit didn't query.
--
-- Code confirms they are live, not dead weight: cmd/patched-cve-sync/main.go
-- loads every app_cpe_mappings row with source_type='app_name' (no part
-- column exists or is filtered) and matches it against every device_apps
-- row for devices active in the last 30 days, so a device_apps row named
-- "macOS"/"Windows" -- the OS pseudo-app internal/oscve's own package
-- comment says "the launch path (PAT-335, internal/cvematch) feeds the
-- device OS to the generic CVE match engine as a pseudo-app" -- is matched
-- against these mappings there. cmd/patched-cve-sync/os_match.go then
-- reconciles: vendor-confirmed findings from Apple security-release /
-- Microsoft MSRC advisories (internal/oscve) supersede and delete the
-- NVD-CPE finding for the same (device, CVE); an NVD-CPE OS finding survives
-- only for a CVE with no vendor advisory. That is the fallback role these
-- four rows exist to fill, and removing them would silently drop OS-CVE
-- coverage for exactly the gap the vendor feeds haven't (yet) closed --
-- "absence requires authority" cuts against deleting a fallback signal
-- source on an audit that found it correct, just misfiled by CPE part.
--
-- The event-driven delta path (internal/cvepipeline) explicitly excludes
-- the two pseudo-app names from mapping-triggered matching
-- (withoutOSPseudoApps, matchDevice's own comment: "OS pseudo-apps are
-- owned by the vendor-advisory matcher (os_match.go) and the nightly run.
-- This path never matches, upserts, prunes or assesses them.") -- so these
-- rows are read only by the nightly full match, by design, not by accident.
--
-- Separately, and not actioned here because it is a matcher-behaviour change
-- rather than a mapping-data question: cvematch.wordTokenMatch is a
-- whole-word-token subsequence match, not an exact-name check against the
-- literal pseudo-app strings "macOS"/"Windows". A real installed
-- application whose display name contains "Windows" as its own token (e.g.
-- "Windows Subsystem for Linux", "Windows Admin Center") would also satisfy
-- the ('windows','Windows') mapping in the nightly full match (which applies
-- Match() to every device_apps row, not just the two pseudo-app names), and
-- would be checked against Windows 10/11 OS-build CPE ranges using that
-- app's own version number rather than an OS build. This is a real
-- code-level risk, not confirmed against any device_cve_findings row (out
-- of this migration's scope, and prod is not queried here) -- flagged as a
-- follow-up ticket, not fixed in this data migration.
--
-- Idempotent by design, same shape as 0169: insert only if the exact row
-- doesn't already exist under source_type = 'app_name'.
BEGIN;

INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
SELECT v.platform, v.match_name, v.cpe_vendor, v.cpe_product, 'PAT-2049 NVD audit: real key, CVE-2022-3421', 'app_name', 'curated'
FROM (VALUES
    ('any', 'Google Drive', 'google', 'drive')
) AS v(platform, match_name, cpe_vendor, cpe_product)
WHERE NOT EXISTS (
    SELECT 1 FROM app_cpe_mappings m
    WHERE m.source_type = 'app_name'
      AND lower(m.match_name) = lower(v.match_name)
      AND m.cpe_vendor = v.cpe_vendor
      AND m.cpe_product = v.cpe_product
);

INSERT INTO schema_migrations (version) VALUES ('0175_google_drive_cpe_key')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
