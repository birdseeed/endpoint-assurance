-- patched.im - 0198_duplicate_tools_category.sql
-- PAT-2151 (child of PAT-2146 "SAM reports"): the duplicate-tools-by-category
-- (consolidation candidates) report. Adds seven new software_categories
-- (pdf_editor, screen_recorder, vpn_client, password_manager, file_sync,
-- video_conferencing, note_taking) with reviewed seed rules for common SMB
-- products, and reuses remote_access (PAT-2148, migration 0197) rather than
-- creating a second remote-access category.
--
-- Additive only:
--   * seven new software_categories rows and their subtypes
--   * one new nullable column, software_category_rules.product_key
--   * seed rules for the new categories, each carrying product_key
--   * a backfill UPDATE that sets product_key on 0197's existing remote_access
--     rules, so this report can group AnyDesk-on-macOS and AnyDesk-on-Windows
--     as one product without a second copy of those rules. rmm_agent rows are
--     untouched: RMM tooling is out of this report's scope (PAT-2146 groups
--     it separately so an MSP's own tooling is never a "duplicate" finding).
--
-- Why product_key: software_category_rules already carries subtype_key, but
-- every existing category (ai_tooling, remote_access, rmm_agent) uses it as a
-- generic classification (desktop_app, browser_extension, agent, ...), not a
-- product identity -- one product's macOS bundle, Windows winget package and
-- Homebrew cask each need their own rule (different identifier_type), and
-- without a shared key across those rules internal/duplicatetools would count
-- "AnyDesk for macOS" and "AnyDesk for Windows" as two distinct products,
-- which would misreport a single dual-platform tool as itself a duplicate.
-- product_key is that shared key: NULL for every rule that predates this
-- migration and is not part of this report (ai_tooling, rmm_agent), set on
-- every rule this migration seeds or backfills. It carries no FK and is not
-- validated against a canonical products table; it is a plain, curated
-- grouping label, scoped to this report only.
--
-- Flag rule: internal/duplicatetools flags a category with three or more
-- distinct product_key values present in the tenant's own estate (evaluated
-- at query time against live software_installations /
-- device_browser_extensions rows, the same categorytag.Matches pure function
-- PAT-2148 and the tag reconciler use -- never a second matcher). The
-- ticket's second rule ("two or more PAID products") needs licence or price
-- data that does not exist yet (PAT-2143's price catalogue); it is
-- deliberately NOT implemented here -- see internal/duplicatetools's package
-- doc and the contract for that open item. A product with no category tag
-- never appears in a duplicate group: that falls out of categorytag's own
-- matching (an untagged installation is simply never selected), not a
-- separate exclusion rule.
--
-- ================================ Verification ================================
-- Staff-curated, per the ticket: no tag is inferred from a product's display
-- name alone. Every identifier below was checked against a primary source at
-- the time of writing (2026-09-26); nothing here is invented.
--
--   * Homebrew cask tokens: fetched https://formulae.brew.sh/api/cask/<token>.json
--     directly and confirmed a 200 response for every cask token seeded here.
--     Several cask JSON payloads also carry the app's own CFBundleIdentifier
--     in their "uninstall".quit or "zap".trash (Preferences plist path)
--     stanzas -- both fields are maintained by Homebrew's cask reviewers
--     against the real app, so they are used here as a primary source for
--     the macOS bundle identifier itself, not just for cask-token existence:
--     google-drive (com.google.drivefs), box-drive (com.box.desktop),
--     nextcloud (com.nextcloud.desktopclient), snagit (com.TechSmith.Snagit),
--     adobe-acrobat-pro (com.adobe.Acrobat.Pro), openvpn-connect
--     (org.openvpn.client.app), loom (com.loom.desktop, from its Preferences
--     plist trash path com.loom.desktop.plist), obsidian (md.obsidian, from
--     ~/Library/Preferences/md.obsidian.plist) and joplin
--     (net.cozic.joplin-desktop, from its own Preferences plist path).
--   * Windows winget IDs: confirmed by listing the exact manifest directory in
--     github.com/microsoft/winget-pkgs via the GitHub API (a 200 with a real
--     version folder listed, not just a repo search hit) for every winget
--     package identifier seeded below.
--   * macOS bundle IDs and Team IDs for six products (1Password, LastPass,
--     Keeper, Tailscale, NordVPN, Dropbox, Zoom, Notion, OBS) were confirmed
--     by downloading the vendor's own current installer directly (pkg/dmg/
--     zip from the vendor's own download URL, several also independently
--     reachable via Installomator's fragment for the same product), expanding
--     it read-only (pkgutil --expand-full / hdiutil attach, never executed)
--     and reading CFBundleIdentifier from the real .app's Info.plist with
--     PlistBuddy, cross-checked against the codesign Team ID on the same
--     .app -- the same standard this repository's own agent build process
--     trusts for its own signature checks. This is the strongest of the
--     methods used here: the actual shipping binary, not a third party's
--     description of it.
--   * Bitwarden's macOS bundle ID (com.bitwarden.desktop) came from the
--     vendor's own public source (bitwarden/clients apps/desktop/
--     electron-builder.json, "appId"), the same class of source 0197 used for
--     RustDesk and TigerVNC.
--   * Apple's own iTunes Search API (itunes.apple.com/search,
--     entity=macSoftware) confirmed the Mac App Store bundle identifier and
--     matched the expected vendor as sellerName for: WireGuard
--     (com.wireguard.macos, WireGuard LLC), Microsoft OneDrive
--     (com.microsoft.OneDrive-mac), Microsoft OneNote
--     (com.microsoft.onenote.mac), Evernote (com.evernote.Evernote), Foxit
--     PDF Editor's Mac App Store build (com.foxit-software.Foxit.PDF.Editor)
--     and PDF Expert (com.readdle.PDFExpert-Mac). Noted per-product below
--     where this is the Mac App Store build specifically and may not match a
--     direct-download build of the same product.
--   * Team IDs not independently re-derived above were cross-checked against
--     Installomator (github.com/Installomator/Installomator,
--     fragments/labels/*.sh, expectedTeamID) the same community-maintained
--     source 0197 used, and only ever paired with a bundle ID confirmed by
--     one of the methods above -- never taken alone as the identifier.
--
-- Explicitly NOT seeded, because no primary source could confirm an exact
-- identifier or the product has no build for that platform (verify before
-- adding a rule; do not guess one from this list):
--   * VPN: Cisco Secure Client, FortiClient (Fortinet), GlobalProtect (Palo
--     Alto Networks) -- no winget package under any plausible publisher path,
--     no Homebrew cask, no macOS identity confirmable without a customer
--     tenant's live deployment. These ship to end users only through
--     enterprise MDM/config profiles, the same pattern 0197 hit for most RMM
--     agents. Open gap; recommendation there is the same as 0197's: capture
--     the real identity from a live device and add it through the admin API.
--   * PDF: PDF-XChange Editor has no Homebrew cask (Windows-only product,
--     confirmed) -- Windows winget coverage only, which is correct, not a
--     gap. PDF Expert (Readdle) has no winget package or manifest path found
--     under any plausible publisher spelling -- it is a Mac/iOS product with
--     no Windows build, also not a gap.
--   * Screen recorders: Camtasia's macOS bundle identifier is version-suffixed
--     (e.g. com.techsmith.camtasia2026, confirmed from its own Homebrew cask
--     zap trash pattern) and changes every release; a static rule would go
--     stale on the next TechSmith major version, so it is deliberately not
--     seeded -- Camtasia's Windows winget and macOS Homebrew cask rules below
--     still give both-platform coverage. Webex's macOS Preferences trail is
--     ambiguous between a legacy identifier (Cisco-Systems.Spark) and a
--     current one (matched only by an unanchored com.webex.* glob) -- no
--     single confirmed bundle ID, so no macos_bundle_id rule; its Windows
--     winget and macOS Homebrew cask rules still cover both platforms.
--     Microsoft Teams' (new) macOS identity is similarly not independently
--     confirmed as a CFBundleIdentifier (only an installer receipt id was
--     found) -- winget and Homebrew cask rules cover it without guessing.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0198_duplicate_tools_category.sql

BEGIN;

-- product_key groups a product's rules (one per identifier type/platform)
-- into the single product internal/duplicatetools reports. NULL for every
-- rule outside this report's scope (ai_tooling, rmm_agent, and any future
-- category that isn't a duplicate-tools consolidation candidate).
ALTER TABLE software_category_rules
    ADD COLUMN product_key TEXT CHECK (product_key IS NULL OR product_key ~ '^[a-z][a-z0-9_]{0,62}$');
COMMENT ON COLUMN software_category_rules.product_key IS
    'PAT-2151: groups a product''s per-platform/per-source rules into one product for internal/duplicatetools. NULL outside that report''s categories.';

INSERT INTO software_categories (key, display_name, description) VALUES
    ('pdf_editor', 'PDF editors',
     'Applications that create, edit or convert PDF documents (not a read-only viewer). Several editors on one estate is a common licence-consolidation candidate.'),
    ('screen_recorder', 'Screen recorders',
     'Applications whose primary purpose is recording the screen (with or without narration/webcam), distinct from a video conferencing app''s own recording feature.'),
    ('vpn_client', 'VPN clients',
     'End-user VPN client applications, corporate or consumer. Several clients on one estate can mean overlapping site-to-site or remote-access VPN spend.'),
    ('password_manager', 'Password managers',
     'Applications and browser extensions whose primary purpose is storing and autofilling credentials.'),
    ('file_sync', 'File sync and cloud storage clients',
     'Desktop sync clients for a cloud storage service (not the storage service''s own web app).'),
    ('video_conferencing', 'Video conferencing',
     'Dedicated video conferencing client applications. A chat app''s own call/huddle feature (e.g. Slack huddles) is not a separate video conferencing product and is deliberately not tagged here.'),
    ('note_taking', 'Note taking',
     'Applications whose primary purpose is personal or team note taking, distinct from a full document editor.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO software_category_subtypes (category_key, key, display_name) VALUES
    ('pdf_editor', 'desktop_app', 'Desktop app'),
    ('screen_recorder', 'desktop_app', 'Desktop app'),
    ('vpn_client', 'desktop_app', 'Desktop app'),
    ('password_manager', 'desktop_app', 'Desktop app'),
    ('file_sync', 'desktop_app', 'Desktop app'),
    ('video_conferencing', 'desktop_app', 'Desktop app'),
    ('note_taking', 'desktop_app', 'Desktop app')
ON CONFLICT (category_key, key) DO NOTHING;

-- Seed rules. state = 'published' with published_at set, exactly as the
-- admin API leaves a rule after create-then-publish (0197's own convention),
-- so the report and ReconcileAll both see them as live immediately.
INSERT INTO software_category_rules
    (identifier_type, identifier_value, qualifier, platform, category_key, subtype_key, product_key, notes,
     version, state, created_by, published_at)
VALUES

    -- ---------------------------- password_manager ----------------------------
    ('macos_bundle_id', 'com.1password.1password', '', 'macos', 'password_manager', 'desktop_app', 'onepassword',
     'Confirmed from 1Password 8''s own installer pkg (cache.agilebits.com), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', '2BUA8C4S2C', 'com.1password.1password', 'macos', 'password_manager', 'desktop_app', 'onepassword',
     'codesign Team ID from the same installer; matches Installomator''s 1password7/1password8 expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'agilebits.1password', 'winget', 'windows', 'password_manager', 'desktop_app', 'onepassword',
     'winget-pkgs manifests/a/AgileBits/1Password confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', '1password', 'brew_cask', 'macos', 'password_manager', 'desktop_app', 'onepassword',
     'formulae.brew.sh/api/cask/1password.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.bitwarden.desktop', '', 'macos', 'password_manager', 'desktop_app', 'bitwarden',
     'bitwarden/clients apps/desktop/electron-builder.json "appId" (vendor''s own public source).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'LTZ2PFU5D6', 'com.bitwarden.desktop', 'macos', 'password_manager', 'desktop_app', 'bitwarden',
     'Installomator expectedTeamID for com.bitwarden.desktop.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'bitwarden.bitwarden', 'winget', 'windows', 'password_manager', 'desktop_app', 'bitwarden',
     'winget-pkgs manifests/b/Bitwarden/Bitwarden confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'bitwarden', 'brew_cask', 'macos', 'password_manager', 'desktop_app', 'bitwarden',
     'formulae.brew.sh/api/cask/bitwarden.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.lastpass.lastpassmacdesktop', '', 'macos', 'password_manager', 'desktop_app', 'lastpass',
     'Confirmed from LastPass''s own installer dmg (download.cloud.lastpass.com), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'N24REP3BMN', 'com.lastpass.lastpassmacdesktop', 'macos', 'password_manager', 'desktop_app', 'lastpass',
     'codesign Team ID from the same installer; matches Installomator''s lastpass expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'lastpass.lastpass', 'winget', 'windows', 'password_manager', 'desktop_app', 'lastpass',
     'winget-pkgs manifests/l/LastPass/LastPass confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'lastpass', 'brew_cask', 'macos', 'password_manager', 'desktop_app', 'lastpass',
     'formulae.brew.sh/api/cask/lastpass.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- Dashlane: Windows only. No Homebrew cask exists (checked; 404) and no
    -- macOS build could be confirmed -- deliberately not seeded for macOS.
    ('package', 'dashlane.dashlane', 'winget', 'windows', 'password_manager', 'desktop_app', 'dashlane',
     'winget-pkgs manifests/d/Dashlane/Dashlane confirmed present (200, versions listed). No Homebrew cask exists (confirmed 404); Windows-only coverage.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.keepersecurity.passwordmanager', '', 'macos', 'password_manager', 'desktop_app', 'keeper',
     'Confirmed from Keeper''s own installer dmg (keepersecurity.com), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', '234QNB7GCA', 'com.keepersecurity.passwordmanager', 'macos', 'password_manager', 'desktop_app', 'keeper',
     'codesign Team ID from the same installer; matches Installomator''s keeperpasswordmanager expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'keepersecurity.keeperdesktop', 'winget', 'windows', 'password_manager', 'desktop_app', 'keeper',
     'winget-pkgs manifests/k/KeeperSecurity/KeeperDesktop confirmed present (200, version 18.6.3.0 listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'keeper-password-manager', 'brew_cask', 'macos', 'password_manager', 'desktop_app', 'keeper',
     'formulae.brew.sh/api/cask/keeper-password-manager.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- ------------------------------- vpn_client --------------------------------
    -- Cisco Secure Client, FortiClient and GlobalProtect are deliberately NOT
    -- seeded: no winget package, no Homebrew cask, no macOS identity
    -- confirmable from a primary source (enterprise MDM/profile deployment
    -- only). See header comment.
    ('macos_bundle_id', 'com.wireguard.macos', '', 'macos', 'vpn_client', 'desktop_app', 'wireguard',
     'Apple iTunes Search API (entity=macSoftware): bundleId com.wireguard.macos, sellerName "WireGuard LLC" -- the Mac App Store build (WireGuard has no direct-download macOS build or Homebrew cask; checked, neither exists). No Team ID independently confirmed, so no macos_team_id rule.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'wireguard.wireguard', 'winget', 'windows', 'vpn_client', 'desktop_app', 'wireguard',
     'winget-pkgs manifests/w/WireGuard/WireGuard confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'io.tailscale.ipn.macsys', '', 'macos', 'vpn_client', 'desktop_app', 'tailscale',
     'Confirmed from Tailscale''s own installer zip (pkgs.tailscale.com), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'W5364U7YZB', 'io.tailscale.ipn.macsys', 'macos', 'vpn_client', 'desktop_app', 'tailscale',
     'codesign Team ID from the same installer; matches Installomator''s tailscale expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'tailscale.tailscale', 'winget', 'windows', 'vpn_client', 'desktop_app', 'tailscale',
     'winget-pkgs manifests/t/Tailscale/Tailscale confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'tailscale-app', 'brew_cask', 'macos', 'vpn_client', 'desktop_app', 'tailscale',
     'formulae.brew.sh/api/cask/tailscale-app.json confirmed 200 (token is tailscale-app, not tailscale).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.nordvpn.macos', '', 'macos', 'vpn_client', 'desktop_app', 'nordvpn',
     'Confirmed from NordVPN''s own installer pkg (downloads.nordcdn.com), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'W5W395V82Y', 'com.nordvpn.macos', 'macos', 'vpn_client', 'desktop_app', 'nordvpn',
     'codesign Team ID from the same installer; matches Installomator''s nordvpn expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'nordsecurity.nordvpn', 'winget', 'windows', 'vpn_client', 'desktop_app', 'nordvpn',
     'winget-pkgs manifests/n/NordSecurity/NordVPN confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'nordvpn', 'brew_cask', 'macos', 'vpn_client', 'desktop_app', 'nordvpn',
     'formulae.brew.sh/api/cask/nordvpn.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'org.openvpn.client.app', '', 'macos', 'vpn_client', 'desktop_app', 'openvpn_connect',
     'Homebrew cask openvpn-connect''s own uninstall.quit stanza names this as the running app''s bundle identifier (Homebrew cask metadata, maintained by its reviewers against the real app).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'ACV7L3WCD8', 'org.openvpn.client.app', 'macos', 'vpn_client', 'desktop_app', 'openvpn_connect',
     'Installomator expectedTeamID for OpenVPN Connect (openvpnconnectv3).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'openvpntechnologies.openvpnconnect', 'winget', 'windows', 'vpn_client', 'desktop_app', 'openvpn_connect',
     'winget-pkgs manifests/o/OpenVPNTechnologies/OpenVPNConnect confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'openvpn-connect', 'brew_cask', 'macos', 'vpn_client', 'desktop_app', 'openvpn_connect',
     'formulae.brew.sh/api/cask/openvpn-connect.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- ------------------------------- file_sync ---------------------------------
    ('macos_bundle_id', 'com.getdropbox.dropbox', '', 'macos', 'file_sync', 'desktop_app', 'dropbox',
     'Confirmed from Dropbox''s own installer dmg (dropbox.com/download), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'G7HH3F8CAK', 'com.getdropbox.dropbox', 'macos', 'file_sync', 'desktop_app', 'dropbox',
     'codesign Team ID from the same installer; matches Installomator''s dropbox expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'dropbox.dropbox', 'winget', 'windows', 'file_sync', 'desktop_app', 'dropbox',
     'winget-pkgs manifests/d/Dropbox/Dropbox confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'dropbox', 'brew_cask', 'macos', 'file_sync', 'desktop_app', 'dropbox',
     'formulae.brew.sh/api/cask/dropbox.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.microsoft.onedrive-mac', '', 'macos', 'file_sync', 'desktop_app', 'onedrive',
     'Apple iTunes Search API (entity=macSoftware): bundleId com.microsoft.OneDrive-mac, sellerName "Microsoft Corporation" (Mac App Store build; normalised lower-case per internal/categorytag.NormalizeRule).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'UBF8T346G9', 'com.microsoft.onedrive-mac', 'macos', 'file_sync', 'desktop_app', 'onedrive',
     'Installomator expectedTeamID for microsoftonedrive (Microsoft''s shared Team ID, also seen on Microsoft Teams).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'microsoft.onedrive', 'winget', 'windows', 'file_sync', 'desktop_app', 'onedrive',
     'winget-pkgs manifests/m/Microsoft/OneDrive confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'onedrive', 'brew_cask', 'macos', 'file_sync', 'desktop_app', 'onedrive',
     'formulae.brew.sh/api/cask/onedrive.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.google.drivefs', '', 'macos', 'file_sync', 'desktop_app', 'google_drive',
     'Homebrew cask google-drive''s own uninstall.quit stanza names this (with its FinderSync helper) as the running app''s bundle identifier.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'EQHXZ8M8AV', 'com.google.drivefs', 'macos', 'file_sync', 'desktop_app', 'google_drive',
     'Installomator expectedTeamID for googledrive (Google Drive File Stream).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'google.googledrive', 'winget', 'windows', 'file_sync', 'desktop_app', 'google_drive',
     'winget-pkgs manifests/g/Google/GoogleDrive confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'google-drive', 'brew_cask', 'macos', 'file_sync', 'desktop_app', 'google_drive',
     'formulae.brew.sh/api/cask/google-drive.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.box.desktop', '', 'macos', 'file_sync', 'desktop_app', 'box',
     'Homebrew cask box-drive''s own uninstall.quit stanza names this as the running app''s bundle identifier.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'M683GB7CPW', 'com.box.desktop', 'macos', 'file_sync', 'desktop_app', 'box',
     'Installomator expectedTeamID for boxdrive.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'box.box', 'winget', 'windows', 'file_sync', 'desktop_app', 'box',
     'winget-pkgs manifests/b/Box/Box confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'box-drive', 'brew_cask', 'macos', 'file_sync', 'desktop_app', 'box',
     'formulae.brew.sh/api/cask/box-drive.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.nextcloud.desktopclient', '', 'macos', 'file_sync', 'desktop_app', 'nextcloud',
     'Homebrew cask nextcloud''s own uninstall.quit stanza names this as the running app''s bundle identifier.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'NKUJUXUJ3B', 'com.nextcloud.desktopclient', 'macos', 'file_sync', 'desktop_app', 'nextcloud',
     'Installomator expectedTeamID for nextcloud.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'nextcloud.nextclouddesktop', 'winget', 'windows', 'file_sync', 'desktop_app', 'nextcloud',
     'winget-pkgs manifests/n/Nextcloud/NextcloudDesktop confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'nextcloud', 'brew_cask', 'macos', 'file_sync', 'desktop_app', 'nextcloud',
     'formulae.brew.sh/api/cask/nextcloud.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- --------------------------- video_conferencing ----------------------------
    -- Slack huddles deliberately not tagged: a chat app's own call feature is
    -- not a separate video conferencing product (ticket instruction).
    ('macos_bundle_id', 'us.zoom.xos', '', 'macos', 'video_conferencing', 'desktop_app', 'zoom',
     'Confirmed from Zoom''s own installer pkg (zoom.us/client/latest/Zoom.pkg), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'BJ4HAAB9B3', 'us.zoom.xos', 'macos', 'video_conferencing', 'desktop_app', 'zoom',
     'codesign Team ID from the same installer.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'zoom.zoom', 'winget', 'windows', 'video_conferencing', 'desktop_app', 'zoom',
     'winget-pkgs manifests/z/Zoom/Zoom confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'zoom', 'brew_cask', 'macos', 'video_conferencing', 'desktop_app', 'zoom',
     'formulae.brew.sh/api/cask/zoom.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- Microsoft Teams (new): macOS CFBundleIdentifier not independently
    -- confirmed (only an installer receipt id was found) -- see header
    -- comment; winget and Homebrew cask cover both platforms without
    -- guessing the bundle id.
    ('package', 'microsoft.teams', 'winget', 'windows', 'video_conferencing', 'desktop_app', 'microsoft_teams',
     'winget-pkgs manifests/m/Microsoft/Teams confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'microsoft-teams', 'brew_cask', 'macos', 'video_conferencing', 'desktop_app', 'microsoft_teams',
     'formulae.brew.sh/api/cask/microsoft-teams.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- Webex: macOS CFBundleIdentifier ambiguous between a legacy and current
    -- identifier (see header comment) -- winget and Homebrew cask cover both
    -- platforms without guessing.
    ('package', 'cisco.webex', 'winget', 'windows', 'video_conferencing', 'desktop_app', 'webex',
     'winget-pkgs manifests/c/Cisco/Webex confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'webex', 'brew_cask', 'macos', 'video_conferencing', 'desktop_app', 'webex',
     'formulae.brew.sh/api/cask/webex.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- ----------------------------- screen_recorder ------------------------------
    ('macos_bundle_id', 'com.obsproject.obs-studio', '', 'macos', 'screen_recorder', 'desktop_app', 'obs',
     'Confirmed from OBS Studio''s own GitHub release dmg (obsproject/obs-studio), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', '2MMRE5MTB8', 'com.obsproject.obs-studio', 'macos', 'screen_recorder', 'desktop_app', 'obs',
     'codesign Team ID from the same release; matches Installomator''s obs expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'obsproject.obsstudio', 'winget', 'windows', 'screen_recorder', 'desktop_app', 'obs',
     'winget-pkgs manifests/o/OBSProject/OBSStudio confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'obs', 'brew_cask', 'macos', 'screen_recorder', 'desktop_app', 'obs',
     'formulae.brew.sh/api/cask/obs.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.techsmith.snagit', '', 'macos', 'screen_recorder', 'desktop_app', 'snagit',
     'Homebrew cask snagit''s own uninstall.quit stanza names com.TechSmith.Snagit as the running app''s bundle identifier (normalised lower-case per internal/categorytag.NormalizeRule).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', '7TQL462TU8', 'com.techsmith.snagit', 'macos', 'screen_recorder', 'desktop_app', 'snagit',
     'Installomator expectedTeamID for snagit2026 (TechSmith''s shared Team ID, also seen on Camtasia).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'techsmith.snagit', 'winget', 'windows', 'screen_recorder', 'desktop_app', 'snagit',
     'winget-pkgs manifests/t/TechSmith/Snagit confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'snagit', 'brew_cask', 'macos', 'screen_recorder', 'desktop_app', 'snagit',
     'formulae.brew.sh/api/cask/snagit.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.loom.desktop', '', 'macos', 'screen_recorder', 'desktop_app', 'loom',
     'Homebrew cask loom''s own zap.trash Preferences path (~/Library/Preferences/com.loom.desktop.plist) names the app''s bundle identifier.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'QGD2ZPXZZG', 'com.loom.desktop', 'macos', 'screen_recorder', 'desktop_app', 'loom',
     'Installomator expectedTeamID for loom.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'loom.loom', 'winget', 'windows', 'screen_recorder', 'desktop_app', 'loom',
     'winget-pkgs manifests/l/Loom/Loom confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'loom', 'brew_cask', 'macos', 'screen_recorder', 'desktop_app', 'loom',
     'formulae.brew.sh/api/cask/loom.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- Camtasia: macOS bundle identifier is version-suffixed (changes every
    -- TechSmith major release) -- deliberately not seeded as macos_bundle_id;
    -- see header comment. Winget and Homebrew cask give both-platform
    -- coverage without a rule that goes stale on the next release.
    ('package', 'techsmith.camtasia', 'winget', 'windows', 'screen_recorder', 'desktop_app', 'camtasia',
     'winget-pkgs manifests/t/TechSmith/Camtasia confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'camtasia', 'brew_cask', 'macos', 'screen_recorder', 'desktop_app', 'camtasia',
     'formulae.brew.sh/api/cask/camtasia.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- ------------------------------- note_taking --------------------------------
    ('macos_bundle_id', 'notion.id', '', 'macos', 'note_taking', 'desktop_app', 'notion',
     'Confirmed from Notion''s own installer dmg (notion.so/desktop/mac/download), CFBundleIdentifier read from the real .app Info.plist.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'LBQJ96FQ8D', 'notion.id', 'macos', 'note_taking', 'desktop_app', 'notion',
     'codesign Team ID from the same installer; matches Installomator''s notion expectedTeamID.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'notion.notion', 'winget', 'windows', 'note_taking', 'desktop_app', 'notion',
     'winget-pkgs manifests/n/Notion/Notion confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'notion', 'brew_cask', 'macos', 'note_taking', 'desktop_app', 'notion',
     'formulae.brew.sh/api/cask/notion.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'com.evernote.evernote', '', 'macos', 'note_taking', 'desktop_app', 'evernote',
     'Apple iTunes Search API (entity=macSoftware): bundleId com.evernote.Evernote, sellerName "Evernote Corporation" (normalised lower-case per internal/categorytag.NormalizeRule).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'Q79WDW8YH9', 'com.evernote.evernote', 'macos', 'note_taking', 'desktop_app', 'evernote',
     'Installomator expectedTeamID for evernote.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'evernote.evernote', 'winget', 'windows', 'note_taking', 'desktop_app', 'evernote',
     'winget-pkgs manifests/e/Evernote/Evernote confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'evernote', 'brew_cask', 'macos', 'note_taking', 'desktop_app', 'evernote',
     'formulae.brew.sh/api/cask/evernote.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'md.obsidian', '', 'macos', 'note_taking', 'desktop_app', 'obsidian',
     'Homebrew cask obsidian''s own zap.trash Preferences path (~/Library/Preferences/md.obsidian.plist) names the app''s bundle identifier.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', '6JSW4SJWN9', 'md.obsidian', 'macos', 'note_taking', 'desktop_app', 'obsidian',
     'Installomator expectedTeamID for obsidian.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'obsidian.obsidian', 'winget', 'windows', 'note_taking', 'desktop_app', 'obsidian',
     'winget-pkgs manifests/o/Obsidian/Obsidian confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'obsidian', 'brew_cask', 'macos', 'note_taking', 'desktop_app', 'obsidian',
     'formulae.brew.sh/api/cask/obsidian.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('macos_bundle_id', 'net.cozic.joplin-desktop', '', 'macos', 'note_taking', 'desktop_app', 'joplin',
     'Homebrew cask joplin''s own zap.trash Preferences path (~/Library/Preferences/net.cozic.joplin-desktop.plist) names the app''s bundle identifier.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'A9BXAFS6CT', 'net.cozic.joplin-desktop', 'macos', 'note_taking', 'desktop_app', 'joplin',
     'Installomator expectedTeamID for joplin.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'joplin.joplin', 'winget', 'windows', 'note_taking', 'desktop_app', 'joplin',
     'winget-pkgs manifests/j/Joplin/Joplin confirmed present (200, version listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'joplin', 'brew_cask', 'macos', 'note_taking', 'desktop_app', 'joplin',
     'formulae.brew.sh/api/cask/joplin.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- OneNote: no standalone Windows winget package exists (checked; only an
    -- unrelated OneNoteDiagnostics tool is published under Microsoft) --
    -- macOS coverage only, which is correct, not a gap.
    ('macos_bundle_id', 'com.microsoft.onenote.mac', '', 'macos', 'note_taking', 'desktop_app', 'onenote',
     'Apple iTunes Search API (entity=macSoftware): bundleId com.microsoft.onenote.mac, sellerName "Microsoft Corporation".', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'UBF8T346G9', 'com.microsoft.onenote.mac', 'macos', 'note_taking', 'desktop_app', 'onenote',
     'Microsoft''s shared Team ID (Installomator-confirmed on OneDrive and Teams; Apple''s catalogue does not itself carry a Team ID).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'microsoft-onenote', 'brew_cask', 'macos', 'note_taking', 'desktop_app', 'onenote',
     'formulae.brew.sh/api/cask/microsoft-onenote.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now())

ON CONFLICT (identifier_type, platform, qualifier, identifier_value, category_key, subtype_key) WHERE state <> 'retired' DO NOTHING;

-- pdf_editor, kept separate only for readability (this VALUES list would
-- otherwise run past a comfortable review length).
INSERT INTO software_category_rules
    (identifier_type, identifier_value, qualifier, platform, category_key, subtype_key, product_key, notes,
     version, state, created_by, published_at)
VALUES
    ('macos_bundle_id', 'com.adobe.acrobat.pro', '', 'macos', 'pdf_editor', 'desktop_app', 'adobe_acrobat',
     'Homebrew cask adobe-acrobat-pro''s own uninstall.quit stanza names com.adobe.Acrobat.Pro as the running app''s bundle identifier (normalised lower-case per internal/categorytag.NormalizeRule).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', 'JQ525L2MZD', 'com.adobe.acrobat.pro', 'macos', 'pdf_editor', 'desktop_app', 'adobe_acrobat',
     'Installomator expectedTeamID for adobeacrobatprodc (Adobe''s Team ID, shared across Adobe''s own products).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'adobe.acrobat.pro', 'winget', 'windows', 'pdf_editor', 'desktop_app', 'adobe_acrobat',
     'winget-pkgs manifests/a/Adobe/Acrobat/Pro confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'adobe-acrobat-pro', 'brew_cask', 'macos', 'pdf_editor', 'desktop_app', 'adobe_acrobat',
     'formulae.brew.sh/api/cask/adobe-acrobat-pro.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- Foxit: bundle ID is the Mac App Store build specifically (Apple's own
    -- catalogue); Foxit's direct-download macOS build reports only an
    -- installer receipt id (com.foxit.pkg.pdfeditor, from the Homebrew
    -- cask's own uninstall.pkgutil stanza and matching Installomator's
    -- commented-out packageID for foxitpdfeditor) which is not necessarily
    -- the same as the running app's CFBundleIdentifier -- not seeded as
    -- macos_bundle_id to avoid conflating an installer receipt with the app
    -- identity. The winget package (still published under Foxit's legacy
    -- PhantomPDF name) and Homebrew cask both give real coverage regardless.
    ('macos_bundle_id', 'com.foxit-software.foxit.pdf.editor', '', 'macos', 'pdf_editor', 'desktop_app', 'foxit',
     'Apple iTunes Search API (entity=macSoftware): bundleId com.foxit-software.Foxit.PDF.Editor, sellerName "FOXIT SOFTWARE INCORPORATED" -- the Mac App Store build.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'foxit.phantompdf', 'winget', 'windows', 'pdf_editor', 'desktop_app', 'foxit',
     'winget-pkgs manifests/f/Foxit/PhantomPDF confirmed present (200, versions listed) -- winget still publishes Foxit''s PDF editor under its legacy PhantomPDF package id; current branding is "Foxit PDF Editor".', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'foxit-pdf-editor', 'brew_cask', 'macos', 'pdf_editor', 'desktop_app', 'foxit',
     'formulae.brew.sh/api/cask/foxit-pdf-editor.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- PDF-XChange Editor: Windows-only product. No Homebrew cask exists
    -- (checked; no macOS build), so Windows coverage only, which is correct.
    ('package', 'trackersoftware.pdf-xchangeeditor', 'winget', 'windows', 'pdf_editor', 'desktop_app', 'pdf_xchange',
     'winget-pkgs manifests/t/TrackerSoftware/PDF-XChangeEditor confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    ('package', 'nitrosoftware.nitropro', 'winget', 'windows', 'pdf_editor', 'desktop_app', 'nitro',
     'winget-pkgs manifests/n/NitroSoftware/NitroPro confirmed present (200, versions listed).', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'nitro-pdf-pro', 'brew_cask', 'macos', 'pdf_editor', 'desktop_app', 'nitro',
     'formulae.brew.sh/api/cask/nitro-pdf-pro.json confirmed 200. macOS CFBundleIdentifier not independently confirmed -- cask coverage only for macOS, no macos_bundle_id rule.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),

    -- PDF Expert (Readdle): Mac/iOS product, no Windows build found (checked;
    -- no winget manifest under any plausible publisher spelling) -- macOS
    -- coverage only, which is correct, not a gap.
    ('macos_bundle_id', 'com.readdle.pdfexpert-mac', '', 'macos', 'pdf_editor', 'desktop_app', 'pdf_expert',
     'Apple iTunes Search API (entity=macSoftware): bundleId com.readdle.PDFExpert-Mac, sellerName "Readdle Technologies Limited".', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('macos_team_id', '3L68KQB4HG', 'com.readdle.pdfexpert-mac', 'macos', 'pdf_editor', 'desktop_app', 'pdf_expert',
     'Installomator expectedTeamID for pdfexpert.', 1, 'published', 'migration:0198_duplicate_tools_category', now()),
    ('package', 'pdf-expert', 'brew_cask', 'macos', 'pdf_editor', 'desktop_app', 'pdf_expert',
     'formulae.brew.sh/api/cask/pdf-expert.json confirmed 200.', 1, 'published', 'migration:0198_duplicate_tools_category', now())

ON CONFLICT (identifier_type, platform, qualifier, identifier_value, category_key, subtype_key) WHERE state <> 'retired' DO NOTHING;

-- Append-only audit: one 'create' entry per rule this migration added,
-- mirroring what the admin API's CreateRule + PublishRule would have
-- written (before = NULL, after = the published row), 0197's own convention.
INSERT INTO software_category_audit (entity_type, entity_id, action, actor, before, after)
SELECT 'rule', r.id, 'create', r.created_by, NULL,
       jsonb_build_object(
           'identifier_type', r.identifier_type, 'identifier_value', r.identifier_value,
           'qualifier', r.qualifier, 'platform', r.platform,
           'category_key', r.category_key, 'subtype_key', r.subtype_key, 'product_key', r.product_key,
           'notes', r.notes, 'version', r.version, 'state', r.state, 'published_at', r.published_at)
FROM software_category_rules r
WHERE r.created_by = 'migration:0198_duplicate_tools_category'
  AND NOT EXISTS (
      SELECT 1 FROM software_category_audit a WHERE a.entity_type = 'rule' AND a.entity_id = r.id
  );

-- Backfill product_key onto 0197's existing remote_access rules, identified
-- by their exact identifiers from that migration, so internal/duplicatetools
-- can reuse remote_access without a second copy of these rules. rmm_agent is
-- untouched (out of this report's scope). Each UPDATE's before/after is
-- audited as an 'edit', the same shape UpdateRule would write, so the append
-- -only trail still records this change.
WITH backfill (identifier_type, platform, qualifier, identifier_value, product_key) AS (
    VALUES
        ('macos_bundle_id', 'macos', '', 'com.philandro.anydesk', 'anydesk'),
        ('macos_team_id', 'macos', 'com.philandro.anydesk', 'KHRWM533LU', 'anydesk'),
        ('package', 'windows', 'winget', 'anydesk.anydesk', 'anydesk'),
        ('package', 'macos', 'brew_cask', 'anydesk', 'anydesk'),

        ('macos_bundle_id', 'macos', '', 'com.teamviewer.teamviewer', 'teamviewer'),
        ('macos_team_id', 'macos', 'com.teamviewer.teamviewer', 'H7UGFBUGV6', 'teamviewer'),
        ('macos_bundle_id', 'macos', '', 'com.teamviewer.teamviewerhost', 'teamviewer'),
        ('macos_team_id', 'macos', 'com.teamviewer.teamviewerhost', 'H7UGFBUGV6', 'teamviewer'),
        ('package', 'windows', 'winget', 'teamviewer.teamviewer', 'teamviewer'),
        ('package', 'macos', 'brew_cask', 'teamviewer', 'teamviewer'),

        ('macos_bundle_id', 'macos', '', 'com.splashtop.splashtop-streamer', 'splashtop_streamer'),
        ('macos_team_id', 'macos', 'com.splashtop.splashtop-streamer', 'CPQQ3AW49Y', 'splashtop_streamer'),
        ('package', 'windows', 'winget', 'splashtop.splashtopstreamer', 'splashtop_streamer'),
        ('package', 'macos', 'brew_cask', 'splashtop-streamer', 'splashtop_streamer'),
        ('package', 'windows', 'winget', 'splashtop.splashtopbusiness', 'splashtop_business'),
        ('package', 'macos', 'brew_cask', 'splashtop-business', 'splashtop_business'),

        ('macos_bundle_id', 'macos', '', 'com.carriez.rustdesk', 'rustdesk'),
        ('macos_team_id', 'macos', 'com.carriez.rustdesk', 'HZF9JMC8YN', 'rustdesk'),
        ('package', 'macos', 'brew_cask', 'rustdesk', 'rustdesk'),

        ('package', 'windows', 'winget', 'goto.logmeinclient', 'goto_logmein'),
        ('package', 'windows', 'winget', 'goto.gotoassistagentdesktopconsole', 'goto_gotoassist'),

        ('browser_extension', 'any', 'chrome_web_store', 'inomeogfingihgjfjlpeplalcfajhgai', 'chrome_remote_desktop'),

        ('macos_bundle_id', 'macos', '', 'com.realvnc.vncviewer', 'realvnc_viewer'),
        ('macos_team_id', 'macos', 'com.realvnc.vncviewer', 'ZNCQ8JEH7X', 'realvnc_viewer'),
        ('package', 'windows', 'winget', 'realvnc.vncviewer', 'realvnc_viewer'),
        ('package', 'macos', 'brew_cask', 'realvnc-connect-viewer', 'realvnc_viewer'),
        ('macos_bundle_id', 'macos', '', 'com.realvnc.vncagent', 'realvnc_server'),
        ('macos_team_id', 'macos', 'com.realvnc.vncagent', 'ZNCQ8JEH7X', 'realvnc_server'),
        ('package', 'windows', 'winget', 'realvnc.vncserver', 'realvnc_server'),
        ('package', 'macos', 'brew_cask', 'vnc-server', 'realvnc_server'),

        ('macos_bundle_id', 'macos', '', 'com.tigervnc.tigervnc', 'tigervnc'),
        ('macos_team_id', 'macos', 'com.tigervnc.tigervnc', 'S5LX88A9BW', 'tigervnc'),
        ('package', 'windows', 'winget', 'tigervnc.tigervnc', 'tigervnc'),
        ('package', 'macos', 'brew_cask', 'tigervnc', 'tigervnc'),

        ('package', 'windows', 'winget', 'parsec.parsec', 'parsec'),
        ('package', 'macos', 'brew_cask', 'parsec', 'parsec'),

        ('package', 'windows', 'winget', 'zoho.zohoassist', 'zoho_assist')
)
UPDATE software_category_rules r
SET product_key = b.product_key
FROM backfill b
WHERE r.category_key = 'remote_access'
  AND r.state <> 'retired'
  AND r.identifier_type = b.identifier_type
  AND r.platform = b.platform
  AND r.qualifier = b.qualifier
  AND r.identifier_value = b.identifier_value
  AND r.product_key IS NULL;

INSERT INTO software_category_audit (entity_type, entity_id, action, actor, before, after)
SELECT 'rule', r.id, 'edit', 'migration:0198_duplicate_tools_category',
       jsonb_build_object('product_key', NULL),
       jsonb_build_object('product_key', r.product_key)
FROM software_category_rules r
WHERE r.category_key = 'remote_access' AND r.product_key IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM software_category_audit a
      WHERE a.entity_type = 'rule' AND a.entity_id = r.id
        AND a.actor = 'migration:0198_duplicate_tools_category'
  );

COMMENT ON TABLE software_categories IS
    'PAT-2015/PAT-2148/PAT-2151: server-side product category taxonomy (ai_tooling, remote_access, rmm_agent, pdf_editor, screen_recorder, vpn_client, password_manager, file_sync, video_conferencing, note_taking, ...).';

INSERT INTO schema_migrations (version) VALUES ('0198_duplicate_tools_category')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
