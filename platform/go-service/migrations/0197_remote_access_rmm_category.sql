-- patched.im - 0197_remote_access_rmm_category.sql
-- PAT-2148 (child of PAT-2146 "SAM reports"): a "remote_access" category tag
-- (internal/categorytag, PAT-2015/PAT-2001) for remote access tools across
-- the estate, and a separate "rmm_agent" category so an MSP's own RMM
-- tooling is never flagged as an unsanctioned remote-access finding.
--
-- Additive only: two software_categories rows, their subtypes, and the
-- reviewed seed rules for both. Unlike 0163 (which deliberately left
-- PAT-2016's AI-tooling rule seed out of the migration, entered instead
-- through the admin API's own audit path), PAT-2148 asks explicitly for the
-- seed and its verification to be recorded here, so this migration also
-- inserts the software_category_audit 'create' row for every rule it adds --
-- the same before/after record the admin API would have written -- to keep
-- the append-only audit trail complete for these rows too.
--
-- Matching is categorytag's own exact-equality match (internal/categorytag),
-- never a substring or display-name guess: identifier_value/qualifier below
-- are already normalised exactly as internal/categorytag.NormalizeRule would
-- normalise them (macOS bundle IDs and package/browser-extension identifiers
-- lower-cased, Team IDs upper-cased 10 characters). This report evaluates
-- these rules directly against live software_installations /
-- device_browser_extensions rows (internal/remoteaccess), so no backfill of
-- software_category_tags is required for the report to be correct from the
-- moment this migration lands; ReconcileAll (categorytag) will still
-- materialise tags for /v1/portal/tagged-products the normal way whenever it
-- next runs.
--
-- ================================ Verification ================================
-- Every identifier below was checked against a primary source at the time of
-- writing (2026-09-26); nothing here is invented. Sources, by identifier type:
--
--   * Homebrew cask tokens: fetched https://formulae.brew.sh/api/cask/<token>.json
--     directly and confirmed a 200 response for every cask token seeded here
--     (anydesk, teamviewer, splashtop-business, splashtop-streamer, rustdesk,
--     realvnc-connect-viewer, vnc-server, tigervnc, parsec). zoho-assist and a
--     LogMeIn/GoTo cask were checked and do NOT exist (404) -- omitted, not
--     guessed.
--   * Windows winget IDs: confirmed by listing the exact manifest directory
--     in github.com/microsoft/winget-pkgs via the GitHub API (a 200 with a
--     real version folder listed, not just a repo search hit) for AnyDesk,
--     TeamViewer, Splashtop (Business and Streamer), RealVNC (Viewer and
--     Server), TigerVNC, Parsec, Zoho Assist, and GoTo's LogMeIn client and
--     GoToAssist console. RustDesk has no winget package (confirmed 404
--     under every plausible publisher spelling) -- omitted.
--   * Chrome Remote Desktop's extension ID (inomeogfingihgjfjlpeplalcfajhgai)
--     was confirmed live on the Chrome Web Store at the time of writing. A
--     legacy/deprecated id (gbchcmhmhahfdphkhkmpfmihenigjmpp) surfaced during
--     research and is deliberately NOT seeded.
--   * macOS bundle IDs and Apple Developer Team IDs came from Installomator
--     (the community-maintained macOS deployment label set every MDM admin
--     in this space cross-checks against), itself cross-checked against
--     vendor documentation (RealVNC's own help center) or the vendor's own
--     public source (RustDesk and TigerVNC ship their bundle identifier in
--     their own GitHub repository -- Cargo.toml / Info.plist.in). These are
--     a well-established secondary source, not a from-the-binary signature
--     check; if one of these ever fails to match a real device's Team ID,
--     retire the rule and re-derive it from that tenant's own observed
--     evidence rather than trusting this comment over the device.
--
-- Explicitly NOT seeded, because no primary source could confirm an exact
-- identifier (verify before adding a rule; do not guess one from this list):
--   * ScreenConnect / ConnectWise Control -- ships as a per-customer branded
--     installer with a unique certificate thumbprint per instance. There is
--     no single stable identity an exact-match rule can key on; categorytag
--     has no substring/pattern rule type. Open gap.
--   * TightVNC, UltraVNC -- no winget package, no Homebrew cask, no
--     confirmed macOS build (both are Windows-only in practice). Open gap.
--   * LogMeIn Pro / GoTo macOS clients, Parsec's macOS bundle ID, Zoho
--     Assist's macOS bundle IDs -- no primary-source confirmation found.
--   * Every RMM agent below except NinjaOne's remote-control sub-component --
--     NinjaOne, Datto RMM, N-able N-central, Kaseya VSA, ConnectWise
--     Automate, Atera and Syncro all ship as tenant/account-branded
--     installers (confirmed: no winget package, no Homebrew cask, under
--     every plausible publisher spelling). Their generic-agent Authenticode
--     signer and macOS bundle identity could not be verified from a primary
--     source in the time available. Recommendation: capture the real
--     identity from one of Andy's own live MSP-managed devices (or a
--     vendor-confirmed PPPC/deployment doc) and add it through the admin API
--     (never invent a signer string), so it gets its own reviewed audit
--     entry the way every other rule here has.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0197_remote_access_rmm_category.sql

BEGIN;

INSERT INTO software_categories (key, display_name, description) VALUES
    ('remote_access', 'Remote access tools',
     'Applications, browser extensions and Homebrew casks that give a person remote control of a device -- screen sharing, remote desktop and unattended-access tools. Unmanaged remote access is a common way in.'),
    ('rmm_agent', 'RMM agents',
     'Remote monitoring and management agents (the tooling an MSP itself deploys to manage an estate), tagged separately from remote_access so an MSP''s own tooling is never flagged as an unsanctioned remote access finding.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO software_category_subtypes (category_key, key, display_name) VALUES
    ('remote_access', 'desktop_app', 'Desktop app'),
    ('remote_access', 'browser_extension', 'Browser extension'),
    ('rmm_agent', 'agent', 'RMM agent')
ON CONFLICT (category_key, key) DO NOTHING;

-- Seed rules. state = 'published' with published_at set, exactly as the
-- admin API leaves a rule after create-then-publish, so the report and
-- ReconcileAll both see them as live immediately.
INSERT INTO software_category_rules
    (identifier_type, identifier_value, qualifier, platform, category_key, subtype_key, notes,
     version, state, created_by, published_at)
VALUES
    -- AnyDesk. macOS: Installomator (expectedTeamID). Windows: winget
    -- AnyDesk.AnyDesk confirmed (manifest directory listing, 200). Cask:
    -- formulae.brew.sh/api/cask/anydesk.json confirmed 200.
    ('macos_bundle_id', 'com.philandro.anydesk', '', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID cross-check; AnyDesk desktop client.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'KHRWM533LU', 'com.philandro.anydesk', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID for com.philandro.anydesk.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'anydesk.anydesk', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/a/AnyDesk/AnyDesk confirmed present (200, version 9.7.16 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'anydesk', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/anydesk.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- TeamViewer (client and Host variant share one Team ID).
    ('macos_bundle_id', 'com.teamviewer.teamviewer', '', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID cross-check; TeamViewer desktop client.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'H7UGFBUGV6', 'com.teamviewer.teamviewer', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID for com.teamviewer.teamviewer.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_bundle_id', 'com.teamviewer.teamviewerhost', '', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID cross-check; TeamViewer Host (unattended access) variant.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'H7UGFBUGV6', 'com.teamviewer.teamviewerhost', 'macos', 'remote_access', 'desktop_app',
     'Same signing Team ID as com.teamviewer.teamviewer (Installomator cross-check).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'teamviewer.teamviewer', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/t/TeamViewer/TeamViewer confirmed present (200, version 15.59.5 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'teamviewer', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/teamviewer.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- Splashtop: Streamer (host) and Business (client) are separate products.
    ('macos_bundle_id', 'com.splashtop.splashtop-streamer', '', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID cross-check; Splashtop Streamer (host) app.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'CPQQ3AW49Y', 'com.splashtop.splashtop-streamer', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID for com.splashtop.splashtop-streamer.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'splashtop.splashtopbusiness', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/s/Splashtop/SplashtopBusiness confirmed present (200, version 3.5.2.1 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'splashtop-business', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/splashtop-business.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'splashtop.splashtopstreamer', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/s/Splashtop/SplashtopStreamer confirmed present (200, version 3.5.0.0 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'splashtop-streamer', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/splashtop-streamer.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- RustDesk (open-source; no winget package -- confirmed 404, omitted).
    ('macos_bundle_id', 'com.carriez.rustdesk', '', 'macos', 'remote_access', 'desktop_app',
     'rustdesk/rustdesk Cargo.toml [package.metadata.bundle] identifier (vendor source), Installomator cross-check.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'HZF9JMC8YN', 'com.carriez.rustdesk', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID for com.carriez.rustdesk.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'rustdesk', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/rustdesk.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- GoTo / LogMeIn: Windows only here -- no macOS bundle ID or Homebrew
    -- cask could be confirmed from a primary source.
    ('package', 'goto.logmeinclient', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/g/GoTo/LogMeInClient confirmed present (200, version 1.3.5692 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'goto.gotoassistagentdesktopconsole', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/g/GoTo/GoToAssistAgentDesktopConsole confirmed present (200, version 5.9.6.56 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- Chrome Remote Desktop: the extension is the product; no separate native
    -- host app identity is seeded.
    ('browser_extension', 'inomeogfingihgjfjlpeplalcfajhgai', 'chrome_web_store', 'any', 'remote_access', 'browser_extension',
     'Chrome Web Store listing for Chrome Remote Desktop confirmed live at this extension ID (200) at time of writing. A legacy id (gbchcmhmhahfdphkhkmpfmihenigjmpp) was seen during research and deliberately not seeded.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- RealVNC: Viewer and Server (Connect) are separate binaries, same
    -- signing Team ID.
    ('macos_bundle_id', 'com.realvnc.vncviewer', '', 'macos', 'remote_access', 'desktop_app',
     'RealVNC help center + Installomator cross-check; VNC Viewer.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'ZNCQ8JEH7X', 'com.realvnc.vncviewer', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID for com.realvnc.vncviewer.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'realvnc.vncviewer', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/r/RealVNC/VNCViewer confirmed present (200, version 6.22.315.46706 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'realvnc-connect-viewer', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/realvnc-connect-viewer.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_bundle_id', 'com.realvnc.vncagent', '', 'macos', 'remote_access', 'desktop_app',
     'RealVNC help center + Installomator cross-check; VNC Server (Connect) agent.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'ZNCQ8JEH7X', 'com.realvnc.vncagent', 'macos', 'remote_access', 'desktop_app',
     'Same signing Team ID as com.realvnc.vncviewer (Installomator cross-check).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'realvnc.vncserver', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/r/RealVNC/VNCServer confirmed present (200, version 6.11.0.47988 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'vnc-server', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/vnc-server.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- TigerVNC. No winget/cask exists for TightVNC or UltraVNC (checked;
    -- 404 under every plausible id) -- deliberately not seeded.
    ('macos_bundle_id', 'com.tigervnc.tigervnc', '', 'macos', 'remote_access', 'desktop_app',
     'TigerVNC vendor GitHub source (release/Info.plist.in), Installomator cross-check.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('macos_team_id', 'S5LX88A9BW', 'com.tigervnc.tigervnc', 'macos', 'remote_access', 'desktop_app',
     'Installomator expectedTeamID for com.tigervnc.tigervnc.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'tigervnc.tigervnc', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/t/TigerVNC/TigerVNC confirmed present (200, versions up to 1.16.2 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'tigervnc', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/tigervnc.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- Parsec. macOS bundle ID not confirmed from a primary source for the
    -- macOS build specifically -- deliberately not seeded; winget and cask
    -- are both confirmed.
    ('package', 'parsec.parsec', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/p/Parsec/Parsec confirmed present (200, version 150.104.1.0 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),
    ('package', 'parsec', 'brew_cask', 'macos', 'remote_access', 'desktop_app',
     'formulae.brew.sh/api/cask/parsec.json confirmed 200.', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- Zoho Assist. No Homebrew cask exists (checked; 404); macOS bundle IDs
    -- seen during research came only from a third-party app-database site,
    -- not a primary source, so deliberately not seeded.
    ('package', 'zoho.zohoassist', 'winget', 'windows', 'remote_access', 'desktop_app',
     'winget-pkgs manifests/z/Zoho/ZohoAssist confirmed present (200, version 2.8.4 listed).', 1, 'published', 'migration:0197_remote_access_rmm_category', now()),

    -- RMM agents. Every vendor below except NinjaOne's remote-control
    -- sub-component ships as a tenant/account-branded installer with no
    -- winget package or Homebrew cask (checked under every plausible
    -- publisher spelling) and no generic-agent Authenticode/Team ID that
    -- could be confirmed from a primary source in the time available:
    -- Datto RMM, N-able N-central, Kaseya VSA, ConnectWise Automate, Atera
    -- and Syncro are therefore NOT seeded here. See the header comment for
    -- the recommendation (verify from a live deployment, then add through
    -- the admin API).
    ('macos_bundle_id', 'com.ninjarmm.ncstreamer', '', 'macos', 'rmm_agent', 'agent',
     'NinjaOne''s macOS remote-control sub-component, bundled with the NinjaRMM agent (this is the one NinjaOne identifier confirmed from research at the time of writing; the main agent''s own macOS bundle ID and every other vendor''s identity remain unverified -- see header comment).', 1, 'published', 'migration:0197_remote_access_rmm_category', now())
ON CONFLICT (identifier_type, platform, qualifier, identifier_value, category_key, subtype_key) WHERE state <> 'retired' DO NOTHING;

-- Append-only audit: one 'create' entry per rule this migration added,
-- mirroring what the admin API's CreateRule + PublishRule would have
-- written (before = NULL, after = the published row).
INSERT INTO software_category_audit (entity_type, entity_id, action, actor, before, after)
SELECT 'rule', r.id, 'create', r.created_by, NULL,
       jsonb_build_object(
           'identifier_type', r.identifier_type, 'identifier_value', r.identifier_value,
           'qualifier', r.qualifier, 'platform', r.platform,
           'category_key', r.category_key, 'subtype_key', r.subtype_key,
           'notes', r.notes, 'version', r.version, 'state', r.state, 'published_at', r.published_at)
FROM software_category_rules r
WHERE r.created_by = 'migration:0197_remote_access_rmm_category'
  AND NOT EXISTS (
      SELECT 1 FROM software_category_audit a WHERE a.entity_type = 'rule' AND a.entity_id = r.id
  );

COMMENT ON TABLE software_categories IS
    'PAT-2015/PAT-2148: server-side product category taxonomy (ai_tooling, remote_access, rmm_agent, ...).';

INSERT INTO schema_migrations (version) VALUES ('0197_remote_access_rmm_category')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
