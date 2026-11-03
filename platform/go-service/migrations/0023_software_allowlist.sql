-- 0023_software_allowlist.sql
-- Per-tenant software allowlist store + OS-baseline seed.
--
-- Allows Patched admins to maintain a per-tenant list of approved applications.
-- Apps not in the list surface as "unreviewed" (default-allow) or flagged
-- (default-deny mode). Each entry can carry an enforcement action:
--   allowed            → approved, take no action
--   flagged            → surface in the dashboard as unapproved drift
--   marked_for_uninstall → intent queued; actual execution is agent-side (PAT-118/PAT-376)
--
-- Match modes (MVP implements exact_name + name_publisher only):
--   exact_name         → LOWER(app.name)      = LOWER(entry.name)
--   name_publisher     → exact_name AND LOWER(app.publisher) = LOWER(entry.publisher)
--   publisher_only     → LOWER(app.publisher) = LOWER(entry.publisher)
--
-- ⚠️  Write path: PAT-66 gate applies before any enforcement action drives
-- agent behaviour on customer endpoints. MVP is flag-only (no agent-side acts).

BEGIN;

-- OS-baseline: apps shipped with macOS / Windows that are always approved
-- and never surfaced as drift. Inherited by all tenants; not editable per-tenant.
-- (Per-tenant overrides can set a specific baseline app to flagged if needed.)
CREATE TABLE allowlist_baseline_apps (
    id          BIGSERIAL    PRIMARY KEY,
    platform    TEXT         NOT NULL CHECK (platform IN ('macos', 'windows', 'any')),
    name        TEXT         NOT NULL,
    publisher   TEXT,
    category    TEXT         NOT NULL DEFAULT 'system',
    notes       TEXT         NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_allowlist_baseline_platform_name
    ON allowlist_baseline_apps (platform, LOWER(name));

-- Per-tenant allowlist entries
CREATE TABLE tenant_allowlists (
    id              BIGSERIAL    PRIMARY KEY,
    tenant_id       UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    platform        TEXT         NOT NULL DEFAULT 'any'
                        CHECK (platform IN ('macos', 'windows', 'any')),
    name            TEXT         NOT NULL,
    publisher       TEXT,
    match_mode      TEXT         NOT NULL DEFAULT 'exact_name'
                        CHECK (match_mode IN ('exact_name', 'name_publisher', 'publisher_only')),
    enforcement     TEXT         NOT NULL DEFAULT 'allowed'
                        CHECK (enforcement IN ('allowed', 'flagged', 'marked_for_uninstall')),
    approved_by     TEXT         NOT NULL DEFAULT '',
    notes           TEXT         NOT NULL DEFAULT '',
    approved_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
-- Expression-based unique index (LOWER(name)) — cannot be expressed as an inline
-- table constraint in PostgreSQL; must be a separate CREATE UNIQUE INDEX.
CREATE UNIQUE INDEX idx_tenant_allowlists_unique
    ON tenant_allowlists (tenant_id, platform, LOWER(name), match_mode);
CREATE INDEX idx_tenant_allowlists_tenant ON tenant_allowlists (tenant_id);

-- Per-tenant default stance: false = default-allow (flag unknowns), true = default-deny
ALTER TABLE tenants ADD COLUMN allowlist_default_deny BOOLEAN NOT NULL DEFAULT false;

-- Append-only audit log for allowlist changes
CREATE TABLE tenant_allowlist_changes (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entry_id    BIGINT,      -- NULL for default_deny toggle
    action      TEXT         NOT NULL,
    -- action values: 'added','removed','enforcement_changed','default_deny_on','default_deny_off'
    actor       TEXT         NOT NULL DEFAULT 'dashboard',
    detail      JSONB        NOT NULL DEFAULT '{}',
    changed_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tenant_allowlist_changes_tenant ON tenant_allowlist_changes (tenant_id);

-- ── macOS baseline seed ───────────────────────────────────────────────────────
-- Apple OS-shipped apps; always approved across all tenants.
INSERT INTO allowlist_baseline_apps (platform, name, publisher, category) VALUES
-- Core system
('macos', 'Finder',             'Apple Inc.',  'system'),
('macos', 'Spotlight',          'Apple Inc.',  'system'),
('macos', 'System Preferences', 'Apple Inc.',  'system'),
('macos', 'System Settings',    'Apple Inc.',  'system'),
('macos', 'System Information', 'Apple Inc.',  'system'),
('macos', 'App Store',          'Apple Inc.',  'system'),
('macos', 'Software Update',    'Apple Inc.',  'system'),
-- Productivity
('macos', 'Safari',             'Apple Inc.',  'browser'),
('macos', 'Mail',               'Apple Inc.',  'productivity'),
('macos', 'Calendar',           'Apple Inc.',  'productivity'),
('macos', 'Contacts',           'Apple Inc.',  'productivity'),
('macos', 'Reminders',          'Apple Inc.',  'productivity'),
('macos', 'Notes',              'Apple Inc.',  'productivity'),
('macos', 'Messages',           'Apple Inc.',  'messaging'),
('macos', 'FaceTime',           'Apple Inc.',  'communication'),
('macos', 'Maps',               'Apple Inc.',  'productivity'),
-- Media
('macos', 'Photos',             'Apple Inc.',  'media'),
('macos', 'Music',              'Apple Inc.',  'media'),
('macos', 'TV',                 'Apple Inc.',  'media'),
('macos', 'Books',              'Apple Inc.',  'media'),
('macos', 'Podcasts',           'Apple Inc.',  'media'),
('macos', 'News',               'Apple Inc.',  'media'),
('macos', 'Stocks',             'Apple Inc.',  'media'),
('macos', 'Weather',            'Apple Inc.',  'media'),
('macos', 'Voice Memos',        'Apple Inc.',  'media'),
('macos', 'QuickTime Player',   'Apple Inc.',  'media'),
-- Utilities
('macos', 'TextEdit',           'Apple Inc.',  'utility'),
('macos', 'Preview',            'Apple Inc.',  'utility'),
('macos', 'Calculator',         'Apple Inc.',  'utility'),
('macos', 'Clock',              'Apple Inc.',  'utility'),
('macos', 'Font Book',          'Apple Inc.',  'utility'),
('macos', 'Stickies',           'Apple Inc.',  'utility'),
('macos', 'Dictionary',         'Apple Inc.',  'utility'),
('macos', 'Screenshot',         'Apple Inc.',  'utility'),
('macos', 'Image Capture',      'Apple Inc.',  'utility'),
('macos', 'Image Viewer',       'Apple Inc.',  'utility'),
-- IT / Admin
('macos', 'Terminal',           'Apple Inc.',  'admin'),
('macos', 'Activity Monitor',   'Apple Inc.',  'admin'),
('macos', 'Disk Utility',       'Apple Inc.',  'admin'),
('macos', 'Console',            'Apple Inc.',  'admin'),
('macos', 'Keychain Access',    'Apple Inc.',  'admin'),
('macos', 'Directory Utility',  'Apple Inc.',  'admin'),
('macos', 'Migration Assistant','Apple Inc.',  'admin'),
('macos', 'Time Machine',       'Apple Inc.',  'admin'),
('macos', 'Bluetooth Screen Lock', 'Apple Inc.', 'admin'),
('macos', 'Automator',          'Apple Inc.',  'admin'),
('macos', 'Script Editor',      'Apple Inc.',  'admin'),
('macos', 'ColorSync Utility',  'Apple Inc.',  'admin'),
('macos', 'Digital Color Meter','Apple Inc.',  'admin'),
('macos', 'Grapher',            'Apple Inc.',  'admin'),
('macos', 'Xcode',              'Apple Inc.',  'developer'),
-- ── Windows baseline seed ─────────────────────────────────────────────────────
('windows', 'Microsoft Edge',                'Microsoft Corporation', 'browser'),
('windows', 'Microsoft Edge WebView2 Runtime','Microsoft Corporation', 'system'),
('windows', 'Windows Security',              'Microsoft Corporation', 'system'),
('windows', 'Windows Defender',              'Microsoft Corporation', 'system'),
('windows', 'Windows Update',                'Microsoft Corporation', 'system'),
('windows', 'OneDrive',                      'Microsoft Corporation', 'productivity'),
('windows', 'Notepad',                       'Microsoft Corporation', 'utility'),
('windows', 'Paint',                         'Microsoft Corporation', 'utility'),
('windows', 'Calculator',                    'Microsoft Corporation', 'utility'),
('windows', 'Photos',                        'Microsoft Corporation', 'media'),
('windows', 'Windows Media Player',          'Microsoft Corporation', 'media'),
('windows', 'Snipping Tool',                 'Microsoft Corporation', 'utility'),
('windows', 'Task Manager',                  'Microsoft Corporation', 'admin'),
('windows', 'PowerShell',                    'Microsoft Corporation', 'admin'),
('windows', 'Windows PowerShell',            'Microsoft Corporation', 'admin'),
('windows', 'Remote Desktop Connection',     'Microsoft Corporation', 'admin'),
('windows', 'Event Viewer',                  'Microsoft Corporation', 'admin'),
('windows', 'Device Manager',               'Microsoft Corporation', 'admin');

INSERT INTO schema_migrations (version) VALUES ('0023_software_allowlist');

COMMIT;
