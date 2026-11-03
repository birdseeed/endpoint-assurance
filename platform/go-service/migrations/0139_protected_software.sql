-- patched.im — 0139_protected_software.sql
-- PAT-1801: protected software list — server-side enforcement so a
-- governance disposition decision (marking an application "unapproved",
-- queuing/targeting a removal, adding an item to a removal campaign's
-- scope) can never be pointed at security tooling: EDR, MDM agents, backup
-- agents, or Patched's own collector.
--
-- This is deliberately a separate concern from tenant_app_policies (0032)
-- and tenant_allowlists (0023): those tables record a tenant's OWN policy
-- decision about an app. protected_software instead records which
-- products a governance decision is not allowed to target at all,
-- regardless of what any tenant later decides. A row here does not grant
-- approval, drift-suppression or CVE-finding suppression — it only blocks
-- the specific disposition actions named above. CVE correlation
-- (device_cve_findings / cve_feed_entries, 0025) is untouched by this
-- table and must keep surfacing findings for a protected product exactly
-- as it would for anything else; protection is about disposition, not
-- visibility.
--
-- ── Shape: shared baseline + per-tenant additions ──────────────────────────
-- tenant_id NULL = shared baseline, seeded below and inherited by every
-- tenant. tenant_id set = a tenant's own addition, on top of the baseline.
-- This mirrors allowlist_baseline_apps/tenant_allowlists (0023): a global,
-- not-per-tenant-editable baseline plus a per-tenant table, rather than a
-- boolean flag column.
--
-- A tenant may freely ADD to their own protected list (INSERT a tenant-
-- scoped row via the API) — over-protecting is the safe direction. A
-- tenant may NOT delete a baseline row directly: baseline rows are shared
-- across every tenant, so a per-tenant DELETE would either do nothing (if
-- scoped by tenant_id) or silently unprotect the product for every OTHER
-- tenant too (if not). Removing a baseline protection for one tenant is
-- instead recorded as an explicit, audited override in
-- protected_software_overrides — see that table below.
--
-- ── Match-basis columns ──────────────────────────────────────────────────
-- bundle_id / team_id (macOS), signer / win_publisher + win_product_code
-- (Windows), process_name (fallback, also matched against product_name —
-- both are the same "weakest tier" per the ticket). A row does not need
-- every column filled; enforcement checks the strongest identifier
-- available first and only falls back to process_name/product_name
-- matching when no stronger identifier was supplied by the caller at all.
-- Fail-closed means exactly that and no more: a product that matches
-- nothing here is NOT protected — this migration and the enforcement code
-- built on it never fuzzy-match a "probably the EDR" case as protected.
--
-- ── Seed data confidence ───────────────────────────────────────────────────
-- Where the exact signer/bundle id is not something this migration can
-- state with confidence, the row uses the vendor's process/product name as
-- its match basis instead of inventing a plausible-looking but unverified
-- signer string. Each such row is commented "verify and tighten" below.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0139_protected_software.sql

BEGIN;

CREATE TABLE protected_software (
    id               BIGSERIAL    PRIMARY KEY,
    tenant_id        UUID         REFERENCES tenants(id) ON DELETE CASCADE,
    -- NULL tenant_id = shared baseline, inherited by every tenant.
    category         TEXT         NOT NULL
                          CHECK (category IN ('edr', 'mdm', 'backup', 'security', 'patched_agent', 'customer_defined')),
    vendor           TEXT         NOT NULL,
    product_name     TEXT         NOT NULL,
    bundle_id        TEXT,        -- macOS CFBundleIdentifier
    team_id          TEXT,        -- macOS Developer Team ID
    signer           TEXT,        -- Windows Authenticode signing identity
    win_publisher    TEXT,        -- Windows installed-program Publisher
    win_product_code TEXT,        -- Windows MSI ProductCode GUID
    process_name     TEXT,        -- fallback: executable/process or display name
    reason           TEXT         NOT NULL DEFAULT '',
    added_by         TEXT         NOT NULL DEFAULT '',
    added_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT protected_software_has_identity CHECK (
        bundle_id IS NOT NULL OR team_id IS NOT NULL OR signer IS NOT NULL OR
        win_publisher IS NOT NULL OR win_product_code IS NOT NULL OR process_name IS NOT NULL
    )
);

-- De-dup convenience index — COALESCE-to-'' so multiple NULL baseline rows
-- for genuinely different identities don't collide (same technique as
-- tenant_app_policies_tenant_identity_uniq, 0032).
CREATE UNIQUE INDEX idx_protected_software_identity
    ON protected_software (
        COALESCE(tenant_id::text, ''),
        COALESCE(bundle_id, ''),
        COALESCE(team_id, ''),
        COALESCE(signer, ''),
        COALESCE(win_publisher, ''),
        COALESCE(win_product_code, ''),
        COALESCE(lower(process_name), '')
    );

CREATE INDEX idx_protected_software_tenant ON protected_software (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE protected_software TO patched;
GRANT USAGE, SELECT ON SEQUENCE protected_software_id_seq TO patched;

-- ── Per-tenant baseline overrides ──────────────────────────────────────────
-- A tenant can only stop enforcing a BASELINE protection through this table,
-- never by deleting the baseline row itself. baseline_id must reference a
-- baseline row (tenant_id IS NULL) — enforced at the application layer
-- (Postgres cannot express a CHECK against another table's column), not by
-- a DB constraint here.
CREATE TABLE protected_software_overrides (
    id           BIGSERIAL    PRIMARY KEY,
    tenant_id    UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    baseline_id  BIGINT       NOT NULL REFERENCES protected_software(id) ON DELETE CASCADE,
    reason       TEXT         NOT NULL,
    removed_by   TEXT         NOT NULL,
    removed_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, baseline_id)
);
CREATE INDEX idx_protected_software_overrides_tenant ON protected_software_overrides (tenant_id);

GRANT SELECT, INSERT, DELETE ON TABLE protected_software_overrides TO patched;
GRANT USAGE, SELECT ON SEQUENCE protected_software_overrides_id_seq TO patched;

-- ── Audit log ───────────────────────────────────────────────────────────
-- Same shape as tenant_allowlist_changes (0023): a lightweight per-tenant
-- admin-action changelog, not the SIEM-grade append-only audit_events
-- (0098) — protected_software changes are infrequent, low-volume operator
-- actions, the same class of event tenant_allowlist_changes already
-- records for allowlist edits.
CREATE TABLE protected_software_changes (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entry_id    BIGINT,      -- protected_software.id ('added') or baseline_id ('baseline_override_removed')
    action      TEXT         NOT NULL,
    -- action values: 'added', 'baseline_override_removed'
    actor       TEXT         NOT NULL DEFAULT '',
    detail      JSONB        NOT NULL DEFAULT '{}',
    changed_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_protected_software_changes_tenant ON protected_software_changes (tenant_id);

GRANT SELECT, INSERT ON TABLE protected_software_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE protected_software_changes_id_seq TO patched;

-- ── Baseline seed ──────────────────────────────────────────────────────────
-- EDR. Signer/bundle-id values below are the vendor's well-known Windows
-- installed-program Publisher string and Windows service process names,
-- which are stable and easy to state with confidence. macOS bundle ids /
-- Developer Team IDs for these vendors are NOT asserted here — verify and
-- tighten with a real signed sample before relying on them for macOS.
INSERT INTO protected_software (category, vendor, product_name, win_publisher, process_name, reason, added_by) VALUES
('edr', 'CrowdStrike', 'CrowdStrike Falcon Sensor', 'CrowdStrike, Inc.', 'CSFalconService.exe',
    'EDR agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('edr', 'SentinelOne', 'SentinelOne Agent', 'SentinelOne, Inc.', 'SentinelAgent.exe',
    'EDR agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('edr', 'Microsoft', 'Microsoft Defender for Endpoint', 'Microsoft Corporation', 'MsSense.exe',
    'EDR agent (Defender ATP sense service) — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('edr', 'Sophos', 'Sophos Intercept X', 'Sophos Limited', 'SAVService.exe',
    'EDR agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed');

-- MDM agents. Jamf's `jamf` binary is a standalone executable, not a signed
-- .app bundle, so bundle_id/team_id are intentionally NULL here — verify and
-- tighten if Jamf ships a signed management daemon bundle id worth matching.
INSERT INTO protected_software (category, vendor, product_name, process_name, reason, added_by) VALUES
('mdm', 'Jamf', 'Jamf Pro Management Framework', 'jamf',
    'MDM management agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed');
INSERT INTO protected_software (category, vendor, product_name, win_publisher, process_name, reason, added_by) VALUES
('mdm', 'Microsoft', 'Microsoft Intune Management Extension', 'Microsoft Corporation', 'IntuneManagementExtension.exe',
    'MDM management agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('mdm', 'Microsoft', 'Microsoft Intune Company Portal', 'Microsoft Corporation', 'Company Portal',
    'MDM enrolment/management agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed');

-- Backup agents.
INSERT INTO protected_software (category, vendor, product_name, win_publisher, process_name, reason, added_by) VALUES
('backup', 'Backblaze', 'Backblaze Backup', 'Backblaze Inc.', 'bzbui.exe',
    'Backup agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('backup', 'Veeam', 'Veeam Agent', 'Veeam Software Group GmbH', 'Veeam.Backup.Service.exe',
    'Backup agent — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed');

-- Patched's own collector. Windows process names are the real AssemblyName
-- output of updater/windows/src/Service/Service.csproj and
-- updater/windows/src/Tray/Tray.csproj (Patched.Service.exe / Patched.Tray.exe)
-- as they ship today. macOS ships as unsigned shell scripts in the interim
-- (no Apple Developer ID yet — gated on PAT-7/9), so bundle_id/team_id are
-- intentionally NULL and the match basis is the collector's actual script
-- names (updater/macos/patched-collect.sh, updater/macos/patched-upload.sh).
-- Revisit once the signed .pkg (Developer ID + notarisation) lands.
INSERT INTO protected_software (category, vendor, product_name, win_publisher, process_name, reason, added_by) VALUES
('patched_agent', 'Patched', 'Patched Service', 'Patched.im Ltd', 'Patched.Service.exe',
    'Patched''s own collector/service process — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('patched_agent', 'Patched', 'Patched Tray', 'Patched.im Ltd', 'Patched.Tray.exe',
    'Patched''s own tray process — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed');
INSERT INTO protected_software (category, vendor, product_name, process_name, reason, added_by) VALUES
('patched_agent', 'Patched', 'Patched macOS Collector', 'patched-collect.sh',
    'Patched''s own collector script (unsigned interim macOS agent) — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed'),
('patched_agent', 'Patched', 'Patched macOS Uploader', 'patched-upload.sh',
    'Patched''s own uploader script (unsigned interim macOS agent) — must never be marked unapproved or targeted for removal via a governance workflow.', 'PAT-1801 baseline seed');

COMMENT ON TABLE protected_software IS
    'PAT-1801: products a governance disposition action (mark unapproved, removal request/campaign scope) may never target, whether a shared baseline (tenant_id NULL) or a tenant''s own addition. Does not grant approval or suppress CVE findings — disposition-only.';
COMMENT ON TABLE protected_software_overrides IS
    'PAT-1801: audited, per-tenant opt-out of one shared baseline protected_software row. The only way to stop enforcing a baseline protection for a tenant — baseline rows are never deleted per-tenant.';
COMMENT ON TABLE protected_software_changes IS
    'PAT-1801: admin-action changelog for protected_software, same shape/purpose as tenant_allowlist_changes (0023).';

INSERT INTO schema_migrations (version) VALUES ('0139_protected_software')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
