-- patched.im — 0003_compliance_rules.sql
-- Adds the CIS L1 rule engine schema and seeds the v1 macOS L1 rule pack
-- (17 controls). The evaluator package in the Go service reads these tables on
-- every extraction and writes one row per (device, rule) into
-- compliance_evaluations.
--
-- Rules are intentionally data, not Go code:
--  * New CIS releases: INSERT new rows + bump benchmark_version, no binary push.
--  * Per-tenant exemptions (later): `enabled = false` for a single rule, or a
--    per-tenant overrides table layered on top.
--  * Backfill: re-running evaluator against historical raw_payloads gives
--    "what would today's CIS L1 say about last quarter?"
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0003_compliance_rules.sql

BEGIN;

-- ============================================================================
-- COMPLIANCE_RULES — versioned ruleset library
-- ============================================================================

CREATE TABLE compliance_rules (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_key                    TEXT NOT NULL,                 -- "cis_macos_2_5_1_1_filevault"
    benchmark                   TEXT NOT NULL,                 -- "CIS Apple macOS"
    benchmark_version           TEXT NOT NULL,                 -- "v3.0.0"
    title                       TEXT NOT NULL,
    description                 TEXT,
    severity                    TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    signal_key                  TEXT NOT NULL,                 -- compliance_signals.key being evaluated
    comparator                  TEXT NOT NULL CHECK (comparator IN ('eq','neq','in','contains','gte','lte')),
    expected_values             TEXT[] NOT NULL,               -- semantics depend on comparator
    applicable_arch             TEXT[],                        -- NULL = all archs, e.g. ['arm64']
    treat_unknown_as            TEXT NOT NULL DEFAULT 'fail' CHECK (treat_unknown_as IN ('pass','fail','not_applicable')),
    nist_mappings               TEXT[],                        -- e.g. ['SC-28','SI-7']
    iso_mappings                TEXT[],                        -- e.g. ['A.10.1.1']
    cyber_essentials_mappings   TEXT[],                        -- e.g. ['malware-protection']
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (benchmark, benchmark_version, rule_key)
);

CREATE INDEX idx_compliance_rules_enabled ON compliance_rules(enabled) WHERE enabled = true;

COMMENT ON COLUMN compliance_rules.expected_values IS
    'Semantics by comparator: eq/in -> any-of match; neq -> none-of; contains -> first element is substring; gte/lte -> first element is numeric bound.';
COMMENT ON COLUMN compliance_rules.applicable_arch IS
    'NULL means rule applies to all devices. Non-NULL = list of device.arch values the rule applies to; rules emit not_applicable on other archs.';
COMMENT ON COLUMN compliance_rules.treat_unknown_as IS
    'What status to emit when the device has no signal for this rule.key. Most controls fail-safe; a few (e.g. screensaver delay where -1 = Apple default) want pass.';

-- ============================================================================
-- COMPLIANCE_EVALUATIONS — per-device, per-rule outcomes (append-only)
-- ============================================================================

CREATE TABLE compliance_evaluations (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id             UUID NOT NULL REFERENCES compliance_rules(id),
    status              TEXT NOT NULL CHECK (status IN ('pass','fail','not_applicable','error')),
    observed_value      TEXT,                                -- what the signal read; NULL if signal missing
    severity            TEXT NOT NULL,                       -- denormalised from rule for cheap filtering
    benchmark_version   TEXT NOT NULL,                       -- denormalised from rule for historical reports
    evaluated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evals_device_evaluated ON compliance_evaluations(device_id, evaluated_at DESC);
CREATE INDEX idx_evals_rule_status      ON compliance_evaluations(rule_id, status);
CREATE INDEX idx_evals_failing          ON compliance_evaluations(device_id, severity)
    WHERE status = 'fail';

-- "Latest evaluation per (device, rule)" is the common dashboard query.
-- Materialised view kept out of MVP — a window function over the indexed
-- table is fast enough for v1 dashboard loads; revisit if it shows up hot.

-- ============================================================================
-- SEED: CIS Apple macOS v3.0.0 — Level 1 (v1 pack, 17 controls)
-- ============================================================================
--
-- Each rule maps to one signal emitted by patched-collect.sh schema_v2 (or its
-- synthetic siblings). Mappings are deliberately conservative — only frameworks
-- where the control is a direct corollary, not "we squint and see a fit".
-- NIST = SP 800-53 r5. ISO = 27001:2022 Annex A. CE = Cyber Essentials.

INSERT INTO compliance_rules
    (rule_key, benchmark, benchmark_version, title, description, severity,
     signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
     nist_mappings, iso_mappings, cyber_essentials_mappings)
VALUES
    ('cis_macos_2_5_1_1_filevault',
     'CIS Apple macOS', 'v3.0.0',
     'Enable FileVault',
     'Disk encryption protects data at rest. Required for any device that may store customer or business data.',
     'critical', 'filevault', 'eq', ARRAY['On'], NULL, 'fail',
     ARRAY['SC-28','SC-28(1)'], ARRAY['A.8.24','A.10.1.1'], ARRAY['secure-configuration']),

    ('cis_macos_2_5_3_sip',
     'CIS Apple macOS', 'v3.0.0',
     'Enable System Integrity Protection (SIP)',
     'Kernel-level protection against tampering with system files. Disabling SIP is a known attacker prerequisite for persistence.',
     'high', 'sip', 'eq', ARRAY['enabled'], NULL, 'fail',
     ARRAY['SI-7'], ARRAY['A.12.5.1'], ARRAY['secure-configuration']),

    ('cis_macos_2_5_2_1_gatekeeper',
     'CIS Apple macOS', 'v3.0.0',
     'Enable Gatekeeper',
     'Blocks execution of unsigned or improperly notarised binaries from the internet.',
     'high', 'gatekeeper', 'in', ARRAY['enabled','assessments'], NULL, 'fail',
     ARRAY['SI-7','SI-3'], ARRAY['A.12.2.1'], ARRAY['malware-protection']),

    ('cis_macos_2_5_2_2_firewall',
     'CIS Apple macOS', 'v3.0.0',
     'Enable the Application Layer Firewall',
     'Restricts inbound connections to allow-listed applications. Reduces lateral-movement surface on shared networks.',
     'high', 'firewall', 'eq', ARRAY['enabled'], NULL, 'fail',
     ARRAY['SC-7'], ARRAY['A.13.1.1'], ARRAY['firewalls']),

    ('cis_macos_2_5_5_sealed_system_volume',
     'CIS Apple macOS', 'v3.0.0',
     'Sealed System Volume integrity intact',
     'Apple Silicon and modern Intel macs ship the system volume sealed and cryptographically signed. A broken seal indicates tampering or an unsupported configuration.',
     'high', 'sealed_system_volume', 'in', ARRAY['enabled','true'], NULL, 'fail',
     ARRAY['SI-7'], ARRAY['A.12.5.1'], NULL),

    ('cis_macos_1_4_auto_security_updates',
     'CIS Apple macOS', 'v3.0.0',
     'Auto-install macOS security updates',
     'Critical CVE patches reach the endpoint without operator action. Drift here is the single largest contributor to known-vulnerable mac fleets in SME estates.',
     'high', 'auto_security_updates', 'eq', ARRAY['On'], NULL, 'fail',
     ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['security-update-management']),

    ('cis_macos_3_x_audit_logging',
     'CIS Apple macOS', 'v3.0.0',
     'Enable audit logging',
     'BSM/auditd-style event logging is needed for after-the-fact investigation. The Apple-default audit_control file present indicates a configured audit subsystem.',
     'medium', 'audit_logging', 'eq', ARRAY['enabled'], NULL, 'fail',
     ARRAY['AU-2','AU-12'], ARRAY['A.12.4.1'], NULL),

    ('cis_macos_2_4_1_remote_apple_events',
     'CIS Apple macOS', 'v3.0.0',
     'Disable Remote Apple Events',
     'Unused service; remote scripting capability surface that has no purpose on a managed endpoint.',
     'medium', 'remote_apple_events', 'eq', ARRAY['Off'], NULL, 'fail',
     ARRAY['AC-17','CM-7'], ARRAY['A.9.1.2'], NULL),

    ('cis_macos_2_4_4_remote_login',
     'CIS Apple macOS', 'v3.0.0',
     'Disable Remote Login (SSH)',
     'Inbound SSH is an attack surface that has no business case on managed endpoints. Admin access should go through MDM or Apple Remote Desktop, not raw SSH.',
     'high', 'remote_login', 'eq', ARRAY['Off'], NULL, 'fail',
     ARRAY['AC-17','CM-7'], ARRAY['A.9.1.2'], ARRAY['secure-configuration']),

    ('cis_macos_2_4_10_screen_sharing',
     'CIS Apple macOS', 'v3.0.0',
     'Disable Screen Sharing',
     'Inbound screen sharing is an attack surface that has no business case on managed endpoints.',
     'medium', 'screen_sharing', 'eq', ARRAY['Off'], NULL, 'fail',
     ARRAY['AC-17','CM-7'], ARRAY['A.9.1.2'], NULL),

    ('cis_macos_2_10_screensaver_password',
     'CIS Apple macOS', 'v3.0.0',
     'Require password to wake from screen saver / sleep',
     'Locks the device when the user steps away. Stops casual physical-access leaks in shared offices and lobbies. DefaultAssumed is the Apple-default state — password is required with a ~5s grace.',
     'medium', 'screensaver_password', 'in', ARRAY['Yes','DefaultAssumed'], NULL, 'fail',
     ARRAY['AC-11'], ARRAY['A.11.2.8'], NULL),

    ('cis_macos_5_1_auto_login_disabled',
     'CIS Apple macOS', 'v3.0.0',
     'Disable automatic login at boot',
     'Devices that auto-login bypass disk encryption pre-boot prompts and any account-level authentication — physical theft compromises both.',
     'high', 'auto_login_user', 'eq', ARRAY['None'], NULL, 'fail',
     ARRAY['IA-2'], ARRAY['A.9.4.2'], ARRAY['secure-configuration']),

    ('cis_macos_5_8_local_admin_count',
     'CIS Apple macOS', 'v3.0.0',
     'Limit local administrator accounts',
     'Standard accounts for daily work; admin rights granted only when needed. Heuristic threshold of 2 admins (typically one user account + one break-glass) is reasonable for SME single-seat endpoints.',
     'medium', 'local_admin_count', 'lte', ARRAY['2'], NULL, 'fail',
     ARRAY['AC-6','AC-2'], ARRAY['A.9.2.3'], ARRAY['user-access-control']),

    ('cis_macos_5_x_password_policy_non_default',
     'CIS Apple macOS', 'v3.0.0',
     'Password policy must not be the Apple-default 4-character fallback',
     'Out-of-the-box unmanaged Macs return Apple''s legacy 4-char policy. Anything is better than the default; MDM-managed devices push a proper policy.',
     'medium', 'password_policy_is_default', 'eq', ARRAY['No'], NULL, 'fail',
     ARRAY['IA-5(1)'], ARRAY['A.9.4.3'], ARRAY['user-access-control']),

    ('patched_mdm_enrolment',
     'patched.im baseline', 'v1',
     'Device is MDM-enrolled',
     'MDM is the centralised lever for everything else in this pack. Not strictly a CIS control, but customer auditors will ask. Included in the patched.im baseline ruleset.',
     'medium', 'mdm_enrolment', 'contains', ARRAY['mdm=Yes'], NULL, 'fail',
     NULL, NULL, NULL),

    ('cis_macos_1_1_pending_security_updates',
     'CIS Apple macOS', 'v3.0.0',
     'No outstanding macOS security updates',
     'Reflects the "softwareupdate -l" backlog at collection time. Pairs with rule 1.4 (auto-install); failure here on an auto-install-enabled device means the device is offline, in a maintenance window, or stuck on an update that needs a reboot.',
     'medium', 'pending_updates_count', 'eq', ARRAY['0'], NULL, 'fail',
     ARRAY['SI-2'], ARRAY['A.12.6.1'], ARRAY['security-update-management']),

    ('cis_macos_5_x_secure_boot_arm64',
     'CIS Apple macOS', 'v3.0.0',
     'Apple Silicon: Secure Boot integrity intact',
     'Apple Silicon devices report Secure Boot policy + pairing integrity. A non-"Full Security" / "Valid" reading indicates downgrade or tampering. Not applicable on Intel.',
     'high', 'secure_boot', 'in', ARRAY['Full Security','Valid'], ARRAY['arm64'], 'fail',
     ARRAY['SI-7','SI-7(1)'], ARRAY['A.12.5.1'], NULL);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0003_compliance_rules');

COMMIT;
