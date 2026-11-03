-- patched.im — 0129_macos_2_10_2_password_after_screensaver_delay.sql
-- PAT-1746: cis_macos_2_10_1_screensaver_timeout checks the wrong control.
--
-- screensaver_delay_seconds is the delay AFTER the screen saver starts (or the
-- display turns off) before a password is required to unlock the session
-- again. On macOS 13+ the collector reads it from `sysadminctl -screenLock
-- status` (updater PAT-1743); on earlier macOS from the legacy
-- askForPasswordDelay plist key. It is not the idle/inactivity interval before
-- the screen saver engages, so a device with a 20-minute idle timeout and a
-- 10-minute password grace period incorrectly PASSED
-- cis_macos_2_10_1_screensaver_timeout's lte-1200-seconds check.
--
-- Andy's call (PAT-1746): add the correctly-scoped rule under a new key and
-- retire the old one rather than repoint it in place, so historical
-- compliance_evaluations rows for cis_macos_2_10_1_screensaver_timeout keep
-- their original meaning (they judged a 20-minute idle window, not a password
-- delay) instead of being silently reinterpreted.
--
-- 1. Add cis_macos_2_10_2_password_after_screensaver_delay (T1 — same
--    collector call as cis_macos_2_10_screensaver_password always emits this
--    signal, so there is no reason to gate it behind tenant_rules). CIS's
--    "5 seconds or immediately" requirement maps to lte 5.
-- 2. Disable cis_macos_2_10_1_screensaver_timeout (enabled = false). The row
--    is kept, not deleted or rewritten, so compliance_evaluations.rule_id
--    foreign keys and historical report/PDF rendering keep resolving to their
--    original title and description. internal/evaluator.LoadRules (T1) and
--    LoadRulesForTenant (T2) both filter on enabled = true, as do the
--    benchmark-totals queries in internal/handlers/posture.go and
--    internal/report/report.go and the current-rules export in
--    internal/report/xlsx.go, so the disabled row stops being evaluated,
--    stops counting toward benchmark totals, and drops out of the current
--    rule-set export — while report joins against compliance_evaluations by
--    rule_id (report.go, portal.go, admin.go, executive.go, xlsx.go,
--    tenant_export.go) carry no enabled filter, so historical evaluations
--    still render correctly.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0129_macos_2_10_2_password_after_screensaver_delay.sql

BEGIN;

-- ============================================================================
-- 1. New rule: password required after screen saver / display sleep begins
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    nist_mappings, iso_mappings, cyber_essentials_mappings,
    platform, enabled
) VALUES (
    'cis_macos_2_10_2_password_after_screensaver_delay',
    'CIS Apple macOS', 'v3.0.0',
    'Ensure Require Password After Screen Saver Begins or Display Is Turned Off Is Enabled for 5 Seconds or Immediately',
    'CIS §2.10.2 (PAT-1746). Signal is screensaver_delay_seconds: the delay after the screen saver starts or the display sleeps before the session requires a password to unlock, read via sysadminctl -screenLock status on macOS 13+ and via the legacy askForPasswordDelay plist key on earlier macOS. This is distinct from cis_macos_2_10_1_screensaver_timeout''s idle-to-activation interval (now retired — it does not measure this control). A missing signal is treated as fail; CIS requires 5 seconds or immediate.',
    'medium',
    'screensaver_delay_seconds', 'lte', ARRAY['5'],
    NULL, 'fail',
    'T1', 'none', false,
    ARRAY['AC-11'], ARRAY['A.8.1'], ARRAY['secure-configuration'],
    'macos', true
)
ON CONFLICT (benchmark, benchmark_version, rule_key) DO NOTHING;

-- ============================================================================
-- 2. Retire the mislabelled rule. Row kept (not deleted) so historical
--    compliance_evaluations keep their original meaning; only its enabled
--    flag changes.
-- ============================================================================

UPDATE compliance_rules
SET enabled = false
WHERE rule_key = 'cis_macos_2_10_1_screensaver_timeout'
  AND benchmark = 'CIS Apple macOS'
  AND benchmark_version = 'v2.1.0';

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0129_macos_2_10_2_password_after_screensaver_delay')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
