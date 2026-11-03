-- patched.im — 0130_macos_2_10_1_screensaver_inactivity.sql
-- PAT-1753: add the correctly-scoped CIS 2.10.1 screen saver inactivity rule.
--
-- migrations/0129 (PAT-1746) retired cis_macos_2_10_1_screensaver_timeout
-- because it evaluated screensaver_delay_seconds — the delay after the
-- screen saver starts (or the display sleeps) before a password is required
-- — as if it were the idle-to-activation interval. That row stays disabled;
-- it is not revived or reused here.
--
-- The updater agent (PAT-1720, updater repo) now emits the signal this
-- control actually needs: screensaver_idle_seconds. It reads
-- com.apple.screensaver idleTime through NSUserDefaults as the console user,
-- so an MDM-profile-forced value wins over a local default the same way
-- every other managed_pref_read signal does. idleTime 0 ("never") is sent as
-- the sentinel 99999 (the same sentinel Windows uses for
-- machine_inactivity_limit_seconds), which fails the lte-1200 check the same
-- as any other over-limit value. A null signal (the read failed, or the key
-- was never set) is treated as fail — the macOS default is not verified, so
-- absence cannot prove compliance.
--
-- 1. Add cis_macos_2_10_1_screensaver_inactivity (T1 — same collector call
--    that always emits screensaver_idle_seconds, so no reason to gate it
--    behind tenant_rules). CIS's "20 minutes or less" requirement maps to
--    lte 1200 seconds.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0130_macos_2_10_1_screensaver_inactivity.sql

BEGIN;

-- ============================================================================
-- 1. New rule: screen saver activates within 20 minutes of inactivity
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
    'cis_macos_2_10_1_screensaver_inactivity',
    'CIS Apple macOS', 'v3.0.0',
    'Ensure an Inactivity Interval of 20 Minutes or Less for the Screen Saver Is Enabled',
    'CIS §2.10.1 (PAT-1753). Signal is screensaver_idle_seconds: com.apple.screensaver idleTime, read through NSUserDefaults as the console user, so an MDM-profile-forced value wins over a local default. idleTime 0 ("never") is sent as the sentinel 99999, the same sentinel Windows uses for machine_inactivity_limit_seconds, which fails this check the same as any other over-limit value. A missing signal (the read failed, or the key is not set) is treated as fail; the macOS default is not verified. This is distinct from cis_macos_2_10_2_password_after_screensaver_delay, which checks the password grace period after the screen saver starts, not the idle interval before it starts. CIS requires 20 minutes (1200 seconds) or less.',
    'medium',
    'screensaver_idle_seconds', 'lte', ARRAY['1200'],
    NULL, 'fail',
    'T1', 'none', false,
    ARRAY['AC-11'], ARRAY['A.8.1'], ARRAY['secure-configuration'],
    'macos', true
)
ON CONFLICT (benchmark, benchmark_version, rule_key) DO NOTHING;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0130_macos_2_10_1_screensaver_inactivity')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
