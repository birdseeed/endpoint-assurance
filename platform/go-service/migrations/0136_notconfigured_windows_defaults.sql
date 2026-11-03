-- patched.im — 0136_notconfigured_windows_defaults.sql
-- PAT-1772 (server half): treat_not_configured_as for the 14 Windows
-- compliance signals the agent-side change (PAT-1772, updater) now reports
-- as the exact string "NotConfigured" when the read succeeds and the
-- setting is genuinely absent, instead of a hardcoded default value.
--
-- Goal: zero score movement. Each treat_not_configured_as value below
-- reproduces exactly what today's live scoring already does for an absent
-- signal, so this ships with no outcome change for any tenant. All 14 rows
-- use comparator = 'eq' with expected_values ['Yes'] (defender_realtime
-- uses ['enabled']); every one currently has treat_not_configured_as = NULL
-- (added by 0131_treat_not_configured_as.sql, never subsequently set for
-- these rule_keys, verified against 0019/0027/0028/0041 and every migration
-- after them).
--
-- 'pass' rows: the agent previously hardcoded a real "Yes"/"enabled" value
-- for the absent case, so today's live outcome is pass; treat_not_configured_as
-- = 'pass' reproduces that.
-- 'fail' rows: the agent previously hardcoded a real "No" value for the
-- absent case, which fails the 'eq' comparator against ['Yes']; treat_not_configured_as
-- = 'fail' reproduces that.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0136_notconfigured_windows_defaults.sql

BEGIN;

-- ============================================================================
-- 'pass' group — absent previously hardcoded to a passing value
-- ============================================================================

UPDATE compliance_rules
SET treat_not_configured_as = 'pass'
WHERE rule_key IN (
    'cis_win_18_9_45_defender_realtime',
    'cis_win_18_4_3_smbv1_client_disabled',
    'cis_win_18_9_85_1_always_install_elevated_disabled',
    'cis_win_18_3_7_wdigest_cleartext_disabled',
    'cis_win_18_9_47_9_defender_behavior_monitoring',
    'cis_win_18_9_47_11_defender_archive_scanning'
)
  AND treat_not_configured_as IS NULL;

-- ============================================================================
-- 'fail' group — absent previously hardcoded to a failing value
-- ============================================================================

UPDATE compliance_rules
SET treat_not_configured_as = 'fail'
WHERE rule_key IN (
    'cis_win_18_6_4_1_llmnr_disabled',
    'cis_win_18_9_8_2_autoplay_disabled',
    'cis_win_18_8_36_1_remote_assistance_disabled',
    'cis_win_18_9_47_4_1_defender_cloud_protection',
    'cis_win_18_9_47_4_2_defender_sample_submission',
    'cis_win_18_9_47_8_defender_pua_protection',
    'cis_win_18_9_47_12_defender_scan_removable_drives'
)
  AND treat_not_configured_as IS NULL;

-- ============================================================================
-- Discrepancy, not silently resolved: nist_win_ac2_laps_enrolled
--
-- This rule's own row (0041_windows_nist_l1_expansion.sql) carries
-- treat_unknown_as = 'pass' and a description stating "Unknown / absent =
-- LAPS managed externally; treat as pass." — an intent authored before the
-- NotConfigured/Unknown split existed. If this migration matched that
-- authored intent, treat_not_configured_as would be 'pass'.
--
-- It is NOT 'pass' here. The agent's actual shipped behaviour before this
-- ticket hardcoded the absent case to a real "No" value, which fails the
-- 'eq' comparator against ['Yes'] — so the live, currently-shipping score
-- for an absent LAPS signal is fail, not pass. This migration's explicit
-- goal is zero score movement ("so no outcome shifts"), so
-- treat_not_configured_as = 'fail' is what's set below, matching current
-- behaviour rather than the rule's originally-authored intent.
--
-- Follow-up recommended (separate ticket, not this one): reconcile
-- treat_unknown_as = 'pass' and the "treat as pass" description text against
-- the 'fail' outcome this migration now locks in for the absent case. That
-- is a deliberate policy question — whether an unmanaged/absent LAPS signal
-- should pass or fail — not something to resolve inside a same-outcome
-- migration.
-- ============================================================================

UPDATE compliance_rules
SET treat_not_configured_as = 'fail'
WHERE rule_key = 'nist_win_ac2_laps_enrolled'
  AND treat_not_configured_as IS NULL;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0136_notconfigured_windows_defaults')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
