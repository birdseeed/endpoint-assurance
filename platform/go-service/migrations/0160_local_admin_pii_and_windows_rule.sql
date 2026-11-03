-- patched.im — 0160_local_admin_pii_and_windows_rule.sql
-- PAT-1974: two changes, both about the same collection.
--
-- 1. Correct pii_observed for the existing macOS local_admin_count rule. The
--    comment 0005_tenant_rules.sql wrote for it ("Does not report account
--    names — count only") is now false: Patched-LTD/updater PR #631
--    (already merged) has the macOS agent emitting local_admins.accounts —
--    real account names — in every payload from the moment it shipped. This
--    is not new PII being introduced by THIS migration; it corrects the
--    documentation to match collection behaviour the agent already has in
--    the field. The signal itself (local_admin_count, a bare integer/
--    "Unknown"/null) is unchanged and still carries no names — the names
--    live in the separate local_admin_accounts table (migration 0159),
--    populated from the local_admins payload object, not from this rule's
--    own signal.
--
-- 2. Seed the Windows equivalent of cis_macos_5_8_local_admin_count.
--    local_admin_count is a platform-neutral signal_key — both the Windows
--    and macOS collectors emit the identical name (updater PR #631) — so
--    the only thing missing was a Windows rule row to evaluate it; the
--    signal itself needed no server-side change.
--
--    Rule key cis_win_5_8_local_admin_count deliberately mirrors the macOS
--    rule's own section number rather than tracking a real CIS Microsoft
--    Windows 11 Benchmark section: 5.8 in that benchmark is System Services,
--    not local admin membership, and there is no numbered CIS Windows
--    control for this exact heuristic (a Patched-chosen "lte 2" threshold)
--    any more than CIS Apple macOS Benchmark v3.0.0's real §5.8 is "Reduce
--    admin accounts" in every edition. cis_macos_5_8_local_admin_count was
--    already an approximate section number when it was seeded in 0003, not
--    a verified benchmark citation; this rule key follows that established
--    (if imperfect) precedent for the sake of an obviously-paired key rather
--    than inventing an unrelated Windows section number for what is, on
--    both platforms, the exact same heuristic over the exact same signal.
--
--    Same threshold (lte 2), same severity (medium), same NIST/ISO/CE
--    mappings as the macOS rule — this is one control evaluated from
--    platform-neutral evidence, not two independent controls that happen to
--    share a name.
--
-- requires_user_consent = false for both rows, deliberately decided here
-- rather than escalated: a local administrator roster is standard, expected
-- IT-administration telemetry an employer routinely holds about a
-- company-owned endpoint for security purposes. It is the same shape as the
-- existing screensaver_password precedent (0005: "root-readable... no
-- per-user consent required") — the roster is read from the OS's own local
-- admin-group membership record (dscl on macOS, NetLocalGroupGetMembers on
-- Windows), not from user-owned data, is not behavioural or content data,
-- and reveals nothing beyond "this account can administer this
-- company-owned machine", which is exactly the fact a company's IT function
-- is expected to know about its own estate. This differs from the
-- browser_extensions/certificates precedent only in degree, not in kind: it
-- is account identity, not activity. Nothing about this ticket's scope
-- (adding names to an already-collected count, not adding a new kind of
-- collection) calls for a different answer than the established
-- screensaver_password precedent.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0160_local_admin_pii_and_windows_rule.sql

BEGIN;

-- ── 1. Correct the macOS rule's pii_observed ────────────────────────────────

UPDATE compliance_rules
SET pii_observed = 'The local_admin_count signal itself is a bare number (or "Unknown"/null on a failed read) — no names. The same collection run also produces the separate local_admins.accounts roster (stored in local_admin_accounts, not compliance_signals), which does report real account names, e.g. "alice" or "MACHINE\\alice". This corrects the prior pii_observed text ("Does not report account names"), which was accurate when written but has not described actual collection behaviour since Patched-LTD/updater PR #631 shipped.'
WHERE signal_key = 'local_admin_count' AND platform = 'macos';

-- ── 2. Seed the Windows equivalent rule ─────────────────────────────────────

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_win_5_8_local_admin_count',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Limit local administrator accounts',
    'Standard accounts for daily work; admin rights granted only when needed. Heuristic threshold of 2 admins (typically one user account + one break-glass) is reasonable for SME single-seat endpoints — the same reasoning and threshold as the macOS rule (cis_macos_5_8_local_admin_count) over the identical local_admin_count signal. Counts every individually provisioned admin (local or directory-sourced user accounts, and SIDs the device could not resolve) but not directory-sourced group principals, whose own membership is opaque to the device.',
    'medium',
    'local_admin_count', 'lte', ARRAY['2'],
    NULL, 'fail',
    'T1',
    'The local_admin_count signal itself is a bare number (or "Unknown" on a failed read) — no names. The same collection run also produces the separate local_admins.accounts roster (stored in local_admin_accounts, not compliance_signals), which does report real account/group names and, where present, the account SID.',
    false,
    'windows',
    ARRAY['AC-6', 'AC-2'], ARRAY['A.9.2.3'], ARRAY['user-access-control']
);

INSERT INTO schema_migrations (version) VALUES ('0160_local_admin_pii_and_windows_rule')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
