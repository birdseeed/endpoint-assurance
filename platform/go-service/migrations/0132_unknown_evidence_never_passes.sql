-- patched.im — 0132_unknown_evidence_never_passes.sql
-- PAT-1758 follow-up: unknown evidence must never raise a score.
--
-- PAT-1758 routes a present-but-unreadable signal (the collector's literal
-- "Unknown" sentinel) through treat_unknown_as, exactly like an absent key.
-- That is correct for the great majority of rules, whose treat_unknown_as is
-- 'fail'. It is NOT correct for a rule whose treat_unknown_as is 'pass' with
-- no treat_not_configured_as set: before PAT-1758, "Unknown" fell through to
-- the comparator (a real, usually-failing observation); after PAT-1758, that
-- same failed read now resolves to a pass. A missing evidence read must
-- never score better than a genuine check — "absence requires authority"
-- (root AGENTS.md) — so any such rule needs its unknown/not-configured
-- split correct before this ticket's fix reaches production.
--
-- A live query of api-01 (2026-09-15) found exactly three rules with
-- treat_unknown_as = 'pass' AND treat_not_configured_as IS NULL after 0131:
--
--   1. nist_win_ac2_laps_enrolled (windows, eq 'Yes')
--      The Windows agent (PAT-1767) sends "No" when LAPS is genuinely absent
--      and "Unknown" only on a failed read. There is no real "absent" case
--      routed through treat_unknown_as here — pass-on-unknown only ever
--      covered a failed read, which is exactly the shape this ticket exists
--      to close. Flip treat_unknown_as to 'fail'; treat_not_configured_as
--      stays NULL (the agent has no NotConfigured case to distinguish for
--      this signal).
--
--   2. cis_macos_2_3_4_2_time_machine_encrypted (macos, eq 'Yes')
--      The macOS agent (PAT-1767) now sends "NotConfigured" when Time
--      Machine has no destination configured (nothing to encrypt — a real,
--      successful read of "not applicable in practice", correctly a pass)
--      and null only on a failed read. Split it the same way 0131 split the
--      six Windows TLS/ASLR rules: treat_not_configured_as = 'pass' (no
--      backup destination = nothing to encrypt), treat_unknown_as = 'fail'
--      (we could not read Time Machine's configuration at all).
--
--   3. cis_macos_1_7_update_deferral_days (macos, lte '30')
--      LEFT UNCHANGED. This signal is numeric (days) and the collector still
--      sends null for both "no deferral configured" (a real pass — updates
--      install immediately) and a failed read — the agent has not been
--      updated to distinguish them with "NotConfigured" for this signal yet.
--      Flipping treat_unknown_as to 'fail' here would make every currently-
--      passing "no deferral configured" device fail for no configuration
--      change, which is a worse outcome than the narrow window this
--      migration is closing. Revisit once the agent sends "NotConfigured"
--      for a genuinely absent deferral policy on this signal.
--
-- Both UPDATEs are guarded by rule_key, benchmark, and the exact current
-- (treat_unknown_as, treat_not_configured_as) values, so this migration is a
-- no-op (0 rows) if a hand-edit already changed the row, rather than
-- clobbering it — same convention as 0131.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0132_unknown_evidence_never_passes.sql

BEGIN;

-- ============================================================================
-- 1. nist_win_ac2_laps_enrolled — no real "absent" case reaches
--    treat_unknown_as; pass-on-unknown only ever covered a failed read.
-- ============================================================================

UPDATE compliance_rules
SET treat_unknown_as = 'fail'
WHERE rule_key = 'nist_win_ac2_laps_enrolled'
  AND benchmark = 'NIST SP 800-53 Rev 5'
  AND treat_unknown_as = 'pass'
  AND treat_not_configured_as IS NULL;

-- ============================================================================
-- 2. cis_macos_2_3_4_2_time_machine_encrypted — split NotConfigured (no
--    backup destination, pass) from Unknown (failed read, fail).
-- ============================================================================

UPDATE compliance_rules
SET treat_not_configured_as = 'pass',
    treat_unknown_as = 'fail'
WHERE rule_key = 'cis_macos_2_3_4_2_time_machine_encrypted'
  AND benchmark = 'CIS Apple macOS'
  AND treat_unknown_as = 'pass'
  AND treat_not_configured_as IS NULL;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0132_unknown_evidence_never_passes')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
