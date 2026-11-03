-- patched.im — 0083_critical_findings_fail_unknown.sql
-- PAT-913 (Option B): findings-based compliance rules must fail-unknown, not pass-unknown.
--
-- The four rules seeded by 0033 (disk_encryption_off + removable_storage_unencrypted,
-- macOS + Windows) were seeded with treat_unknown_as = 'pass'. Because a
-- findings-based signal is only present when the agent reports a violation, a
-- device that never assessed the control (older agent predating PAT-743, a
-- collector whose sub-check errored, an agent that never checked in) had no
-- signal row and therefore scored a clean PASS on a critical full-disk-encryption
-- control. On an audit-evidence report "we did not assess this" and "this passed"
-- must not look identical.
--
-- The code half of PAT-913 (buildSignalsMap) writes a positive "Pass" signal only
-- for a control the agent explicitly attests it assessed this run, via the new
-- compliance_assessments.controls_assessed list, and did not flag. A genuinely
-- clean attesting device therefore still passes. treat_unknown_as = 'fail' bites
-- only when the control is unattested (absent from controls_assessed, or the
-- section is missing entirely, as on every agent deployed before PAT-913), which
-- is exactly the case this migration is meant to catch. An initialised-but-empty
-- findings array can no longer fake a Pass, because Pass never derives from the
-- findings array.
--
-- Scope note (critical-rule review, PAT-913 point 2): every other critical rule
-- already had treat_unknown_as = 'fail' and needs no change:
--   cis_macos_2_5_1_1_filevault (0003), cis_win_18_10_11_bitlocker_os_drive (0019),
--   cis_win_18_9_45_defender_realtime (0019). Those read direct compliance signals
--   that a reporting agent always emits, so absence already means "not reported"
--   and already failed-unknown. Only the four findings-based rules below defaulted
--   to pass-unknown.

BEGIN;

UPDATE compliance_rules
SET treat_unknown_as = 'fail'
WHERE rule_key IN (
    'patched_macos_disk_encryption_off',
    'patched_win_disk_encryption_off',
    'patched_macos_removable_storage_unencrypted',
    'patched_win_removable_storage_unencrypted'
)
  AND treat_unknown_as = 'pass';

INSERT INTO schema_migrations (version) VALUES ('0083_critical_findings_fail_unknown')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
