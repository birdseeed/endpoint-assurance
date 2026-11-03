-- patched.im — 0133_mandatory_aslr_fail_closed.sql
-- PAT-1770: mandatory ASLR fails closed when the setting is not configured.
--
-- Numbering note: 0132 is already claimed by an unmerged draft PR (#497).
-- Only uniqueness is enforced (see migrations/README.md), so this migration
-- is numbered 0133 to leave that gap for whichever PR lands first.
--
-- rule_key nist_win_si16_mandatory_aslr was seeded in
-- 0041_windows_nist_l1_expansion.sql with treat_unknown_as = 'pass' on the
-- theory that "Win11 has ASLR on by default". 0131_treat_not_configured_as.sql
-- split that into treat_not_configured_as = 'pass' / treat_unknown_as = 'fail'
-- (absent registry value = OS default = pass; a failed read = fail), but kept
-- the 'pass' outcome for the absent case.
--
-- That outcome is wrong. Mandatory ASLR (Exploit Protection's
-- ForceRelocateImages, read from
-- HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions,
-- PAT-1770) is OFF by default on Windows 10/11 — opt-in ASLR (the
-- /DYNAMICBASE default) is on by default, but mandatory ASLR is a distinct,
-- separately-configured setting. A device that has never touched this
-- setting is not force-relocating images built without /DYNAMICBASE, so
-- "not configured" must fail, not pass. Verified on a device 2026-09-15.
--
-- The seed description also names the wrong registry value (MoveImages,
-- which does not control this mitigation) and justifies pass with the
-- opt-in/mandatory conflation above. Both are replaced.
--
-- Deliberate outcome change (Andy, 2026-09-15): this makes stock Windows
-- devices — which do not have mandatory ASLR configured — fail this control.
-- That is the point: the prior pass was a false negative on every unconfigured
-- device.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0133_mandatory_aslr_fail_closed.sql

BEGIN;

UPDATE compliance_rules
SET treat_not_configured_as = 'fail',
    title = 'Mandatory ASLR (Force randomization for images) enabled system-wide',
    description = 'NIST SI-16. Mandatory ASLR relocates every image at load, including images built without the /DYNAMICBASE linker flag. The agent reads the system Exploit Protection setting ForceRelocateImages from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions (PAT-1770). Passes only when the setting is on. Not configured fails: mandatory ASLR is off by default, so an unset value means images are not force-relocated. A failed or undecodable read is Unknown and fails.'
WHERE rule_key = 'nist_win_si16_mandatory_aslr'
  AND benchmark = 'NIST SP 800-53 Rev 5'
  AND treat_not_configured_as = 'pass'
  AND treat_unknown_as = 'fail';

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0133_mandatory_aslr_fail_closed')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
