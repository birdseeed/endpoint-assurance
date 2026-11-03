-- patched.im — 0134_auto_updates_pass_on_os_default.sql
-- PAT-1780: automatic Windows updates pass when not configured.
--
-- Numbering note: 0132 is already claimed by an unmerged draft PR (#497);
-- see 0133 for the same gap. Only uniqueness is enforced (migrations/README.md).
--
-- rule_key cis_win_18_9_102_auto_updates was seeded in
-- 0019_windows_cis_l1_rules.sql with treat_unknown_as = 'fail' and no
-- treat_not_configured_as (column did not exist yet; added in 0131, defaults
-- to NULL = "use treat_unknown_as"). That means a genuinely absent policy —
-- no GPO, no MDM policy, no local override — currently fails, even though
-- Windows 10/11 ship with automatic updates enabled by default. A device
-- relying on that OS default is compliant, not failing.
--
-- Set treat_not_configured_as = 'pass' so absence reads as compliant on the
-- OS default. treat_unknown_as stays 'fail' (unchanged, deliberately): a
-- failed read still must not pass, since we then have no idea what state the
-- device is actually in.
--
-- Description updated to describe the actual read order: Group Policy
-- (NoAutoUpdate, AUOptions), then the Intune/MDM PolicyManager
-- Update/AllowAutoUpdate value (PAT-1780), then the local AUOptions value;
-- not configured passes on the OS default. Title is unchanged; it is not
-- factually wrong.
--
-- Deliberate outcome change (Andy, 2026-09-15): stock Windows devices with no
-- update policy configured stop failing this control.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0134_auto_updates_pass_on_os_default.sql

BEGIN;

UPDATE compliance_rules
SET treat_not_configured_as = 'pass',
    description = 'CIS §18.9.102. The agent reads, in order, the Group Policy NoAutoUpdate and AUOptions values, the Intune/MDM Update/AllowAutoUpdate value under PolicyManager (PAT-1780), then the local AUOptions value. Not configured passes: Windows 10/11 enable automatic updates by default, so a device with no policy set relies on that OS default rather than failing for want of an explicit setting. A failed read is Unknown and still fails. Unpatched Windows devices are the primary vector for ransomware lateral movement in SME estates.'
WHERE rule_key = 'cis_win_18_9_102_auto_updates'
  AND benchmark = 'CIS Microsoft Windows 11'
  AND treat_unknown_as = 'fail'
  AND treat_not_configured_as IS NULL;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0134_auto_updates_pass_on_os_default')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
