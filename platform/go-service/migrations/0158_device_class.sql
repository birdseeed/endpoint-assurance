-- patched.im — 0158_device_class.sql
-- PAT-1960: a Windows Server that enrols must get an honest "not assessed:
-- no benchmark for this device class" instead of being scored against the
-- CIS Microsoft Windows 11 (workstation) pack. Today
-- `ac.platform = 'windows' AND d.os = 'Windows'` matches every Windows
-- device regardless of workstation/server/domain-controller role, which
-- produces wrong failures and — worse — wrong passes on exactly the
-- machines an assessor cares most about.
--
-- devices.device_class classifies the endpoint itself. 'unknown' is the
-- default and is deliberately NOT the same claim as "workstation" — every
-- device in the estate is 'unknown' until the PAT-1959 Windows agent change
-- ships and starts reporting a real value. compliance_rules.device_class is
-- the benchmark side: NULL means "applies to every class" (every macOS rule
-- today, and any future class-agnostic Windows rule); a populated array
-- names the exact classes a rule applies to.
--
-- The rule-matching predicate applied everywhere a rule is matched against a
-- device (evaluator.LoadRules/LoadRulesForTenant, report.fetchControlCoverage,
-- the portal control-coverage handler, report.Fetch's benchmark-totals query):
--
--   cr.device_class IS NULL
--   OR d.device_class = ANY(cr.device_class)
--   OR d.device_class = 'unknown'
--
-- The third clause is deliberate and load-bearing. Without it this migration
-- would instantly flip every existing Windows device (all 'unknown' today)
-- to "not assessed", which is a far worse regression than the bug being
-- fixed. 'unknown' therefore keeps exactly today's behaviour — evaluated
-- against every enabled rule for its platform — but must be labelled
-- "device class not reported" wherever coverage is presented, since it is
-- not the same claim as a device whose class was actually evidenced.
--
-- Both new devices columns are derived, re-extractable data (from the
-- immutable raw_payloads archive), same as every other devices.* column —
-- a rollback of this migration loses nothing that re-extraction can't
-- rebuild once a newer agent has reported it again.

BEGIN;

ALTER TABLE devices
    ADD COLUMN device_class TEXT NOT NULL DEFAULT 'unknown'
        CHECK (device_class IN ('workstation', 'server', 'domain_controller', 'unknown'));

ALTER TABLE devices
    ADD COLUMN installation_type TEXT;

ALTER TABLE devices
    ADD COLUMN os_caption TEXT;

COMMENT ON COLUMN devices.device_class IS
    'Coarse endpoint classification: workstation | server | domain_controller | unknown. Default/unknown means no agent has ever reported a real value (PAT-1959 is what starts reporting it, Windows-only for now) — scored exactly like a workstation today (see 0158 header), never silently upgraded to a guess.';
COMMENT ON COLUMN devices.installation_type IS
    'Verbatim OS installation-type string as reported by the agent, e.g. Windows registry InstallationType (Client | Server | Server Core). NULL when not reported. Informational only — device_class, not this column, drives rule matching.';
COMMENT ON COLUMN devices.os_caption IS
    'Verbatim OS caption/edition string as reported by the agent, e.g. WMI Win32_OperatingSystem.Caption ("Microsoft Windows Server 2022 Standard"). NULL when not reported. Informational only.';

ALTER TABLE compliance_rules
    ADD COLUMN device_class TEXT[];

COMMENT ON COLUMN compliance_rules.device_class IS
    'NULL means this rule applies to every device class (every macOS rule today). A populated array names the exact devices.device_class values this rule applies to. Matched together with devices.device_class = ''unknown'' (see 0158 header) — never read this column alone.';

-- Backfill: the live Windows rule library is three separate sets, not one.
-- As of this migration, production holds:
--
--   patched.im baseline        v1              1 rule
--   NIST SP 800-53 Rev 5       Rev 5 (2020)   19 rules
--   CIS Microsoft Windows 11   v2.0.0         51 rules
--
-- Only the CIS Microsoft Windows 11 benchmark is workstation-specific — it
-- is written against a client OS baseline and does not apply to Windows
-- Server. The NIST SP 800-53 rules and the patched.im baseline are general
-- controls with no workstation/server distinction in their source material;
-- nothing establishes them as workstation-only, so they stay device_class
-- NULL deliberately (applies to every class) rather than being swept into
-- the same restriction. A blanket `WHERE platform = 'windows'` update would
-- mark all three sets workstation-only, and a Windows Server would then get
-- zero evaluations from every Windows rule rather than just the 51 that are
-- genuinely workstation-only — the exact same "evaluated nothing, reported
-- as nothing to evaluate" failure this migration exists to fix, just from
-- the opposite direction.
--
-- Matched on benchmark name, not benchmark_version, so a future
-- CIS Microsoft Windows 11 v2.1.0 (or later) is still caught by this same
-- backfill's intent without a follow-up migration.
--
-- macOS rules stay NULL too (apply to every class — macOS has no
-- server/domain-controller distinction here).
UPDATE compliance_rules
SET device_class = ARRAY['workstation']
WHERE platform = 'windows' AND benchmark = 'CIS Microsoft Windows 11';

INSERT INTO schema_migrations (version) VALUES ('0158_device_class')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
