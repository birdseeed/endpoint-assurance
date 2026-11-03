-- patched.im — 0212_protected_software_bitdefender.sql
-- PAT-2234: add Bitdefender to the shared protected_software baseline.
--
-- The macOS agent now reports Bitdefender from a signed Endpoint Security
-- system extension by Apple Team ID (updater macos/lib/sectools.sh,
-- _sectools_team_ids), in addition to its install path, and the Windows agent
-- already reports it from HKLM\SOFTWARE\Bitdefender. Both send the
-- security_tools entry {"id": "bitdefender", "name": "Bitdefender"}. With no
-- baseline row, EDR coverage (PAT-2226) and the Cyber Essentials malware
-- protection control (PAT-1927) could only call such a device "unrecognised".
--
-- ── Match basis ──────────────────────────────────────────────────────────
-- product_name 'Bitdefender' is what the EDR coverage report matches: it
-- compares each reported tool's name and id case-insensitively against
-- product_name and process_name (report.edrToolMatches), so both "Bitdefender"
-- and "bitdefender" hit this row. Keep it equal to the agents' display name.
--
-- team_id GUNFMW623Y is Bitdefender SRL's Apple Developer Team ID, taken from
-- a real install on tenant-zero (2026-09-28), not from memory:
-- AntivirusforMac.app, BitdefenderAgent.app and CoreSecurity.app are signed
-- "Developer ID Application: Bitdefender SRL (GUNFMW623Y)", chained to Apple
-- Root CA, and pass codesign --verify -R '=anchor apple generic and
-- certificate leaf[subject.OU] = "GUNFMW623Y"'. It is the same Team ID the
-- agent's seed table reports on; the two must stay aligned (updater
-- test-sectools.zsh pins the agent table and names this migration). For
-- governance disposition (protectedsoftware.Check) it protects every app
-- Bitdefender signs, Bitdefender VPN included; over-protecting is the safe
-- direction (0139).
--
-- The Windows Publisher string and service names are not asserted: nothing in
-- either repo evidences them yet. Windows devices still match on the name.
--
-- Idempotent: inserts only when no baseline row carries this Team ID.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0212_protected_software_bitdefender.sql

BEGIN;

INSERT INTO protected_software (category, vendor, product_name, team_id, reason, added_by)
SELECT 'security', 'Bitdefender', 'Bitdefender', 'GUNFMW623Y',
       'Antivirus and endpoint security agent. Must never be marked unapproved or targeted for removal via a governance workflow.',
       'PAT-2234 baseline seed'
WHERE NOT EXISTS (
    SELECT 1 FROM protected_software
    WHERE tenant_id IS NULL AND team_id = 'GUNFMW623Y'
);

INSERT INTO schema_migrations (version) VALUES ('0212_protected_software_bitdefender')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
