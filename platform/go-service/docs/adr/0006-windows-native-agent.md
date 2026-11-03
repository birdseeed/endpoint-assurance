# ADR-0006: Windows endpoint is a native C# .NET service (supersedes ADR-0002)

**Status:** Accepted
**Deciders:** Andy (sole maintainer, pre-incorporation)
**Supersedes:** [ADR-0002](0002-windows-client-approach.md) (PowerShell collection script, no native agent)

> **Rationale note:** this ADR records a decision that was already executed in code
> (the agent exists and runs on the `win-staging` pilot). The "why" below is
> reconstructed from the implementation; confirm/expand with Andy where marked.

---

## Context

ADR-0002 decided the v1 Windows endpoint client would be a **PowerShell
collection script via Intune** — explicitly *no native agent, no Windows Service, no MSI* —
to stay at parity with the macOS `patched-collect.sh` script and avoid the Windows
native-binary tax (signing, SmartScreen cold-start, MSI packaging).

That decision was scoped to **compliance collection only**. Since then the Windows
workstream absorbed a second, heavier requirement that ADR-0002 did not weigh: the
**Patched Updater** (on-demand + scheduled third-party app patching via winget/Chocolatey,
with a user-facing tray, signed-artifact verification, and a provenance audit trail). That
is not a one-shot collection job — it needs a **persistent background process**:

- 15-second trigger polling so the tray's "deploy now" works on demand (not just daily).
- A daily scheduled run that *installs* updates, not just reports them.
- Authenticode verification before install, winget COM automation, per-action provenance POSTs.
- A WPF/WinForms tray for end-user status/deferral UX.
- Egress concerns a script keeps re-solving: HMAC signing, Ed25519-verified agent-config
  polling, and proxy resolution (system/manual/off) re-evaluated per request.

A PowerShell script run by Intune cannot host a tray, can't respond to on-demand triggers
between Intune cycles, and would re-implement the auth/config/proxy machinery the macOS
*native updater* already has. So the compliance collector and the updater **converged into
one native agent** — which is what was actually built.

## Decision

**The Windows endpoint client is a native C# .NET 8 Windows Service**, packaged as a WiX
MSI, with a companion WPF/WinForms tray. It lives at `windows-agent/` in the monorepo.

It does both jobs in one process:
- **Compliance + inventory** (`src/Service`): `DeviceCollector`, `ComplianceCollector`
  (the 13 CIS Windows 11 L1 signals seeded by migration `0019`), `InstalledAppScanner`
  (registry uninstall keys — not `Win32_Product`), `SecurityToolDetector`; assembled by
  `InventoryCollector` and POSTed to `/v1/inventory` by `InventoryPoster` (schema-v3
  envelope, bearer + HMAC-SHA256, the exact server contract macOS uses).
- **Updater** (`src/Engine`): winget COM / Chocolatey engines behind `IPackageEngine`,
  per-tenant allowlist, `BootstrapInstaller`; `ProvenancePoster` writes the audit trail.
  (Currently `PilotNoOpEngine` during the PAT-312 pilot — reports, does not install.)
- **Platform parity plumbing**: `AgentConfigFetcher`/`AgentConfigManager` (Ed25519-verified
  `/v1/agent-config`, 15-min poll — parity with macOS PAT-281), `ProxyResolver` +
  `DynamicWebProxy` (PAT-309, parity with macOS PAT-278), `OsUpdateChecker` (WUA, PAT-308),
  `Verifier` (Authenticode).

Service: `Patched Agent`, LocalSystem, auto-start, restart-on-failure. State/creds/logs
under `%ProgramData%\Patched\` (creds in `creds/`, mirroring macOS `/etc/patched`).

## Why this diverges from ADR-0002

ADR-0002's reasoning holds *for a compliance-only collector* — and remains true for macOS,
where the updater is a **separate** product (`updater` repo) and `patched-collect.sh` stays
a script. The divergence is Windows-specific: bundling the updater into the endpoint made a
persistent native service the simpler design than {Intune script for compliance} +
{separate updater binary}. The native-binary tax (signing/SmartScreen) is accepted and
tracked — the MSI ships **unsigned** for the pilot (SmartScreen "More info → Run anyway");
Authenticode signing is blocked on incorporation + OV/EV cert (`installer/sign-hook.bat`).

## Consequences

- **macOS and Windows are no longer the same shape.** macOS = script collector + separate
  updater; Windows = unified native service. That's an accepted, deliberate asymmetry, not
  drift. "Joint v2 native-agent decision" from ADR-0002 is moot for Windows.
- **Server side is unchanged** — same `/v1/inventory` contract, same schema-v3 envelope,
  same 13 CIS rules (migration `0019`). No Go changes were needed to accept Windows payloads.
- **Provenance:** this is a clean-room rebuild authored by Andy, distinct from the
  quarantined legacy `windows-agent/` PowerShell (Rob-authored, see PAT-175) — different
  language, different architecture, no shared lineage.
- **Open:** Authenticode signing (incorporation-gated); flip `PilotNoOpEngine` → real
  winget/choco engine post-pilot; CI builds it on `windows-latest`; a Windows self-pilot
  (PAT-18) validates the daily ingest + the 13 rules end-to-end.
