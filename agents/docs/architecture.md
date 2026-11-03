# updater — architecture

## Overview

```
Intune ──deploys──▶ endpoint bundle (/usr/local/patched-updater/)
                        │
 com.patched.update (LaunchDaemon, root)
   • daily scheduled run   ┐
   • trigger-file watch    ┘──▶ patched-update.sh
                                  • verifies bundle integrity
                                  • runs the engine (Team ID + notarization)
                                  • writes update-status.json   ──▶ menu bar app
                                  • POSTs provenance ──▶ api.patched.im

Patched macOS runner (NOT an endpoint)
 legacy verification ── manual ──▶ resolve + download + verify selected
                                   vendor sources; emit diagnostic artifact only
```

## Components

### engine/

Hard-forked from Installomator (MIT). Full commit history imported with
`git subtree add --prefix=engine` (no squash). Tagged `engine-import`.
Patched owns the fork from that tag forward; no upstream tracking remote.

The endpoint executes the engine's shell `case` statement. A structured label
manifest supplies verification and endpoint-authorization data. CI enforces the
paired execution contract for every allowlisted label; see `engine/labels/` and
`docs/label-manifest-format.md`.

### engine/labels/

The **label manifest**: one `<label>.json` per application. The full directory
is the manifest; there is no separate index file. All records validate against
`contracts/label.schema.json`. CI rejects any record with an invalid Team ID or
non-HTTPS URL.

Key fields per record:
- `expected_team_id` — 10-char Apple Developer Team ID (load-bearing; closes T4)
- `download.method` — `static` (fixed URL) or `resolved` (URL computed at run time)
- `patched.allowlisted` — whether this label is deployed to endpoints

### endpoint/

- `patched-update.sh` — privileged daemon script, installed at
  `/usr/local/patched-updater/patched-update.sh`
- `com.patched.update.plist` — LaunchDaemon for scheduled + trigger-driven runs
- `labels-allowlist.txt` — **generated** from the manifest (never hand-edit);
  regenerate with `python3 ci/validate-labels.py --emit-allowlist endpoint/labels-allowlist.txt`

### verifier/

Quarantined vendor-source diagnostic (PAT-52/PAT-1474). It can read label
records, resolve and download selected vendor sources, and compare retained
results. It does not run on endpoints. Scheduled verification, publication,
alert creation and automatic smoke-test fan-out are disabled; a deliberate
manual run emits a workflow artifact only. The vendor verifier itself was
deleted by PAT-2304, and the manual smoke-test and behavioral-analysis
workflows, which installed catalogue apps on hosted runners, by PAT-2308
(both 2026-09-30).

### menubar/

SwiftUI menu bar app (`PatchedUpdater`). Runs as the user (no privilege). Reads
`update-status.json` written by the daemon. Requests on-demand runs by dropping
a trigger file. Spec: `contracts/update-status.schema.json`. Phase 2 build.

### contracts/

JSON Schema files:
- `label.schema.json` — the label record schema (used by CI)
- `update-status.schema.json` — the daemon → menu bar app contract
- `update-status.sample.json` — a worked example

### ci/

- `validate-labels.py` — validates all `engine/labels/*.json` records against
  the schema, enforces security invariants, and rejects managed-label drift
  from the shell engine. Run on every PR via `.github/workflows/validate-labels.yml`.

### scripts/brand-guard.sh

Standalone brand-compliance gate. **Runs as the first step before any agent
packaging** (and on every push/PR via `.github/workflows/brand-guard.yml`).
Rejects builds that contain:

- Incorrect copy terms ("fleet", "endpoints closed", "patched.io" domain).
- Web brand fonts (Archivo / Inter / JetBrains Mono) in native agent UI — only
  `BrandTokens.swift` is exempt (logo lockup registration).
- Missing required brand assets (`patched-ring-mark-mono`, `patched-app-icon`).
- Deprecated self-service language ("Open Posture", "endpoints open/closing").

Run locally: `bash scripts/brand-guard.sh`

### tools/

- `convert-installomator-labels.py` — the PAT-41 converter: parses
  `engine/fragments/labels/*.sh` and emits manifest records. Retained as an
  historical import helper, not authority to import Installomator upstream data
  or resume broad catalogue maintenance.

## Security model

See `docs/installomator-security-review.md` for the full threat model. Key
controls:

- **T4 (wrong binary signed by attacker)** — `expected_team_id` required,
  10-char pattern enforced by schema, CI rejects empty; engine verifies after
  install.
- **T5 (URL-resolution tampering)** — `resolved` labels carry residual risk;
  mitigated by the mirror path (Phase 2): mirrored labels become `static` +
  hash-pinned from the endpoint's perspective.
- **T6 (endpoint bundle tampering)** — `patched-update.sh` verifies its own
  bundle integrity before running the engine.

## Current state

**2026-09-18 source state (PAT-1833, pending review and release):** both endpoint
agents now attach their already-computed OS-update verdict to the next
`POST /v1/inventory`. Windows threads the cycle's `OsUpdateInfo` directly from
the worker into `InventoryPoster`; an unavailable result omits the section.
macOS reads the atomic `update-status.json` written by `patched-update.sh` at
upload time and includes only a complete contract-valid block whose
`checked_at` is not in the future and is no more than 48 hours old (the daily
03:00 daemon means evidence tolerates one missed run before it goes stale, not
two). The queued
collector payload remains unchanged, and missing, unreadable, malformed,
partial or stale local evidence is omitted rather than replaced with defaults.
This records repository code state only; it is not endpoint deployment or
operating evidence.

**** — PAT-40 + PAT-41 complete.

- `github.com/Patched-LTD/updater` created private (PAT-40).
- Installomator hard-forked into `engine/`, tagged `engine-import` (PAT-41).
- 1120-record label manifest generated; all 1120 validate; CI live.
- `endpoint/`, `menubar/`, `verifier/`, `contracts/`, `docs/` seeded from the
  Cowork prototype (Installomator integration review session).
- `validate-labels` CI check wired on every PR and `main` push touching labels.

**Phase 2 outstanding:** verifier (PAT-52), endpoint daemon polish + Intune
bundle (PAT-43/44/47/48), label allowlist curation (PAT-42), menu bar app
(PAT-51).
