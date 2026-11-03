# updater

Both Patched.im **endpoint agents** — macOS and Windows — live here: managed
third-party application updates **and** endpoint inventory collection for client
Macs and Windows PCs. The server-side platform that ingests what the agents
report (ingestion, extractor, CIS evaluator, the signed agent-config endpoint,
and the `contracts/` wire-format authoring) is the separate
`Patched-LTD/patched.im` repo; this
repo holds the agent code and *consumes* that contract.
.
The legacy update engine is **hard-forked from
[Installomator](https://github.com/Installomator/Installomator)** and quarantined.
Patched does not track or merge from upstream, perform routine upstream review,
or maintain its broad catalogue. The retained fork exists only to preserve its
security and compatibility boundaries while PAT-1481 evaluates separately
approved, bounded macOS operations.

## One repo — both endpoint agents

Everything that runs on a customer endpoint lives here: the **macOS** agent and
the **Windows** agent, each with its inventory collector and its update rail (and,
on macOS, the menu-bar skin). Keeping them together keeps the per-OS layout
symmetric and the shared contracts in one place. The update engine is a hard fork
— not a branch kept mergeable with upstream — so there is no reason to split it
out either.

```
docs/
  installomator-security-review.md   Historical security & architecture review
  download-architecture.md           Historical direct vs. mirror architecture
  label-manifest-format.md           The label data model
  verification-agent-design.md       Historical vendor-source verifier design
macos/                               (macOS) inventory collector
  patched-collect.sh                 Thin orchestrator (root via Intune) → lib/
  lib/                               23 collector/enforcement modules (hardware, filevault, …)
  build-bundle.sh                    Inlines lib/ into dist/patched-collect.sh
  patched-upload.sh                  HMAC-signing queue drainer (LaunchDaemon)
  com.patched.{collect,upload}.plist LaunchDaemons
  README.md                          Collection surface + Intune deployment
engine/                              (macOS) hard-forked Installomator update engine; labels as data
endpoint/
  patched-update.sh                  (macOS) privileged update daemon wrapper
  com.patched.update.plist           LaunchDaemon (scheduled + trigger-driven)
  labels-allowlist.txt               Curated label allowlist
  README.md                          Endpoint deployment
verifier/                            (macOS) quarantined vendor-source diagnostic
menubar/
  PatchedUpdater/                    (macOS) SwiftUI menu bar app ("the skin")
  README.md                          Build & run
windows/                             (Windows) unified agent — collector + updater + tray
contracts/
  update-status.schema.json          The daemon → menu bar app contract
  update-status.sample.json          A worked example
  label.schema.json                  Label data-model schema
  uninstall-status.schema.json       Uninstall-execution status contract
ci/                                  Label + allowlist validators (CI)
tools/                               Bundle / .pkg build scripts
```

> **Layout note (PAT-384).** The macOS collector was imported here with full
> history from `patched.im` (`macos-agent/` → `macos/`), making this repo the
> single home for both endpoint agents. Windows is already unified under
> `windows/`; macOS is still split — its updater rail sits at the top level
> (`engine/`, `endpoint/`, `menubar/`, `verifier/`) while the collector landed at
> `macos/`. Folding those updater dirs under `macos/` for full per-OS symmetry is
> a tracked follow-up (the PAT-384 *target end state*), deliberately out of scope
> for the collector move.

The `engine/` subtree holds Installomator's imported source and full commit
history (tagged `engine-import`). The label manifest (`engine/labels/`) has
1,108 records (1,092 auto-converted from Installomator fragments + 16 hand-reviewed
curated/patched entries), all validating against `contracts/label.schema.json`.

`verifier/` is a quarantined vendor-source diagnostic. It is not a scheduled
production verifier or an upstream-maintenance authority.

## Repository & licensing

**This repository is private.** It holds Patched product code and an internal
security review (with a threat model) — it is not for public distribution.

The `engine/` is a **hard fork** of Installomator, which is MIT-licensed. MIT
permits private use and modification: the only obligation is to retain the
Installomator `LICENSE` text and copyright notice inside `engine/`. Patched is
under no obligation to publish its changes or keep the fork public.

## How it fits together

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

```

The **menu bar app** runs as the user, holds no privilege, reads the status
file, and requests on-demand runs by dropping a trigger file — the
**admin-scheduled + self-service** model.

The historical verification-agent design does not replace upstream label
maintenance in the current product. It is retained only as a design and
threat-model reference; see `docs/verification-agent-design.md`.

## Status

Installomator is retained as a quarantined hard fork in `engine/` (PAT-41,
). The 1,108-record label manifest and its validation remain so the
legacy execution path cannot silently lose its security invariants. PAT-1474
stopped scheduled vendor verification, signed-catalogue publication, package
mirroring, upstream-label maintenance and automatic package smoke testing.
Selected package workflows are manual diagnostics only, with mirror dispatches
defaulting to dry-run. The former Installomator upstream-review workflow was
removed entirely, so neither a schedule nor a manual dispatch can create a
maintenance issue. No package-maintenance output is part of the vNext software
identity or governance model. The endpoint daemon
(`endpoint/patched-update.sh`) has had substantial production hardening since
its initial build (dozens of PRs — see its git history), and the menu bar app
(`menubar/PatchedUpdater/`) is built.

### CI checks

| Check | Script | Triggers |
|-------|--------|---------|
| `validate-labels` | `ci/validate-labels.py` | any label, schema, or validator change |
| `validate-allowlist` | `ci/validate-allowlist.py` | label, allowlist, or either validator change |

`validate-allowlist` makes threat T4 (empty/missing `expectedTeamID`) unrepresentable
for allowlisted labels — a label without a valid 10-char Team ID and an https URL
cannot reach a shipped config.

### Endpoint allowlist

`endpoint/labels-allowlist.txt` lists the seven apps deployed to client Macs:
1Password, Firefox, ghostty, Google Chrome, Notion, Slack, Zoom. Each has been
confirmed against Apple: code signature valid, notarized, observed Team ID
equals the manifest `expectedTeamID`. The allowlist expands deliberately as
the estate grows.

See the security review §6 for the phased plan and §9 for open decisions.
Signing/notarization is gated on Patched.im Ltd. incorporation, tracking the
macOS agent's existing v1→v2 gate.

## Read first

[`docs/installomator-security-review.md`](docs/installomator-security-review.md) —
the historical security and architecture review. Its threat model remains a
reference for any separately approved, bounded PAT-1481 operation; it does not
describe a continuous verification service.
