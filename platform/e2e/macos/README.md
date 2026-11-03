# PAT-739 — macOS Layer B E2E Harness

Runs the **real** macOS Patched collector inside a Tart macOS VM against the local E2E stack.

## Architecture

```
HOST (macOS)
├── e2e/stack.sh up   — Postgres + patched-api (:18080/:18081) + extractor + dashboard
├── vm.sh             — Tart VM lifecycle (clone / run / SSH)
├── install-agent.sh  — Copies macos/ agent into VM; runs install.sh
└── run-collection.sh — Triggers collect+upload; polls admin API for verdicts

  Tart NAT (bridge100 / vmnet)
    ┌─────────────────────────────┐
    │  patched-e2e-macos VM       │
    │  macOS Sequoia (arm64)      │
    │  /usr/local/bin/            │
    │    patched-collect.sh       │
    │    patched-upload.sh        │
    │    lib/*.sh                 │
    │  /etc/patched/              │
    │    tenant-id                │
    │    bearer-token             │
    │    hmac-secret              │
    └─────────────────────────────┘
         │  POST /v1/inventory
         ▼
    HOST 0.0.0.0:18080  (patched-api, rebounded for VM run)
```

## Networking choice: Option A — rebind API

`patched-api` defaults to `127.0.0.1:18080` which the VM cannot reach over Tart's NAT.
`install-agent.sh` kills the existing API process and restarts it with
`LISTEN_PUBLIC=0.0.0.0:18080` so the VM can POST to `http://<host-gateway>:18080`.
The internal admin listener stays on `127.0.0.1:18081` — never exposed to the VM.

The host gateway from the VM's perspective is derived dynamically via `route -n get default`
inside the VM (typically `192.168.64.1` for Tart's default NAT bridge).

**Restore**: `stack.sh down && stack.sh up` returns the API to loopback-only.

## VM credentials

| Field | Value |
|-------|-------|
| User  | `admin` |
| Pass  | `admin` (Cirrus default; used only for initial key exchange) |
| Sudo  | passwordless |
| SSH   | key after first `vm.sh up`; key stored at `t9/vm_key` |

## Revert / reset mechanism

Tart does **not** support snapshots. The revert mechanism is:

```bash
./vm.sh reset       # stop + delete + re-clone from base OCI image
./vm.sh up          # boot fresh clone
./install-agent.sh  # re-install agent
./run-collection.sh # run collection
```

Re-clone is fast because APFS copy-on-write is used — only changed blocks are written.

## Script reference

| Script | Purpose |
|--------|---------|
| `vm.sh up` | Clone (if absent) + start headless + wait for SSH + install key |
| `vm.sh down` | Stop VM (clone kept) |
| `vm.sh ssh [-- cmd]` | SSH passthrough; optional command |
| `vm.sh ip` | Print VM's IP |
| `vm.sh reset` | Stop + delete + re-clone (idempotent revert) |
| `vm.sh destroy` | Stop + permanently delete VM |
| `install-agent.sh` | Install macOS agent into VM against local stack |
| `run-collection.sh` | Trigger collect+upload; write `artifacts/baseline-verdicts.json` |
| `run_layerb.sh` | T10 end-to-end state-induction run: baseline → induce → collect → restore → collect → ledger |
| `induce.sh apply\|restore` | Copies + runs `apply_remote.sh`/`restore_remote.sh` inside the VM as root |
| `build_ledger.py` | Builds `artifacts/layerb-ledger.json` from a `run_layerb.sh` run |

## Layer B state induction (T10)

`run_layerb.sh` flips real endpoint state across 11 groups (firewall,
gatekeeper, sharing daemons, software-update prefs, screensaver, pwpolicy,
audit perms, auto-login, filesystem perms, sudo, mobileconfig) and proves the
dashboard verdict tracks the real state, in both directions. Full results
from the most recent run, including 7 confirmed collector bugs found this
way, are in `../data/macos-layerb-results.md`.

```bash
./vm.sh up && ./install-agent.sh   # if not already running
./run_layerb.sh                    # runs the full 3-cycle induction + ledger
```

## Quick start

```bash
# 1. Ensure local stack is running.
~/Development/Patched.im/patched.im-pat-739/e2e/stack.sh up

# 2. Boot the VM (first run clones from base image ~seconds on APFS).
./vm.sh up

# 3. Install the agent (also rebinds API to 0.0.0.0).
./install-agent.sh

# 4. Collect + verify verdicts.
./run-collection.sh
# → artifacts/baseline-verdicts.json contains per-rule verdict map.

# 5. Revert test (reset VM + re-run).
./vm.sh reset
./vm.sh up
./install-agent.sh
./run-collection.sh
```

## Artifacts

- `artifacts/baseline-verdicts.json` — per-rule verdict map from the first real VM collection.

## Deviations / known issues

- **No LaunchDaemon scheduling tested** — daemons are installed and loaded, but the
  E2E harness uses direct `patched-collect.sh` + `patched-upload.sh` invocation (not
  the collect-trigger script) because `patched-collect-trigger.sh` expects the agent
  at `/usr/local/patched-updater/` while `install.sh` puts it in `/usr/local/bin/`.
- **patched-api rebind** — the API is restarted with `0.0.0.0:18080` for the duration
  of the VM run. `stack.sh status` still works (PID file is updated).
- **MDM gates** — `patched-collect.sh` may emit empty/default values for MDM-controlled
  signals (e.g. `managed_prefs`, enrollment state) on the unmanaged Cirrus base image.
  This is expected; the focus is that the payload is ingested and evaluated correctly.
- **macOS 26 parser** — the Cirrus base is Sequoia; collector output reflects that version.
