# brand-ring-mark-prompt.md

Self-contained handoff prompt (per `AGENTS.md`: phased, literal git, Phase 0
working-state update). Run with autonomy; one sequential session per repo; do not
run git inside a sandbox/mount — commit on the real checkout. Never commit secrets.

/ "estate" never "fleet"; metric is "apps patched", never "endpoints closed";
domain is **patched.im**. /

---

## Context

Patched's mark is now the **ring mark** (Archivo **P** in a rounded-square frame,
one signal-orange `#F5530A` arc on the top-right corner):
- **bare** on light chrome, menu bars, the patched.im nav and in-product headers;
- on a **slate tile** (mark hugging the tile edge — one bordered frame, never a
  filled knockout) for app icons, the Dock and favicons.

The **pixel-P** (`patched-mark-*`) is now **marketing only**. The pixel
estate-field grid is **retired**; the brand graphic device is the **posture
gauge** — the ring-mark squircle as a live meter (slate = apps **patched**,
orange front = **patching**, faint = **unpatched**).

SVG masters are provided in the design package under `kit/`:
`patched-ring-mark-slate.svg`, `-white.svg`, `-mono.svg`, `patched-app-icon.svg`,
`patched-app-icon-light.svg`, `favicon.svg`.

The **self-service agent UI** (the macOS menu-bar popover and the Windows tray
flyout) is specified visually in `reference/Self-Service Agent.html` (in the
design package) — open it for the exact layout, spacing, states and copy. Build
the real agent UI to match it; it is the source of truth for that surface.

---

## Phase 0 — working state
Add a dated entry to the "Working state — Patched.im" Linear Document: "Rolling
the ring mark + posture-gauge brand into `branding`, building the self-service
agent panel, and enforcing both in `updater` deploys." Check Linear (team PAT)
for any existing brand issue; create one if missing.

---

## Phase 1 — `Patched-LTD/branding`

1. Branch: `git checkout -b brand/ring-mark`
2. Copy the provided SVG masters into the repo:
   - `kit/logo/patched-ring-mark-slate.svg` `-white.svg` `-mono.svg`
   - `kit/logo/patched-app-icon.svg` `kit/logo/patched-app-icon-light.svg`
   - `kit/favicon/favicon.svg`
3. Regenerate rasters from the masters (Archivo installed locally), then commit:
   - `favicon-16/32/48.png` ← `favicon.svg`
   - `apple-touch-icon.png` (180) and `app-icon-512/1024.png` ← `patched-app-icon.svg`
   - `favicon.ico` (16/32/48) ← `favicon.svg`
   - delete the superseded pixel-P favicon/app-icon PNGs.
   - If `sync-brand.sh` regenerates `assets/` from `kit/`, run it so `assets/`
     matches; add `patched-ring-mark-*` and `patched-app-icon*` to its source list.
4. Update the brand docs so the rules are written down (edit `README.md` /
   `brand/*` / any `CLAUDE.md` in the repo):
   - **Two marks** — pixel-P = marketing only; ring mark = app/product/agent.
   - **App icons = ring on a slate tile** (hugging the edge; no knockout).
   - **Graphic device = the posture gauge** (slate patched · orange patching
     front · faint unpatched); the pixel estate-field grid is retired.
   - **Metric language: apps patched / patching / unpatched** (not closed/closing/open).
   - **Never "fleet" → always "estate"**; **domain is patched.im**.
   - **Native apps use the system font**; the only brand-font element is the logo
     lockup (Archivo).
5. Commit + PR (endpoint-trust review gate applies before merge):
   ```sh
   git add kit/ assets/
   git commit -m "brand: ring mark across the board, app-icon/favicon on slate tile, posture gauge, apps-patched language"
   git push -u origin brand/ring-mark
   ```

---

## Phase 2 — self-service agent UI on `Patched-LTD/updater`

`updater` is the macOS/Windows self-service agent (menu-bar app + tray app). Build
its user-facing panel to match `reference/Self-Service Agent.html`. Anatomy (both
platforms, light + dark):

- **Entry icon:** menu-bar item (macOS) / tray item (Windows) = the
  **`patched-ring-mark-mono`** template (single-colour; macOS renders it as a
  template image so the OS tints it — never the colour mark here).
- **Header:** the ring mark + **"Patched" in Archivo 600** lockup (the *only*
  Archivo in the app), a `Managed` tag, and a settings gear.
- **Posture summary:** the **posture gauge** (the ring-mark squircle as a live
  meter — slate = patched, orange front = patching, faint = unpatched) beside a
  headline (`N updates ready`) and a legend (`84 patched · 1 patching · 6
  unpatched`). Drive gauge from real counts: patched/patching/total.
- **Primary action:** one **`Patch all`** button in signal orange `#F5530A`
  (+ download size); macOS adds a `Later` secondary.
- **App list:** apps needing patching (name, `old → new` version), the in-progress
  one showing a live orange progress bar + %, then an `Up to date` section with a
  muted check. Per-row `Update` buttons.
- **Footer:** `Last checked …` + an **`Open Self Service →`** deep-link.
- **Type:** everything is the **OS system font** (`-apple-system`/SF on macOS,
  `Segoe UI Variable`/Segoe UI on Windows). The lockup is the only Archivo.
- **Surfaces:** respect light/dark; macOS popover uses vibrancy, Windows flyout
  uses Mica; signal orange ≤ ~2% of the surface (the button + the front).

Land this behind the repo's normal review; keep the daemon/data wiring (apps,
versions, progress, last-checked) feeding the panel.

---

## Phase 3 — enforce on `Patched-LTD/updater` (deploy gate)

`updater` is the macOS/Windows self-service agent. Add a **brand guard** that runs
in CI and as a pre-deploy step so non-conforming agent updates cannot ship.

1. Branch: `git checkout -b ci/brand-guard`
2. Add `scripts/brand-guard.sh` (fails the build on any violation):
   ```sh
   #!/usr/bin/env bash
   set -euo pipefail
   # Scan shippable source/copy (exclude vendored + generated + git dirs).
   FILES=$(git ls-files | grep -Ev '^(vendor/|third_party/|.*\.lock|dist/|build/)')
   fail=0
   check() { # pattern, message
     local hits
     hits=$(printf '%s\n' "$FILES" | xargs -I{} grep -InE "$1" {} 2>/dev/null || true)
     if [ -n "$hits" ]; then echo "BRAND GUARD: $2"; echo "$hits"; fail=1; fi
   }
   check '\bfleet\b'                 'Use "estate", never "fleet".'
   check 'endpoints? closed'         'Metric is "apps patched", not "endpoints closed".'
   check 'patched\.io'               'Domain is patched.im, not patched.io.'
   check '(closing|open) front'      'Use patching/unpatched language for the posture gauge.'
   # Native UI must use the system font — brand webfonts only allowed in the logo lockup.
   check "font-family:[^;]*(Archivo|Inter|JetBrains)" \
         'Native agent UI must use the OS system font; brand webfonts only in the logo lockup (allowlist that file).'
   # Required brand assets present and correct.
   for a in patched-ring-mark-mono patched-app-icon; do
     git ls-files | grep -q "$a" || { echo "BRAND GUARD: missing asset $a"; fail=1; }
   done
   # macOS menu-bar icon must be the mono template (single-colour), not the colour mark.
   if git ls-files | grep -qi 'menu.*bar.*icon'; then
     git ls-files | grep -qi 'patched-ring-mark-mono' || { echo "BRAND GUARD: menu-bar icon must be the mono template"; fail=1; }
   fi
   # Self-service panel must use the posture-gauge + apps-patched language, not old terms.
   check 'endpoints? (open|closing)'  'Self-service panel: use patched / patching / unpatched.'
   check 'Open Posture'               'Self-service deep-link label is "Open Self Service".'
   [ "$fail" -eq 0 ] && echo "brand-guard: OK"
   exit "$fail"
   ```
   `chmod +x scripts/brand-guard.sh`. Add an allowlist comment for the one logo
   lockup file that is legitimately set in Archivo.
3. Wire it into CI (`.github/workflows/brand-guard.yml`) on push/PR:
   ```yaml
   name: brand-guard
   on: [push, pull_request]
   jobs:
     guard:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: bash scripts/brand-guard.sh
   ```
4. Wire it into the **deploy interlock**: add `bash scripts/brand-guard.sh` as the
   first step of the agent-update build/release script (before signing/packaging),
   so a failing guard blocks the deploy. Note this in the repo's `docs/architecture.md`
   `## Current state` deploy block (the owner runs deploys over Tailscale).
5. Confirm the agent itself ships the right assets: app/Dock icon = `patched-app-icon`
   (ring on slate tile), menu-bar item = `patched-ring-mark-mono` template, all UI
   text in the OS system font (SF / Segoe UI), only the logo lockup in Archivo.
6. Commit + PR:
   ```sh
   git add scripts/brand-guard.sh .github/workflows/brand-guard.yml
   git commit -m "ci: brand guard — block agent updates that violate brand/copy rules"
   git push -u origin ci/brand-guard
   ```

---

## Acceptance
- `branding` PR merges the ring-mark masters + regenerated rasters + written rules.
- `updater` self-service panel (menu-bar + tray, light + dark) matches
  `reference/Self-Service Agent.html`: gauge + apps-patched summary, `Patch all`,
  app list with live progress, `Open Self Service →`, system font everywhere but
  the lockup.
- `updater` CI runs `brand-guard` green; a deliberate "fleet"/"patched.io"/colour-
  menu-bar / "Open Posture" change makes it **red**; the deploy script refuses to
  package on red.
- Definition of Done = code + in-repo docs + Linear updated.
