# PAT-1047: full dashboard frontend rewrite

**Superseded by `docs/design/pat-1047/REDESIGN_V2.md`.** The plan below (originally
Phases 2/3's horizontal workload-tab IA: `Overview`/`Devices`/`Apps & Patching`/
`Compliance & Vulnerabilities`/`Reports`/`Configuration`) was implemented, then
rejected on review — it changed colour, type, spacing and navigation chrome but
preserved the old page/card/tab mental model. REDESIGN_V2.md is the implementation
contract for the replacement workflow-first architecture (global rail + context
navigator + vertical customer workflow nav: `Priorities`/`Devices`/`Patching`/
`Assurance`/`Evidence`/`Customer setup`) actually implemented; this file is kept for
process/phase history and for the parts of the brief REDESIGN_V2.md doesn't restate
(Phase 0 coordination, Phase 4 test/check discipline, Phase 6 cache-contract
mechanics). Where this file's Phase 2/3 IA conflicts with REDESIGN_V2.md, REDESIGN_V2.md
governs. `docs/design/pat-1047/SURFACE_INVENTORY.md` records the authoritative,
up-to-date per-surface mapping actually built.

Three PNG artboards were the visual references for light-first density, system
type, restrained orange and familiar admin controls — per REDESIGN_V2.md, they
were never the information-architecture contract.

- `home.png`
- `tenant-overview.png`
- `device-detail.png`

They were removed from the tree on 2026-09-13 (PAT-1701, 3.7 MB for a closed
ticket; PAT-1676's artboards are current). Code comments that cite them still
resolve from history: `git show e513eb6:docs/design/pat-1047/home.png > home.png`.

The outcome must be a genuine full-console redesign. Do not describe a token
change, CSS overlay, or three isolated screen rebuilds as completion.

## Non-negotiable product rules

- Preserve every current backend route, payload contract, workflow, RBAC gate,
  confirmation gate, audit path, download and functional action.
- Do not add MDM or remote-control behaviour. Patched Tier 1/2 devices are not
  MDM-enrolled.
- Keep the Home tenant-first. It ranks customers that require attention and
  drills into a tenant. It is not a per-device activity feed.
- Use the system font throughout the operator UI.
- Use `estate`, never `fleet`, in visible copy.
- Do not use em dashes in visible copy.
- Keep the canonical Patched ring-mark lockup. Orange is the brand and primary
  action accent, not a decorative colour wash.
- Preserve PAT-854-safe handling of attacker-influenced values. Never put a
  non-constant value inside a generated inline JavaScript handler string.
- Do not deploy. Do not push, open a PR, merge, or change Linear. Codex performs
  the independent review and release handoff after implementation.

## Phase 0: coordination before code

1. Read `AGENTS.md`, `CLAUDE.md`, this file, and `docs/API_REFERENCE.md`.
2. Fetch PAT-1047 from Linear and read the "Working state - Patched.im"
   document. PAT-1047 is already assigned and In Progress.
3. Confirm the checkout is:

   ```sh
   git status --short --branch
   git merge-base --is-ancestor origin/main HEAD
   ```

4. Do not edit the Working State document. This is routine ticket execution,
   not a new standing rule.

## Phase 1: freeze the functional surface inventory

Before changing markup, create
`docs/design/pat-1047/SURFACE_INVENTORY.md`. Cross-check
`docs/API_REFERENCE.md`, `consoleNav()`, `_SECTIONS`, `_NAV_MAP`,
`tenantTab()`, the tenant `data-tab` values, device-detail loaders and every
`section-*` element.

The inventory must account for at least:

### Global surfaces

- Home
- Customers
- Service Health: Infrastructure and Automations
- Admin Tools: Billing, Catalogue and all Catalogue sub-tabs, Credentials,
  Docs, Leads, Logs and Reports

### Tenant surfaces

- Overview
- Account
- Application Control
- Browser Extensions
- Customer Access
- Deploy Agent
- Devices
- Enforcement Audit
- Needs Attention, if still conditionally reachable
- Patch & Deploy and all current sub-tabs
- Reports
- Runbook
- Shadow IT
- Software Catalogue
- Software Metering
- Webhooks
- Compliance destination and its CIS Controls, Compliance Status and CVE
  Findings sub-tabs

### Device detail

- Current summary/header actions
- Patching
- Security or hardware posture
- Software
- Extensions
- Logs/activity
- Compliance
- Removal and any other existing guarded action

For every entry, record its current DOM id, activation function, data loader,
new destination, and verification method. Nothing may disappear merely because
it is not present in the three reference images.

## Phase 2: build the new shell and component contract

Modify in dependency order:

1. `static/css/theme.css`
   - Replace the trading-dashboard semantic system with light-first neutral
     admin-console tokens.
   - Preserve canonical brand tokens imported from
     `static/vendor/brand/tokens.css`.
   - Define semantic tokens for canvas, rail, surface, border, text, muted
     text, focus, action, success, warning and danger.
   - Keep a coherent dark-mode mapping, but light mode is the default visual
     acceptance target.
   - Use the system sans stack for all operator UI. Brand type may remain only
     inside the canonical lockup where already required.

2. `static/css/console.css`
   - Implement the shared application shell shown in the mockups: compact top
     bar, persistent global rail, main content canvas and responsive drawer.
   - Implement one page-header, command-bar, tab-bar, status-strip, panel,
     table, badge, empty/loading/error and definition-list language.
   - Reduce radius, shadow and decorative-card use. Use spacing, borders and
     hierarchy instead.
   - Remove or rewrite old selectors that recreate the previous dark
     trading-dashboard appearance.
   - Preserve narrow-width and touch behaviour.

3. `templates/console.html`
   - Rebuild the top-level shell while preserving Jinja auth/environment
     inputs and stable IDs used by JavaScript/tests.
   - Keep the canonical inline ring-mark SVG byte-for-byte in shape and colour.
   - Keep global navigation persistent in tenant and device contexts.
   - Add the customer selector and operator identity to the top context bar.
   - Replace the old tenant-sidebar swap with the approved tenant header and
     horizontal workload navigation:
     `Overview`, `Devices`, `Apps & Patching`,
     `Compliance & Vulnerabilities`, `Reports`, `Configuration`.
   - Make every specialist tenant screen reachable through an obvious
     secondary workload destination. Do not hide functionality in an
     undocumented overflow.
   - Rebuild Home, tenant Overview and Device Detail closely against the three
     approved PNGs, using real current data and graceful source degradation.
   - Migrate every remaining global and tenant surface to the shared page
     anatomy. Remove one-off visual fragments and inline layout styles when
     they fight the shared component contract.
   - Preserve all existing event handlers, stable DOM IDs and data loaders
     unless a deliberate, tested mapping replaces them.

4. Supporting JavaScript in `templates/console.html` and
   `static/js/theme.js`
   - Update navigation state, focus management, mobile behaviour, page titles,
     customer switching and device-detail routing for the new shell.
   - Preserve hash/deep-link compatibility wherever current URLs exist.
   - Do not change API contracts.
   - Keep source-state distinctions between empty, unavailable, loading and
     error.

## Phase 3: migrate the complete information architecture

**Superseded — see REDESIGN_V2.md.** The mapping below is the original v1 baseline
(horizontal workload tab bar). The implemented v2 mapping is a 64px global rail
(Work/Customers/Operations/Administration) plus a 280px context navigator, and a
vertical customer workflow nav grouped `Priorities`/`Devices`/`Patching`/`Assurance`/
`Evidence`/`Customer setup` — record in `docs/design/pat-1047/SURFACE_INVENTORY.md`,
which is the up-to-date source. Kept below for history only.

Use these workload mappings as the baseline:

### Global

- `Home`
- `Customers`
- `Service Health`, with Infrastructure and Automations inside the workload
- `Admin Tools`, with the current Billing, Catalogue, Credentials, Docs, Leads,
  Logs and Reports surfaces inside the workload

### Tenant

- `Overview`
- `Devices`
- `Apps & Patching`: patch/deploy, software catalogue, application control,
  browser extensions, software metering and enforcement audit
- `Compliance & Vulnerabilities`: compliance status, CIS controls, CVE
  findings and related advisory posture
- `Reports`: scheduled/ad-hoc reports, relevant audit/delivery views and
  Shadow IT if its current purpose remains reporting rather than configuration
- `Configuration`: account, customer access, deploy agent, webhooks and
  runbook

If live code shows a specialist surface belongs elsewhere, preserve it and
record the corrected mapping in `SURFACE_INVENTORY.md`. Do not fabricate an
architecture fact.

### Device

- `Overview`
- `Hardware`
- `Software`
- `Patching`
- `Compliance`
- `Activity`

Map the current security and extension detail into the appropriate destination
without losing the underlying data or actions.

## Phase 4: accessibility, security and regression tests

1. Add focused tests for:
   - the new global shell and exact primary navigation;
   - persistent global navigation in tenant context;
   - tenant workload navigation and complete specialist mapping;
   - device workspace tabs;
   - canonical ring-mark lockup;
   - light-first system-font and semantic-token contract;
   - absence of the retired old-shell anchors;
   - the PAT-854 inline-handler safety invariant;
   - build-id and asset-version alignment.

2. Run:

   ```sh
   pytest -q
   ```

3. Run any existing static/security checks documented by the repository.
4. Search the changed visible copy for `fleet` and em dash characters.
5. Inspect `git diff --check` and `git diff origin/main`.
6. Confirm no secret, production data, database or generated report entered the
   diff.

## Phase 5: local rendered acceptance

**Not run in the v2 implementation session** — rendered/visual acceptance is Codex's
independent pass per the v2 brief ("Codex will run that independently after your
implementation"). The structural/behavioral claims below are verified by the Phase 4
test suite instead; this phase's rendered-capture requirement remains the spec for
whoever performs that visual pass.

Run the dashboard locally using repository-supported development settings and
exercise representative states with fixture or mocked API data. Capture PNGs
under `docs/design/pat-1047/acceptance/` for:

- Home at desktop width
- Customers
- Service Health
- one Admin Tools table
- tenant Overview
- tenant Devices
- Apps & Patching
- Compliance & Vulnerabilities
- Reports or Configuration
- device Overview
- one narrow-width global view
- one narrow-width tenant view
- light mode and dark mode

Compare the Home, tenant Overview and device Overview captures directly with
the approved PNGs. Correct visible drift before declaring implementation
complete.

## Phase 6: cache contract and handoff

1. Advance `CONSOLE_BUILD_ID` once for the complete rewrite batch.
2. Update every pinned test and asset query derived from that value.
3. Update `docs/API_REFERENCE.md` so its screen inventory describes the new
   information architecture.
4. Leave `docs/architecture.md` Current State unchanged because this session
   does not deploy.
5. Finish with:

   ```sh
   git status --short
   git diff --stat origin/main
   git diff --check
   ```

Report:

- files changed;
- surface-inventory coverage;
- tests and rendered captures;
- any genuine blocker or intentionally preserved exception.

Stop before commit, push, PR, merge or deployment. Codex owns the independent
review and final sign-off.
