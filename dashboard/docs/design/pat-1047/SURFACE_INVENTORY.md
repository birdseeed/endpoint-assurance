# PAT-1047 — functional surface inventory

Source of truth for what must survive the rewrite. Originally compiled before the PAT-1047
v1 reskin; updated here to record the implemented v2 mapping against
`docs/design/pat-1047/REDESIGN_V2.md` (v1's rejected horizontal-workload-tab IA is
superseded — see that document for the workflow-first contract). Every row below has a
working destination in the v2 information architecture, or an explicit, recorded reason it
does not.

Format per entry: **current DOM id / activation fn** → **data loader(s)** → **v2 destination**
→ **verification**.

## Global surfaces

Desktop uses a 64px global rail (Work, Customers, Operations, Administration) plus a 280px
context navigator whose content changes with the selected destination or customer
(`_applyContextNav()`). Only one context-nav group is active at a time — the material change
from the v1 always-all-visible single rail.

| Surface | Current section id | Activation | Loader(s) | v2 destination | Verification |
|---|---|---|---|---|---|
| Work (formerly Home) | `section-home` | `consoleNav('home')`, `grail-work` | `_loadHomeData(false)` | Global rail → Work: ranked customer list + inspector, compact Service Health/Automations status rail, secondary recent-activity panel | `test_pat956_home_redesign.py`, `test_pat1047_v2_surfaces_and_responsive.py` |
| Customers | `section-customers-list` | `consoleNav('customers-list')`, `grail-customers` | `_loadCustomersList(false)` | Global rail → Customers: list-detail (searchable/sortable list + selected-customer preview inspector) | `test_pat1047_v2_surfaces_and_responsive.py` |
| Service Health · Infrastructure | `section-ops` | `consoleNav('ops')`, nav-ops | `_opsLoad(false)`, `/api/ops/data` | Global rail → Operations; context navigator → Service Health → Infrastructure | `test_pat955_expanded_sidebar.py` |
| Service Health · Automations | `section-automations` | `consoleNav('automations')`, nav-automations | `_autoLoad(false)` | Global rail → Operations; context navigator → Service Health → Automations | `test_pat955_expanded_sidebar.py` |
| Admin Tools · Billing | `section-billing` | `consoleNav('billing')`, nav-billing | `_loadBilling(false)` | Global rail → Administration; context navigator → Admin Tools → Billing | `test_pat955_expanded_sidebar.py` |
| Legacy Catalogue (Apps/Approvals/Hosting) | `section-catalogue`, `.cat-tab` × 3 | source-compatible only | no live activation | Not navigable under PAT-1481; historical reads remain behind authenticated routes | `test_pat1481_dashboard_quarantine.py` |
| Admin Tools · Credentials | `section-credentials` | `consoleNav('credentials')`, nav-credentials | `_credLoad(false)` | Global rail → Administration; context navigator → Admin Tools → Credentials | `test_pat955_expanded_sidebar.py` |
| Admin Tools · Docs | `section-docs` | `consoleNav('docs')`, nav-docs | `_docsLoad()` | Global rail → Administration; context navigator → Admin Tools → Docs | `test_pat955_expanded_sidebar.py` (API_REFERENCE.md's Admin Tools group now lists Docs — the v1 gap is fixed) |
| Admin Tools · Leads | `section-leads` | `consoleNav('leads')`, nav-leads | `_leadsLoad()` | Global rail → Administration; context navigator → Admin Tools → Leads | `test_pat955_expanded_sidebar.py` |
| Admin Tools · Logs (owner-only) | `section-logs` | `consoleNav('logs')`, nav-logs (`.owner-only`) | `_logsLoad(false)` | Global rail → Administration; context navigator → Admin Tools → Logs | `test_pat1047_v2_surfaces_and_responsive.py` (RBAC) |
| Admin Tools · Reports (cross-tenant delivery log) | `section-reports` | `consoleNav('reports')`, nav-reports | `_loadReports(false)` | Global rail → Administration; context navigator → Admin Tools → Reports | `test_pat955_expanded_sidebar.py` — distinct from tenant-workflow Evidence → Reports, keep both |

### Orphaned / dead surfaces (unchanged by v2, recorded rather than silently touched)

* **`section-customer-detail`** and **`section-findings`** — pre-PAT-358 flat tenant→device→findings IA. No live entry point reaches either from the current customer workflow or global nav; both remain preserved byte-for-byte (DOM, ids, JS untouched), same reasoning as the original inventory: deleting genuinely-unreachable legacy code is out of scope for this IA rewrite.
* **`#section-ops`'s inline `style="display:none"` bug** — fixed as part of migrating `section-ops` to the shared shell (class-based `.active` visibility is the whole point of the shell contract); Infrastructure no longer renders blank when opened.
* **`needs-attention` tenant tab** — retired as a separate destination; stale links canonicalise to **Devices** (`device-health`).
* **`deploy-agent` tenant tab** has no entry in `_onTabActivated()`'s loader dispatch table — its panel has no lazy-load-on-activate hook (renders static/self-initializing content). Preserved as-is; not a rewrite defect to fix.

## Tenant surfaces — customer workflow nav (`#section-tenant-workspace`)

Authoritative current list is `_TENANT_TABS` (console.html): 15 directly-clickable
destinations plus 2 nested Assurance sub-tabs, 17 active destinations total.
`_WORKLOAD_TABS` is the single navigation-mapping source of truth for the six v2
workflow groups (REDESIGN_V2.md); `test_pat1047_v2_surfaces_and_responsive.py` cross-checks
it against the table below exhaustively, not just spot-checking individual tabs.
`EXPECTED_TENANT_DESTINATIONS` in `tests/test_pat955_expanded_sidebar.py` pins all 14
*directly-clickable* destinations (the other 2 — `cis-controls`, `cve-findings` — are
sub-tabs of the `compliance-status` destination via the existing `cc-subtab-nav` 3-way
switcher, not separate nav entries — predates this rewrite, PAT-1009).

| data-tab | Loader (`_onTabActivated`) | v2 workflow group | Sub-position |
|---|---|---|---|
| `overview` | `_ovActivate()` | **Priorities** (default) | — |
| `device-health` | `_dhActivate()` | **Devices** | default sub-tab |
| `disposition-queue` | `_dqActivate()` | **Devices** | sub-tab; PAT-1609 — quiet/stale/dormant devices still on the customer's own list, reconciled against PAT-1595's device-lifecycle; records a named contact's disposition (PAT-1825), never a compliance state |
| `software-catalogue` | `_scActivate()` | **Software governance** | default sub-tab; tenant policy, new-app review and drift only, with no package execution |
| `app-control` | `_acActivate()` | **Software governance** | sub-tab (same `app_control_enabled` conditional visibility preserved) |
| `browser-extensions` | `_bxActivate()` | **Software governance** | sub-tab; policy and exact-artifact extension removal retained |
| `protected-software` | `_psActivate()` | **Software governance** | sub-tab; PAT-1820 — effective per-tenant protected-software set (baseline + tenant additions), add/override-remove, changelog |
| `removal-campaigns` | `_rcActivate()` | **Software governance** | sub-tab; PAT-1612 — PAT-1598's authorised-removal dry-run/authorize/cancel campaigns (draft → dry_run → authorized, cancel from draft/dry_run only); governance record only, no agent-facing delivery path |
| `compliance-status` | `_csActivate()` | **Assurance** | default sub-tab (of the 3-way `cc-subtab-nav`) |
| `cis-controls` | `_cisControlsActivate()` | **Assurance** | sub-tab |
| `cve-findings` | `_cveActivate()` | **Assurance** | sub-tab |
| `reports` | `_rptActivate()` | **Evidence** | default sub-tab |
| `evidence-issued` | `_evdActivate()` | **Evidence** | sub-tab (PAT-1613 — issued reports table, schedule summary and assessor pack, against `docs/design/console-redesign/07-evidence.html`; distinct from `reports`, which owns schedule/contact CRUD and the legacy combined history view) |
| `software-metering` | `_meterActivate()` | **Evidence** | sub-tab |
| `enforcement-audit` | `_eaLoad(tenantId)` | **Evidence** | sub-tab |
| `shadow-it` | `_sitTenantActivate()` | **Evidence** | sub-tab (read-mostly discovered-software findings + approve/unapprove policy view — monitoring/reporting in character, matches Evidence's baseline placement) |
| `account` | `_acctActivate(); _staleActivate()` | **Customer setup** | default sub-tab |
| `customer-access` | `_caActivate()` | **Customer setup** | sub-tab |
| `deploy-agent` | none (see above) | **Customer setup** | sub-tab |
| `webhooks` | `_whActivate()` | **Customer setup** | sub-tab |
| `runbook` | `_rbActivate()` | **Customer setup** | sub-tab |

v1's `Overview`/`Devices`/`Apps & Patching`/`Compliance & Vulnerabilities`/`Reports`/
`Configuration` horizontal workload-tab-bar grouping is retired. PAT-1481 retained 15 directly-clickable
destinations plus 2 nested Assurance sub-tabs, 17 active destinations total; PAT-1613 added
`evidence-issued`, bringing the total to 18 active destinations; PAT-1820 added
`protected-software` (directly-clickable, same as its Software governance sibling tabs), bringing
the total to 19 active destinations; PAT-1612 added `removal-campaigns` (same placement), bringing
the total to 20 active destinations; PAT-1609 added `disposition-queue` under **Devices**, that
group's second destination, giving it its own `subtabbar-devices` sub-nav for the first time and
bringing the total to 21 active destinations, in
`Priorities`/`Devices`/`Software governance`/`Assurance`/`Evidence`/`Customer setup`,
rendered as a vertical customer workflow nav (`#cwf-nav`) in the context navigator —
REDESIGN_V2.md's explicit taxonomy. Two tabs move group in the regrouping: `software-metering`
and `enforcement-audit` move from the old Apps & Patching group to **Evidence** (they are
audit/reporting surfaces, not patching configuration); `reports` and `shadow-it` also land in
**Evidence** rather than a standalone `Reports` group. `patch-deploy` remains a source-compatible
legacy panel only and stale hashes canonicalise to CVE Findings. The tenant `software-catalogue`
route is retained as Software policy: stale approved-software/new-apps hashes canonicalise there,
and it exposes policy classification, review and drift evidence only. Global catalogue and all
package-execution controls remain quarantined.

## Device workspace (`#section-device-detail`)

v1's horizontal six-tab bar is retired. v2 is a diagnostic frame: a compact identity header
(persistent, all tabs) plus a narrow vertical device navigator (`#dd-subtab-nav`, now
`.ddw-nav`) beside the panel content (`.ddw-panels`).

| Current | Loader | v2 destination | Notes |
|---|---|---|---|
| Identity grid (`#dd-identity-grid`) + issues banner (`#dd-issues-banner`) — always visible, not a tab | `_loadDeviceDetail()` | **Summary** (`data-ddtab="overview"`, label renamed) | Split investigation view: ranked issues/signals, device details, recent activity. `_ddRenderOverviewPosture()`'s invented 0-100 "posture" score (arbitrary point deductions, no backing metric) is deleted — `_ddRenderSummaryTiles()` renders only the two real, already-sourced counts (Patching failures, Compliance findings/%) |
| Header actions: `#dd-revoke-btn`, `#dd-delete-btn`, back-link | `_ddRevokeDevice()`, `_deleteDevice()`, `consoleNav('tenant-workspace')` | **Summary** (persistent header, all tabs) | Both destructive actions keep `dangerConfirm()` + `X-Confirm-Resource`, unchanged |
| `patching` sub-tab | `_applyDdTab` → static (loaded with `_loadDeviceDetail`) | **Patching** | unchanged content |
| `compliance` sub-tab | same | **Compliance** | unchanged content |
| `software` sub-tab | same | **Software** | unchanged; `extensions` folded in as a sub-section (see below) |
| `extensions` sub-tab | `_loadDeviceExtensions()` | **Software** (sub-section) | No standalone "Extensions" destination in the 6-destination set. Folded into Software as a secondary in-panel sub-tab, preserving `_loadDeviceExtensions()` and all filtering unchanged |
| `security` sub-tab (AV/EDR, signals, system extensions, background items) | same | **Hardware** | content renamed to Hardware, unchanged data/loader |
| `logs` sub-tab (agent logs, "Request logs" action) | same | **Activity** | unchanged, `_logsRequest()` preserved |

`_DD_TABS` array, `_ddTab()`/`_applyDdTab()` dispatch, and all six panel divs are preserved;
only the outer nav markup (horizontal tab bar → vertical `.ddw-nav`) and the Overview→Summary
label change. At tablet width the evidence inspector moves below the selected signal; at phone
width both the customer workflow nav and the device navigator become full-width stacks
(`@media (max-width: 900px)` in `theme.css`/`console.css`).

## PAT-854 safety carried into v2

`tests/test_pat854_xss_onclick_escaping.py` passes (0 hits), including its whole-template
regex regression guard, which covers every new `onclick` handler added by v2 (Work's
`_homeSelectTenant`/`_renderHomeInspector` signal rows, Customers' `_clSelectTenant`/
`_clRenderInspector`) — all use the `data-*` + `this.dataset.x` idiom, never string
concatenation into a JS literal.

## CONSOLE_BUILD_ID contract

`main.py` defines `CONSOLE_BUILD_ID`. Consumed by `/console/{rev}` routing and stamped into
the Jinja context as `console_build_id`, used for 3 `?v=` cache-busting query params in
`templates/console.html` (theme.js, theme.css, console.css). `static/js/theme.js` deliberately
does **not** hardcode a second copy — it parses its own `<script>` tag's `?v=` at runtime
(`consoleBuildId()`) specifically because a hardcoded second copy caused two past
mobile-redirect-loop incidents (PAT-966, 2026-07-25). This indirection is preserved unchanged;
`CONSOLE_BUILD_ID` advanced for the complete v2 rewrite batch (`"2026-07-29a"` →
`"2026-07-29b"`) and again for the Portal-palette acceptance correction
(`"2026-07-29c"`), alongside every pinned test that asserts its literal value
(`tests/test_admin_logs.py`, `tests/test_pat1006_home_patching_first.py` per AGENTS.md's
footgun note; `tests/test_console_build_id.py` asserts the mechanism, not a literal, so needed
no change).

## Tests rewritten or added for v2

* `tests/test_pat955_expanded_sidebar.py` — rewritten: pins the global-rail/context-navigator
  split, the conditional (not always-expanded) context-nav groups, and the vertical customer
  workflow nav's exhaustive data-tab/group mapping.
* `tests/test_pat956_home_redesign.py` — rewritten: pins Work's list-detail anatomy (ranked
  list + inspector, no leading metric-card strip), selection-without-navigation, and the
  compact operations status rail sitting below the priority workspace.
* `tests/test_pat1047_console_rewrite.py` — rewritten: shell regression coverage for the new
  structure, the shared Portal palette, the deleted device posture score, the
  removed hidden duplicate identity, and the retired v1 anchors alongside the pre-existing
  ones.
* `tests/test_pat1047_v2_surfaces_and_responsive.py` — added: exhaustive walk of all 11 global
  surfaces, all 17 active tenant destinations (15 directly clickable plus 2 nested Assurance sub-tabs,
  cross-checked against the table above), all 6 device
  destinations, the identity/RBAC contract surviving the shell rewrite, and responsive
  no-horizontal-tab-stack behaviour (both navigators becoming drawers, list-detail/device
  workspace stacking at narrow widths).
* `tests/test_pat783.py`, `tests/test_admin_logs.py`, `tests/test_pat1006_home_patching_first.py`
  — small updates: the first for the new `#cwf-nav` id (was `#workload-tabbar`), the latter two
  for the `CONSOLE_BUILD_ID` bump and (PAT-1006) the `home-dashboard-grid` → list-detail markup
  change.
* Tab-specific frontend-slice tests (`test_app_control_tab.py`, `test_cve_findings_tab.py`,
  `test_enforcement_audit_tab.py`, `test_needs_attention_tab.py`, `test_deploy_agent_tab.py`,
  `test_pat826.py`, `test_pat128.py`, `test_pat852.py`, `test_pat960_catalogue_hosting_ops.py`)
  assert `data-tab` values, panel ids, and loader functions that are all preserved unchanged by
  v2 — pass without modification since they don't assert the outer nav chrome.
