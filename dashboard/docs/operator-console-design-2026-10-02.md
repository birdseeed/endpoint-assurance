# Operator console design contract · 2 October 2026

PAT-2372 prepares a service console for review. It changes no production template, router, backend, authentication, data or deployment. The preview is **local and entirely synthetic**. A passing preview test proves UI behaviour only; it does not prove any API, permission or support session works in production.

## Evidence and authority

- Dashboard source: `00a8d92400dd5f63aeb69e0fe71d0e3b7a6aeab2`, branch `andy/pat-2372-operator-design-contract`.
- Ticket authority: PAT-2372; supplied full body at `../.claude/linear-runs/evidence/mvp-first-step-20261002/PAT-2372-body.md`.
- Related issues read through Linear on 2 October: PAT-1964, 1965, 1966, 1967, 1968, 2373, 2374, 2375. Initial 1967/1968 lookup errors succeeded on retry. No ticket writes.
- Primary route evidence: [console.html](../templates/console.html), `_SECTIONS`, `_TENANT_TABS`, `_WORKLOAD_TABS`, `consoleNav`, `enterTenant`, `tenantTab`, `_onTabActivated`, `_DD_TABS`, and DOMContentLoaded routing.
- API evidence: [main.py](../main.py), route decorators, handler bodies, `_CONSULTANT_WRITE_ALLOW`, `_OWNER_ONLY_GET`, `_CONFIRM_RULES`, `api_bearer_auth`; [console-governance.js](../static/js/console-governance.js) for retirement and capability gates.
- [API_REFERENCE.md](API_REFERENCE.md) supplies context, but its screen inventory is stale: it still lists Billing, Leads, Application Control, Enforcement Evidence and Runbook, and describes six device tabs. Source currently has seven device tabs and excludes those retired screens. Use the source audit below. Correct that documentation with the implementation slice, not by reactivating old surfaces.
- No live API, customer data, credentials, authenticated browser, production host or network-backed fixture was used. The only remote reads were the expressly requested Linear issue descriptions.

## Product contract

Staff run the service, handle tenant lifecycle and answer requested support. Customers manage their own estate evidence, governance decisions and settings in the customer portal. The first screen lists service failures; customer posture is neither the staff queue nor an aggregate score.

Four primary destinations: **Service overview**, **Tenants**, **Operations**, **Intelligence**. Tenant context is explicit above the workspace; global destinations reset it to “All tenants”. Environment and staff role remain visible in the top bar at both acceptance widths. Support is entered through a named tenant, never a context-free global impersonation button.

Keep the existing backend authority until the responsible ticket changes it deliberately. The target read-only support design does not mean the current backend is read-only. Owner/consultant are staff roles. Owner/administrator/viewer in PAT-1967 are reproduced **customer** roles, not new staff RBAC values.

## Route audit and disposition

All hashes below belong to the single `GET /console/{rev}` page. `/` and `/console` redirect to it; there is no rendered `/admin` page. “Keep” retains purpose and authority, with shared shell styling. “Reshape” changes operator presentation or workflow in the named downstream ticket. “Retire” preserves existing retirement; it is not a request to delete compatibility handlers.

Current global navigation uses Work, Customers, Operations and Administration. `_SECTIONS` contains 15 section identifiers, including internal drill-ins. A section identifier is **not** proof of a reloadable deep link: DOMContentLoaded explicitly restores only `#tenant/{id}/{tab}` and `#customers-list`; other initial hashes fall back to Home. `consoleNav` currently uses `history.replaceState`, not push-based back history. PAT-2373 must test and repair route restoration/back behaviour deliberately.

### Global sections: complete `_SECTIONS` inventory

| Current section / entry | Decision and target | Actual reads / source owner | Reason and authority |
|---|---|---|---|
| `#home` (Work) | Reshape → Service overview / PAT-1966 | `/admin/tenants/overview`, `/api/home/triage`, `/admin/health/proxy`, `/admin/automations` | Current triage ranks customer estate issues and has capped tenant fan-out. Replace the staff work model, keep health rail. Do not relabel the old queue “service exceptions”. |
| `#customers-list` | Reshape → Tenants / PAT-2374 | `/admin/tenants/overview`, `/admin/tenants/revoked`, `/admin/tenants/trials` | Identity, access, coverage and freshness replace posture prioritisation. Keep search, filters and lifecycle workflows. |
| `tenant-workspace` → `#tenant/{id}/{tab}` | Reshape → named tenant workspace / PAT-2374, 1967 | Tenant reads below | Preserve isolation and specialist evidence while separating lifecycle from customer-owned writes. |
| `customer-detail` | Keep internal compatibility, no new primary destination | Existing tenant state / overview loaders | Legacy drill-in identifier, not a new operator page. Consolidate only after caller inventory. |
| `device-detail` | Keep read diagnostic drill-in / PAT-1967 | `/admin/devices/{device_id}`, apps, tenant certs, extensions, agent health, logs, historical removals | Device context must retain parent tenant. Do not infer a durable device deep link from this flat section. |
| `findings` | Keep read diagnostic drill-in / PAT-1967 | Tenant `cve-findings`, `findings`, `device-lifecycle`, `finding-dispositions`, `/admin/tenant-rules/{id}` | CIS and CVE evidence remain separate sections and remediation paths. Disposition writes need on-behalf-of authority. |
| `reports` (global) | Keep → Operations / delivery history | `/admin/reports`, local `report_deliveries` (latest 200) | Delivery history is service evidence. Do not infer all report-generation failures from this capped feed. |
| `ops` | Keep → Operations / Infrastructure | `/api/ops/data` | Existing host, backup, disk, service/version/partition evidence and guarded recovery, not customer posture. |
| `automations` | Keep → Operations / Automations | `/admin/automations`, `/admin/automations/{job_name}/runs` | Retired package jobs stay historical; preserve owner trigger/confirmation/audit. |
| `truth` | Keep → Operations / Operational Truth | `/admin/truth`, local manifest joined to evidence | Missing evidence remains visible; no green default for absent emitters. |
| `credentials` | Keep → Operations / Administration | `/api/credentials`, local stored credential inventory | Existing credential workflows and RBAC, no secrets in preview or screenshots. |
| `docs` | Keep → Operations / Documentation | `/api/docs/tree`, `/api/docs/content`, `/api/docs/search` | Retain operator documentation; production source may be GitHub-backed, preview loads none. |
| `logs` | Keep → Operations / Audit logs | `/admin/logs`, local/remote aggregated log sources | Owner-only GET, not an ordinary consultant read. Keep bounded pagination and filters. |
| `homebrew-review` | Reshape location → Intelligence / Homebrew review | `/admin/homebrew/review`; map/accept/dismiss POSTs remain separate | Existing tenant-free mapping review is a usable beta read surface. Moving it must not widen curation permissions. |
| `software-alerts` | Reshape location → tenant-scoped support evidence, not global catalogue | `/admin/software-alerts`; tenant acknowledge POST | Contains tenant context. Do not put observations/tenant IDs into the global product catalogue, or turn customer policy into service failure. |

### Tenant routes: complete 19-entry `_TENANT_TABS` inventory

In this table, `T` means `/admin/tenants/{tenant_id}`. All routes require the exact selected tenant; cached data must carry tenant and request-generation identity. Response arrival for tenant A after switching to B must be discarded, including errors and counts.

| Hash suffix under `#tenant/{id}/` | Decision and target | Existing source paths | Required behaviour |
|---|---|---|---|
| `overview` | Reshape → support summary | `T/needs-attention`, `T/devices`, `T/apps`, `T/enrolled-devices`, `/api/tenant/{id}/certs`; newer evidence helpers also consume findings/drift/lifecycle | Read-only evidence, source failures and freshness, no operator estate rating. Do not revive old advisory-hours helper output. |
| `account` | Reshape → tenant identity/lifecycle | `T/account` (local clients), `T/stale-digest-config`, `T/decommission`, `T/decommission/devices` | Keep account identity and explicit guarded lifecycle. Subscription-tier display is not payment-provider evidence. Retired engagement/charging panels stay absent. |
| `browser-extensions` | Keep read evidence; writes → 1967 | `T/browser-extensions`, `T/extension-policies/scan`, `T/extension-policies`, `T/extension-removals` | Policies are customer decisions. Historical removal/cancellation compatibility must not add execution authority. |
| `cis-controls` | Keep read evidence; writes → 1967 | `/admin/tenant-rules/{id}`, `/admin/tenant-platforms/{id}` | Existing effective rules/platforms are not a global benchmark publishing library. Preserve current PUT/DELETE RBAC pending audited support changes. |
| `compliance-status` | Keep read evidence; writes → 1967 | `T/findings`, `T/devices`, `T/ce-status`; attestations use `/admin/tenant-attestations/{id}/{control_id}` | CE availability is explicit. Do not infer compliance from missing coverage or merge attestation with measured evidence. |
| `cve-findings` | Keep read evidence | `T/cve-findings`, `T/cve-findings/{cve_id}/devices` | Retain affected-device/evidence basis and external remediation context, no patch execution. |
| `device-health` | Keep → device evidence | `T/devices`, `T/enrolled-devices`, `T/agent-health` | Coverage denominator must include enrolled never-seen devices. API limits are not complete estate totals. |
| `disposition-queue` | Reshape → disposition history / 1967 | `T/device-lifecycle`, `T/device-dispositions` | Stop assigning customer disposition decisions as staff work. Keep historical assertions distinct from observed facts. |
| `device-lifecycle` | Keep → coverage evidence | `T/device-lifecycle` | Includes source-specific freshness and disposition context. Not an en-masse reporting-drop detector by itself. |
| `reports` | Reshape → read support / delivery context | `T/reports-config`, `T/reports/deliveries`, `T/delivery-contacts`, `T/report-schedules`, `T/report-records` | Generating/emailing a report changes customer state. Existing permissions remain until 1967 inventories and wraps those routes. |
| `evidence-issued` | Keep → issued evidence | `T/report-records`, `T/report-schedules`, `T/devices`, `T/enrolled-devices` | Frozen evidence, hashes and supersession remain distinct from live data. Existing downloads retain session checks. |
| `software-catalogue` | Keep → customer Software policy, not global Intelligence | `T/allowlist/scan`, `T/app-policies`, `T/new-apps`, `T/app-policy-drift`, historical `T/removal-summary` | Identity and policy need no installer/package. Customer policy writes move to audited on-behalf-of flow; no execution reintroduced. |
| `software-metering` | Keep read evidence | `T/metering`, `T/metering/{app_name}` | Usage scope/collection gaps stay visible; absence does not prove non-use. |
| `deploy-agent` | Reshape label → Agent enrolment | POST `T/enrollment-tokens?path=mdm`; existing platform instructions | Agent onboarding is retained, not software deployment. Token minting is a side effect; owner-authorised lifecycle only, never read-only support session. |
| `shadow-it` | Keep tenant policy evidence | `/admin/shadow-it/findings/{id}`, `T/app-policy-drift`, `T/app-policies` | Tenant-specific observations stay out of global Intelligence. PUT `/admin/shadow-it/{id}/{label}` is a customer-setting mutation. |
| `webhooks` | Keep read configuration/history; writes → 1967 | `T/webhooks`, `T/webhooks/{webhook_id}/deliveries` | Create/edit/delete/test require separate authority. A “test” sends traffic and is not a harmless support read. |
| `customer-access` | Reshape → access evidence / guarded administration | `T/portal-users`, `T/portal-welcomes`, `T/portal-users/{email}/welcome-context`, `T/support-access` | Invitations, welcomes and access changes stay behind current server checks; do not send from a view-as-customer session. |
| `protected-software` | Keep capability gate, normally absent | `T/protected-software`, `T/protected-software/changes` | Only literal `removal_capability === true` permits navigation/rendering. Missing/false/string values deny. Preview does not offer it. |
| `removal-campaigns` | Keep capability gate, normally absent | `T/removal-campaigns` and detail | Same literal-true gate. No new deployment/removal authority; existing guarded historical workflow only if capability is authoritative. |

### Device drill-ins and stale/retired routes

The current `_DD_TABS` has seven members, not the six in the old docs. A source mismatch also needs PAT-2375 investigation: the device certificate helper calls `/admin/tenants/{id}/certs?device_id=...`, while the audited handler is `/api/tenant/{id}/certs`. This audit has not exercised either at runtime; do not claim the device certificate panel is verified.

| Internal tab | Visible label | Decision / source |
|---|---|---|
| `overview` | Summary | Keep diagnostic summary from `/admin/devices/{device_id}` with parent tenant. |
| `inventory` | Hardware | Keep physical inventory from device response. |
| `hardware` | Security | Keep security evidence; the identifier is historical and must not be swapped casually. |
| `software` | Software | Keep apps and browser-extension evidence from existing device/tenant reads. |
| `patching` | Patching | Reshape label to update evidence only after caller audit; preserve truthful historical evidence, no rollout or patch commands. |
| `compliance` | Compliance | Keep evaluations from device response; don't invent control health when evidence is absent. |
| `activity` | Activity | Keep history/log reads. Requesting a log bundle is a POST and belongs outside a read-only support session. |

| Stale or retired destination | Actual current treatment | Contract |
|---|---|---|
| Global `catalogue` | `_QUARANTINED_SECTIONS` sends it to Home | Remains retired. PAT-2249 removed catalogue/hosting backend routes too; not every legacy API still exists. |
| Global billing, renewals, charges, leads | Not in `_SECTIONS` or active navigation; legacy implementation/handlers remain where not separately removed | No DOM render path or activation hook restored. Payment-provider status, when available, is a distinct read model. |
| Tenant service engagement | Removed from active account rendering; implementation retained | Keep retired, including advisory-hours work model. |
| `approved-software`, `new-apps` | Canonicalise to `software-catalogue` | Preserve bookmark compatibility into Software policy. |
| `needs-attention` | Canonicalises to `device-health` | Internal data aggregation, not a separate staff queue destination. |
| `patch-deploy` | Canonicalises to `cve-findings` | Preserve retirement; no Updates/Rollouts/Policy/Activity resurrection. |
| `app-control`, `enforcement-audit`, `runbook` | Canonicalise to `overview` | Preserve retirement in navigation, rendering and activation. |
| Protected/removal hashes without literal-true capability | Canonicalise to `software-catalogue` | Fail closed before loading sensitive panel data. |
| Unknown tenant tab | `enterTenant` defaults to overview; `tenantTab` ignores unknown | Downstream router must specify safe canonical fallback and verify no stale panel remains. |
| Unknown tenant ID | Ordinary hash restore returns to Customers | This applies to normal hash navigation only. When the legacy `_IMP` impersonation object exists, `console.html` synthesises a minimal tenant object from its recorded tenant ID/name if the tenant lookup is missing or fails (`console.html:8321–8332`); this fallback is confined to that legacy impersonation path. |
| `/admin/tenants/{id}/impersonation/start` | GET creates local console impersonation cookie and redirects to `/console`; separate write-mode POST exists | This is **not** the accepted 1967 portal session. Do not wire the new “View customer portal” button to it. |
| `/certs`, report/download links | Separate legacy utility/download paths, outside console hash inventory | No new primary navigation; preserve download credential and audit boundaries. |

## Operator check copy contract

Primary operator copy uses a human name and plain explanation. Each check shows its result and reason alongside the last checked or received time. Keep route paths and internal check IDs in this source map, not in the operator-facing preview. Preserve unavailable, stale, partial and not-assessed states; synthetic preview data must not imply successful live checks.

| Operator-facing name | Technical source mapping | Explanation and interpretation |
|---|---|---|
| Receiving device reports | `/admin/health` → `service_health.ingestion_freshness`; `health_admin.go` provides `most_recent_ingest_at` and `stalest_tenant`; dashboard proxy forwards this as health data | Shows the latest device report receipt and available freshness evidence. It does not establish that every device reported. Keep the receipt/observation time visible. |
| Dashboard version check | `GET /admin/check-status`, check ID `deploy_drift`; `DEPLOYED_SHA`, checkout `HEAD`, tracked-worktree state | Compares the checked-out revision and tracked changes with the recorded deployed revision. A stale result means the comparison has not been verified recently; it does not mean the release is old or prove which binary is running. Show check time and reason. |
| Server maintenance checks | `GET /admin/check-status`, check ID `maintenance_prod01`; local config/security checks including stray configuration backups and systemd hardening | Checks server settings for unexpected changes. This describes configuration and security checks, not routine repairs. Show result, reason and check time. |
| Backup jobs / last successful backup | `/api/ops/data` → `/admin/health` → `service_health.backup_jobs`, mapped to `out.backups` in `main.py` around line 14520 | Show each backup job and latest successful run when evidence exists. A success heartbeat is not proof of restore capability. Missing/unavailable data is not a success; the preview must say “not checked yet” and make no success claim. |
| Scheduled jobs | `/admin/automations` and `/admin/automations/{job_name}/runs` | Show scheduled automation run history and guarded triggers. Retired package jobs are historical, not overdue. Include last run time and a human-readable outcome/reason when available. |
| Check coverage | `/admin/truth` plus declared check inventory and observed evidence | Show which declared checks have evidence and which are missing. Missing evidence stays unassessed; it must not become a healthy zero. |

The approved Operations catalogue also covers outgoing email settings and outcomes, customer access setup, CIS evaluation/CVE matching, vulnerability data updates, report generation and delivery, backup restore tests, server service/database/disk/certificate health, software version checks and billing connectivity/lifecycle. A present source that has not been exercised says “Not checked in this preview”; a missing telemetry or provider integration says “Unavailable”, each with a reason and “Not checked” time. Scheduled-job evidence includes next expected and missed runs and repeated failures. Email covers enabled/dry-run state, authentication and send outcomes, plus bounce evidence where supported; provider acceptance does not prove recipient receipt. Backup completion remains separate from restore testing. Billing stays unavailable until provider integration, then includes webhook failures and unreconciled lifecycle events. PAT-1966 owns the service exception evidence and source thresholds; PAT-2373 owns the operator UI integration; PAT-2375 owns end-to-end source/role/state acceptance. Customer access evidence follows PAT-2382, and provider lifecycle evidence follows PAT-1886.

Carry this name + explanation + result/reason + last checked/received time + disclosed technical detail pattern into PAT-2373 and PAT-1966. Keep technical detail available as secondary disclosure or design/source documentation, not as the primary label.

## API source map and gaps

“Exists” means a handler/caller exists at the audited source SHA, not that a live endpoint was exercised. All preview rows are authored synthetic fixtures. The mock “since” times are incident-onset design examples; they must not be copied from check evaluation time in production.

| Proposed information | Existing provenance | Availability and implementation requirement |
|---|---|---|
| Tenant name, platform, observed count | `proxy_tenants_overview` → platform `/admin/tenants/overview`; local `clients.billing_tier` enrichment | Read exists. Caller contract includes `id`, `name`, `device_count`, `active_last_7d`, platform flags and trial fields. Null is unknown, not zero. Paginated detail counts need authoritative totals. |
| Reporting/coverage and latest evidence | `T/device-lifecycle`, `T/devices` (`last_seen`, `total`, `limit`, `offset`), `T/enrolled-devices`; `DEVICE_FRESHNESS` | Partial directory projection. Do not fan out unbounded device lists for every row. Reuse an authoritative lifecycle summary or add bounded overview projection in 2374 follow-up. |
| Active/revoked access | `/admin/tenants`, overview, `/admin/tenants/revoked`; restore/offboard handlers | Existing indexes, distinct from “reporting well”. Never classify lack of inventory as revoked access. |
| Recorded onboarding | `admin_account_get`, `clients.onboarding_state` | Local account state exists; it does not prove signup time or first useful finding. Preserve its actual vocabulary. Preview “New” is a presentation example, not a newly defined backend enum. |
| Service availability/check freshness | `GET /admin/check-status` → `_get_check_statuses` | Fields are `name`, `state`, `reason`, `evaluated_at`, `age_seconds`, `stale`. State is not `status`, and reason is not `detail`. Existing examples include `deploy_drift`, `maintenance_prod01`. No claim of an existing check named “evaluator” or “CVE matcher”. |
| Ingest/infra | `/admin/health/proxy`, `/api/ops/data`; platform `/admin/health` and local service reads | Existing raw evidence. Preserve absent/error fields. `/api/admin/service-health` has fallback/default logic; do not treat its `ok` fields as authoritative over missing upstream data without validating the underlying evidence. |
| Evaluator / CVE matcher / sync failures | `/admin/automations`, individual `/runs`, platform health, declared `/admin/truth` evidence | Source families exist; exact eligible job names, lag timestamps, error semantics and thresholds need validation in 1966. Do not generate operational rows from catalogue-retirement history or missing emitters. |
| Report delivery failure | `/admin/reports` (200 latest local delivery records); `T/reports/deliveries` (50 latest) | Delivery `status`, `generated_at`, `sent_at` exist. A capped history is not complete incident coverage; distinguish delivery from generation. |
| Report-generation failure | `T/report-records`, generation POST responses; automation/check history | No unified failed-generation exception feed proved in this audit. 1966 must validate upstream failure persistence; otherwise explicitly unavailable. |
| Tenant reporting drop | Current reporting counts / lifecycle snapshots | Baseline, comparison window, expected population and threshold are absent from the reviewed dashboard contract. No percentage invented. Backend follow-up must handle revoked/new/offline cohorts and late/incomplete inventory. |
| Incident “since”, stable identity and resolution | Check evaluation times; delivery event timestamps | No cross-source incident-onset/lifecycle contract established. 1966 must supply first-seen/onset or display “Unknown” with observed-at separately. Stable IDs needed for deduplication. |
| Intune connector lifecycle failures | No current dashboard connector-status source in audited routes; scanner Graph integration removed | Unavailable until PAT-1880 source is supplied. Uploading an Intune file is not a working connector. |
| Signup stuck before first useful finding | Local account onboarding field only | Unavailable until PAT-1884 milestone timestamps and threshold exist. Do not map “onboarding” to “stuck”. |
| Trial/payment/cancellation | Legacy trial endpoints and local account/billing implementation | These are not PAT-1886 provider lifecycle evidence. Show unavailable pending the provider contract. Never restore v2 Billing to fill the gap. |
| Requested customer portal support | Legacy console impersonation/support-opt-out/history handlers | Accepted short-lived tenant-bound portal session, role reproduction, revocation and customer-visible access audit are missing from this dashboard flow. Entire new entry disabled until 1967 integration is proven. |
| Benchmarks | Per-tenant rule/platform routes | No global library/publish/retire/import-dry-run contract in dashboard. PAT-1932/1968 public-launch scope. No mocked “published” catalogue masquerading as current data. |
| Global software intelligence | `/admin/homebrew/review`, `/admin/shadow-it/catalogue` | Existing mapping/category reads, not the full product-confidence programme. Validate that reused projections contain no tenant IDs or observations. Global confidence curation remains 1968/1874/1922; category model stays PAT-2001. |

Existing freshness settings are specific to their evidence: `DEVICE_FRESHNESS = {active_max_days: 7, silent_min_days: 30}`; check status uses six minutes for `deploy_drift`/`maintenance_prod01` and two hours for other checks. The fast loop runs every two minutes. These are **not** approved reporting-drop percentages, evaluator lag limits or signup deadlines. Daily jobs can legitimately exceed the generic two-hour freshness flag; inspect their expected cadence before calling them broken. PAT-1966 must document source-owned thresholds and raise a separate decision item where missing, as its ticket requires.

### Proposed exception response, not an implemented API

Prefer one bounded platform exception feed (1966 explicitly includes the platform) over the old dashboard fan-out. Final URL/schema belongs to that ticket. The minimum contract is:

- `sources[]`: source key, `available|unavailable|error|stale`, reason, observation time, completeness and applicable threshold/cadence provenance.
- `exceptions[]`: stable ID, type, service impact, `scope=global|tenant`, nullable tenant ID, first-seen/onset if known, observed-at, evidence summary and an allow-listed console destination.
- `generated_at` describes feed assembly only. It must not replace source observation time. Missing source cannot resolve an incident or clear a count.
- Coverage and exception count are separate. Empty available sources may produce zero exceptions while the coverage banner remains partial.
- Deep links are derived from trusted route identifiers and tenant identity, not arbitrary URLs supplied by an emitter.

## Brand and component specification

### Pinned identity, no new direction

The root `../branding` checkout on `main` is at `c3cecf8` and still has kit v2.1.0. Its existing Brand v3 worktree/branch `codex/pat-2180-brand-v3-fix`, commit **`adf89fd85c5e830ebb5fcf4aa777f454ccd5bbfb`**, carries `guidelines/brand-v3.md`, generated kit v3.0.0 tokens and the approved Option 4 geometric P. That guide explicitly supersedes the v2 canvas and permits system stacks for console density.

The preview vendors `kit/tokens.css` and `kit/logo/patched-lockup-horizontal.svg` **byte for byte from that commit**, under [operator-preview/brand](operator-preview/brand). No copied asset is placed in production `static/`. See [brand-provenance.json](operator-preview/evidence/brand-provenance.json) for hashes. The outlined wordmark carries no font-download dependency. PAT-2373 must reconcile the canonical branding revision and shared portal/dashboard token migration before production changes; it must not run an unpinned sync from the stale local main checkout.

| Contract | Token / value | Usage |
|---|---|---|
| Primary, links, selected nav, keyboard focus | `--primary`, `--link`, `--nav-active`, `--focus-ring`; light `#2563EB` | Existing v3 blue. Active rail has both fill and 3px leading indicator. |
| Surface, secondary surface, structure | `--surface` white, `--surface-sunken` `#F8FAFC`, `--navy` `#0F172A` | Quiet white tables with navy identity/preview band. No decorative gradients behind data. |
| Primary/body/muted text | `--text-strong`, `--text-body`, `--text-muted` | Headings, body and metadata respectively. Never use disabled token for necessary evidence. |
| Success/warning/failure/unknown | `--success`, `--warning`, `--danger`, `--unknown` and washes | Always labelled. Stale and unreadable evidence is unknown, not healthy. |
| Unavailable/not assessed | `--not-assessed`, dashed border | Visible reason; never a silent blank or healthy zero. |
| Signal orange | `--signal` retained in kit | Not used for actions, focus, navigation or status. No orange needed in this preview. |
| UI type | Native system stack per root/repo rules and v3 console exception | H1 28/1.2, weight 700; H2 17; body 14/1.5; table 13; metadata 11–12. No external fonts. |
| Data type | `--font-mono` with local fallbacks; tabular numerals | Timestamps, codes and identifiers only, not all body copy. |
| Spacing | Local layout aliases 4, 8, 12, 16, 24, 32px | 24–28px workspace gutter, 12px table cell vertical padding, 16–18px panel padding. |
| Shape | `--radius-sm` 6px, `--radius` 10px; status badges 4px | One-pixel semantic borders; no gratuitous card shadows. |
| Focus | 3px `--focus-ring`, 3px offset | Native controls and links; main receives route focus, dialog closes back to trigger. |

### Reusable components and layout

| Component | Contract | Existing implementation to reuse in 2373 |
|---|---|---|
| Operator shell | 76px header; 208px primary rail at 1440, 184px at 1024; labelled destinations; named environment and role | Existing topbar/context/role sources and `_applyRoleGate`; replace layout without changing role resolution. |
| Context bar | Tenant selector separate from global nav, shows actual selected identity; fixture selector exists only in preview | `_populateSwitcher`, `enterTenant`, request-generation guards; no production fixture controls. |
| Page header | One H1, purpose, source snapshot/time; no “live” badge without evidence | Existing `_setDocTitle`, freshness helpers. |
| Dense table | Semantic caption, header cells, text status, bounded wrapping, explicit row link; 36px minimum controls | `.data-table` patterns and existing pagination/filter behaviour; avoid clickable non-keyboard table rows. |
| State panel | Loading, empty, source error, stale last-known evidence and unavailable are distinct | Existing `console-errors.js`/workspace helpers; do not convert rejected fetch to `[]` and green UI. |
| Health rail | Beside main list at 1440, beneath it at 1024; observation ages visible | Existing health/automation loaders, validated source mapping. |
| Tenant lifecycle panel | Separate from customer evidence; clear scope and owner role; dangerous actions retain typed confirmation | `confirmModal`, `_auditHeaders`, existing revoke/restore/decommission handlers. No new destructive API. |
| Support entry/dialog | Exact tenant, required reference/reason/customer role; no pretend session success | New 1967 integration; native dialog in preview demonstrates focus only. |
| Global intelligence entry | Tenant-free products/categories/benchmarks; read availability explicit | Existing Homebrew read/review helper boundaries; do not reuse tenant Software policy as a global catalogue. |

At 1024 the rail remains labelled and visible, action columns stay inside the page, and secondary panels stack below primary evidence. Scrolling vertically is intentional. Smaller widths get a simple stacked preview layout, but mobile acceptance and dark-mode visual QA are deferred to 2373/2375. The preview locks light mode; the vendored kit includes its original dark tokens unchanged.

## Permissions and support boundaries

This document is not a new authorisation model. `api_bearer_auth` currently accepts the app session cookie or shared Bearer; Bearer resolves to owner. The preview neither loads nor emulates these credentials. The local role dropdown only demonstrates presentation and is not security evidence.

Consultants have ordinary GET reads except `_OWNER_ONLY_GET` (including `/admin/logs` and engagement-orphan inspection) plus an explicit write allow-list: report generation/email, account updates, delivery-contact and report-schedule CRUD, legacy engagement/conversion writes and tenant-entry signal. Do not describe consultant as universally read-only, remove these workflows as an incidental shell change, or enable an owner control because a CSS class changed.

Owner lifecycle changes use existing server RBAC, `_CONFIRM_RULES`, `X-Confirm-Resource` where applicable, `_audit_write` and resource scope. Offboard is reversible through restore; purge is not ordinary offboarding and remains a distinct destructive workflow. Agent decommission is not interchangeable with tenant access revocation. The preview has no live action handlers, including for owners.

Download paths retain current app-session defence-in-depth and middleware distinctions. Loading a tenant in the existing console can POST `/api/tenant/{id}/signal`; the future support session must not inherit incidental side effects from general console loaders. API enforcement and side-effect enumeration, not disabled buttons, establish read-only access.

PAT-1967’s 26 September accepted flow is mandatory: select tenant → reference/reason/customer role → short-lived tenant-bound session → **real portal** rendering with permanent tenant/role/read-only/expiry banner. Audit views, existing report downloads, attempted actions, start/end/expiry; revoke immediately; reject tenant switching, extension, reuse and expired sessions. No membership grant or reusable impersonation URL. On-behalf-of writes leave that session, record staff identity plus `channel=console` and requested support reference, and create customer-visible history. A separate dependent mutation slice is permitted; weakening the session is not.

## Downstream implementation slices and gates

| Ticket | Concrete implementation slice | Acceptance and split-out work |
|---|---|---|
| **PAT-2373** | Migrate production brand assets/tokens from reconciled pinned v3 revision; implement shell/context/nav/type/tables/states using browser-loaded helpers; preserve all actual section/tab IDs and gates. Fix global initial hash and back/forward handling, define context-clearing behaviour. Bump `CONSOLE_BUILD_ID` and inspect all pins when production assets change. | Screenshots of all six core views at 1440/1024; no horizontal clipping; focus/skip/dialog/back/reload behaviour; owner and consultant presentation; unchanged server authority; `npm run test:console` plus relevant Python/e2e gates. Do not implement missing support/exception APIs inside a cosmetic shell PR. Update stale API screen docs with final routes. |
| **PAT-2374** | Tenant directory with current identity/access/coverage/freshness and recorded onboarding, including new/no-evidence/revoked/error cases; workspace with separate lifecycle controls and support entry. Preserve existing revoke/restore/offboard/decommission confirmation/audit. | Two disposable tenants; stale-response race and selection/reload tests; null vs zero vs source failure; revoke/restore requests use exact current tenant. Add a separate bounded overview projection if current API lacks required fields; do not N+1 fan out across all tenants. No new deletion API or billing-state inference. |
| **PAT-1966** | Platform service-exception assembly endpoint plus dashboard proxy/helper/list/health rail. Start from validated current ingest/check/job/report evidence. Every exception has actual scope, evidence and valid deep link; onset unknown when unavailable. | Fixture per exception/source state; dedupe/partial/pagination bounds; unavailable never zero; documented source-owned thresholds; no old customer posture ranking. Split persisted reporting-drop baselines, unknown lag thresholds, missing generation-failure persistence and incident lifecycle into explicit backend work. Signup/Intune/billing remain unavailable until upstream contracts ship. Link recovery proof to PAT-2370. |
| **PAT-1967** | Cross-repo platform + portal support-session contract first, then dashboard entry. Required support context, customer-role reproduction, real portal, read-only API denial, immediate revocation, single purpose/expiry and customer-visible audit. | Enumerate every portal mutating route and prove direct calls fail, including email/invite/webhook-test/export creation. Test two tenants, roles, revocation, expiry/replay, attempted writes and download/view audit. Old console impersonation/write-mode is not a substitute. Separate dependent on-behalf-of mutation child may follow; inventory all customer-owned dashboard writes before claiming completion. Feed PAT-2367/2292. |
| **PAT-2375** | Walk complete source inventory above against integrated implementation; record route/role/state/tenant coverage, changed hashes, before/after screenshots and deployed SHA only when runtime access is authorised. | Owner + restricted staff; two disposable tenants; every retired/capability hash; keyboard, tenant races, API failures, confirmations and audit. Local preview evidence does not pass runtime acceptance. Failures/unverified routes keep tickets open. Independent model/session sign-off is separate from author tests. |
| **PAT-1968** (public launch) | Full benchmark lifecycle, import dry-run/publish/retire-successor and product-confidence curation | Beta includes navigation/current read sources only. No tenant identifiers in global catalogue. Existing category model PAT-2001 remains the source; no duplicate catalogue. Not a new beta launch blocker. |

Recommended order: 2373 shared shell; 2374 tenant workspace and 1966 exception integration; 1967 platform/portal security capability with dashboard entry; 2375 integrated acceptance. Backend-owned work can proceed independently once schemas/authority are explicit. Do not keep visual work blocked on unavailable provider/benchmark programmes.

## Local preview and verification

Open [operator-preview/index.html](operator-preview/index.html), or serve **only** `docs/operator-preview` on loopback:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory docs/operator-preview
```

Preview hashes are intentionally local examples: `#service`, `#tenants`, `#tenant/alder`, `#support/alder`, `#operations`, `#intelligence`. They are not a production route migration. “Preview support request” opens an inert dialog, never a portal session. Lifecycle actions are disabled for owner and absent for consultant. Unknown/retired hashes display an unavailable page. Search and state filtering, navigation, tenant switching, reload, state selection, retry and dialog keyboard behaviour are interactive.

The acceptance runner starts an ephemeral loopback static server, imports no dashboard application, uses the locally installed Playwright/Chromium, and aborts requests outside that origin or any non-GET request. CSP also forbids connections and form actions. It serves only preview files and never reads `.env`, customer fixtures or runtime databases.

### Red → green evidence

The acceptance file was written and executed **before** `index.html`, CSS or JS existed. It failed at the meaningful precondition `Requested operator preview does not exist`, exit **1**. Its navigation/state/keyboard assertions were retained unchanged through implementation. The exact command for both runs:

```sh
../dashboard/venv/bin/python docs/operator-preview/acceptance.py
```

- red.log: original failure before implementation.
- green.log and [acceptance.json](operator-preview/evidence/acceptance.json): browser version, passing behavioural checks, exact viewport heights, screenshot filenames and unchanged acceptance SHA-256.
- console-tests.log: existing `npm run test:console`, **343 passed**, exit 0.
- checks.log: local Ruff, JavaScript syntax and whitespace checks. No full backend suite or deploy/e2e fan-out: production code is unchanged and the local preview has its own browser check.
- [supplemental.json](operator-preview/evidence/supplemental.json): keyboard containment/return through the support dialog and tenant filter exercise; additional screenshots include lower 1024 workspace content and the dialog. The initial supplemental Shift+Tab check failed (retained in `supplemental-first.log`); explicit Tab wrapping fixed containment in the installed Chromium. Close also bypasses required-field validation. The primary acceptance file stayed unchanged.

### Exact screenshot index

Every named viewport capture is 1000px high at device scale 1. At these widths tables and controls stay within the page; long pages intentionally continue vertically. Lower-page screenshots cover actions below the first viewport.

| View | 1440 wide | 1024 wide |
|---|---|---|
| Service overview | [1440](operator-preview/evidence/service-1440.png) | [1024](operator-preview/evidence/service-1024.png) |
| Tenants | [1440](operator-preview/evidence/tenants-1440.png) | [1024](operator-preview/evidence/tenants-1024.png) |
| Tenant workspace | [1440](operator-preview/evidence/tenant-alder-1440.png) | [1024](operator-preview/evidence/tenant-alder-1024.png) |
| Support entry | [1440](operator-preview/evidence/support-alder-1440.png) | [1024](operator-preview/evidence/support-alder-1024.png) |
| Operations | [1440](operator-preview/evidence/operations-1440.png) | [1024](operator-preview/evidence/operations-1024.png) |
| Intelligence | [1440](operator-preview/evidence/intelligence-1440.png) | [1024](operator-preview/evidence/intelligence-1024.png) |
| Empty | [1440](operator-preview/evidence/service-empty-1440.png) | [1024](operator-preview/evidence/service-empty-1024.png) |
| Loading | [1440](operator-preview/evidence/service-loading-1440.png) | [1024](operator-preview/evidence/service-loading-1024.png) |
| Error | [1440](operator-preview/evidence/service-error-1440.png) | [1024](operator-preview/evidence/service-error-1024.png) |
| Degraded | [1440](operator-preview/evidence/service-degraded-1440.png) | [1024](operator-preview/evidence/service-degraded-1024.png) |
| Keyboard focus | [1440](operator-preview/evidence/keyboard-focus-1440.png) | [1024](operator-preview/evidence/keyboard-focus-1024.png) |

The browser tests exercise actual Tab/Enter/Escape, skip-to-main, hash navigation/reload, tenant switch without another tenant's text, search, role presentation, disabled session start, retry and computed focus outlines. They do not emulate server RBAC or claim a screen-reader audit. Dark mode, production router integration, all specialist-screen renders, long translated/customer-origin strings, and authenticated runtime checks remain downstream acceptance work.

No commits, pushes, PRs, Linear updates, independent review, deployment or runtime verification were performed in this leaf run. Parent owns full diff acceptance, NVIDIA/OpenCode review and all subsequent publication/gates. Requested runtime was `gpt-6-astra` / high / fresh context; observed model and reasoning metadata were not exposed to this run.
