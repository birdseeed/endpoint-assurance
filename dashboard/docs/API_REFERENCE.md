# API Reference — `dashboard.patched.im`

All routes under `https://dashboard.patched.im`. FastAPI/Uvicorn on `127.0.0.1:8000`, fronted by nginx and Cloudflare Access. `main.py` has well over a hundred routes at this point — this doc groups them by area rather than itemising every one. **`main.py` is the source of truth for the exact route list**; grep it (`grep -n '@app\.\(get\|post\|put\|patch\|delete\)' main.py`) for anything not covered below.

## Auth model

Requests under `/api/*` and `/admin/*` (except `GET` requests whose paths end `/download`) go through `api_bearer_auth` middleware, which accepts **either** of two credentials (PAT-695):

1. **Session cookie** (`patched_session`) — minted server-side when `/console/{rev}` renders, from the Cloudflare Access identity in the `Cf-Access-Authenticated-User-Email` header. This is how the browser UI authenticates; there is no client-side Bearer token to manage any more.
2. **Shared Bearer token** (`Authorization: Bearer ${DASHBOARD_API_KEY}`) — for scripts, the instant-rollback path, and inter-service callers (e.g. Jarvis Job Scout). Carries no email, so it always resolves to the `owner` role.

Cloudflare Access itself still gates the edge first — email-OTP, authorised team list, `CF_Authorization` cookie. An unauthenticated request never reaches the app.

**RBAC (PAT-695/696):** every authenticated caller resolves to a role — `owner` or `consultant` — via `_role_for_email`. Consultants get all `GET`s plus an explicit write allow-list (`_consultant_write_allowed`); anything else on a mutating verb 403s with `"requires the owner role"`.

**Destructive-action confirmation:** some `/admin/*` proxies (tenant delete/purge and similar) require a header `X-Confirm-Resource` echoing the resource's name/identifier back, or they 428/409. See `_confirm_rule` in `main.py`.

**Audit log:** every destructive write (once past RBAC/confirmation) is recorded via `_audit_write(actor, role, method, path, outcome)`.

**Exemptions from the middleware** — routes reached by plain `<a href>` / `window.location` navigations, which can't carry custom headers, rely on CF Access (cookie) alone instead:
- `GET` requests whose paths end `/download`
- `/admin/**/impersonation/start` and `/admin/impersonation/end`

| Response signal | Origin | Meaning |
|---|---|---|
| HTTP 302 → `cloudflareaccess.com` | CF edge | Not signed in to CF Access — log in first |
| `{"error":"Unauthorized"}` (401) | App middleware | No valid session cookie and no/wrong Bearer |
| `{"error":"Forbidden — ..."}` (403) | App middleware (RBAC) | Consultant role attempting a write outside the allow-list |
| `{"error":"Confirmation required..."}` (428) / `{"error":"Confirmation mismatch..."}` (409) | App middleware | Missing/wrong `X-Confirm-Resource` on a guarded destructive route |
| `{"error":"Not available in impersonation mode..."}` (403) | `impersonation_write_guard` | Mutating call during a read-only impersonation session |
| 200/4xx/5xx reaching the handler | App | Request passed both auth layers |

---

## Pages

There is **one** page template, `console.html` — a single-page app with a hash router for tenant sub-tabs. There is no `templates/dashboard.html`, no standalone `/admin` page, and no "Compliance Admin" screen; those were retired in the console rebuild. Any doc, runbook, or comment still pointing at `GET /`, `GET /admin`, or `templates/dashboard.html` as a rendered page is describing a screen that no longer exists.

The PAT-2373 operator shell retains the current section IDs. Global destinations are **Service overview** (`#home`, existing customer-posture reads), **Tenants** (`#customers-list`), **Operations** (`#ops`) and **Intelligence** (`#homebrew-review`, existing tenant-free mapping review, and `#software-identities`, PAT-2404, below). Operations also exposes `#automations` (Scheduled jobs), `#truth` (Check coverage), `#credentials`, `#docs`, `#software-alerts`, `#logs` (owner only) and `#reports`. These global hashes restore on reload and browser history; entering a global destination clears selected tenant context.

PAT-2374 keeps the tenant directory and account lifecycle as read projections of existing sources. `tenants/overview` supplies total devices and `active_last_7d` (reporting in the last seven days); missing counts remain unknown, and malformed collections are unavailable rather than an empty estate. The separate revoked source supplies revocation dates. Fetch time is labelled separately from unknown source observation time. Account 404 is unavailable identity/onboarding evidence, not a new prospect record. Portal mappings are provisioned identities, with disabled mappings and the independent welcome-send record shown separately; neither proves current Cloudflare sign-in authority or recipient receipt. Report configuration, records and delivery attempts fail independently. Read generations reject late success and error callbacks after tenant changes or navigation, including A → B → A. The support-session entry is disabled and unavailable pending PAT-1967; it does not invoke impersonation. Existing lifecycle actions, confirmation, RBAC and audit routes are unchanged.


Tenant routes remain `#tenant/<id>/<tab>` with existing tab and capability gates. Customer access is the existing access-management screen, not a new support session. Device detail and findings remain contextual drill-ins. No new API, permission, session, destructive action or retired-screen activation is introduced. Service-exception assembly, tenant lifecycle redesign and real portal support sessions remain separate tickets.

### `GET /`

Redirects (302) to `/console/{CONSOLE_BUILD_ID}`.

### `GET /console`

Redirects (302) to `/console/{CONSOLE_BUILD_ID}`. `CONSOLE_BUILD_ID` is a cache-busting string bumped in `main.py` on console changes.

### `GET /console/{rev}`

Renders `console.html` — the entire authenticated UI. If `rev` doesn't match the current `CONSOLE_BUILD_ID`, redirects to the current one (forces stale browser tabs onto the current build). Also mints the `patched_session` cookie from the CF Access identity, hydrates any active impersonation session, and injects role/env/API-backend context for the application shell.

**Auth:** CF Access only for the page load itself (session cookie is minted here, not required to reach it). All subsequent `/api/*`/`/admin/*` calls from the page need the cookie this route just set.
**Response:** `text/html`.

---

## Screen / tab inventory

`console.html` is one page, organised around progressive investigation
(`all customers -> customer priorities -> affected devices -> device
evidence`, per `docs/design/pat-1047/REDESIGN_V2.md`). Three persistent
regions at desktop widths:

- **Global rail (64px)** — `consoleNav()` routes between the four global
  destinations: Work, Customers, Operations, Administration. Establishes
  global context only.
- **Context navigator (280px)** — its content changes with the selected
  global destination or customer (`_applyContextNav()`): Operations exposes
  the Service Health group, Administration exposes the Admin Tools group,
  and a customer exposes the customer workflow nav (`tenantWorkload()` for
  the six workflow groups, `tenantTab()` for the 19 active specialist tenant
  screens within them).
- **Workspace** — the active list, investigation or specialist tool.

Both the global rail and context navigator stay visible in global, tenant
and device contexts (the context navigator collapses to zero width, never
hidden, when no group applies — e.g. on Work/Customers). The top bar
contains the customer switcher and operator identity.

**Always visible (global rail):**
- **Work** — customer-priority command centre: a ranked customer list plus
  a selection inspector (signals, affected devices, evidence age, direct
  links into the relevant customer destination), a compact Service
  Health/Automations status rail, and secondary recent estate activity. Not
  a generic dashboard and not a per-device queue.
- **Customers** — list-detail: searchable/sortable customer list plus a
  selected-customer preview (service tier, device coverage, strongest
  signals, `Open customer` action).

**Operations → Service Health (context navigator):**
- **Automations** — scheduled job evidence. `installomator_sync`,
  `daily_vendor_verify`, `mirror_pipeline`, and `mirror_pipeline_windows`
  remain visible only as quarantined/retired history, never as healthy or
  overdue scheduled work.
- **Infrastructure** — service health / ops panel (req/s, p95 latency, extractor throughput, scheduler heartbeat).

**Administration → Admin Tools (context navigator):**
- **Billing** — tier rates, billing summary.
- **Credentials** — stored credential inventory.
- **Docs** — searchable operator documentation.
- **Leads** — Calendly-sourced prospect leads and conversion tracking.
- **Logs** — owner-only unified feed over every audit/alert-history table the dashboard writes (admin actions, impersonation sessions, report sends, outbound Slack alerts) plus remote automation-run history. Server-side filters (source, outcome, free text, time range), bounded + paginated, expandable rows.
- **Reports** — cross-tenant report delivery log.

**Intelligence (context navigator):**
- **Homebrew review** — tenant-free Homebrew CVE mapping queue (PAT-2046).
- **Software identities** — cross-tenant review of software identities devices reported (PAT-2404): platform switch and search, a "Reported by devices" table (Review for promotable rows, blocked reason otherwise) and a "Reviewed" table (Retire with a reason and confirm). Owner-only writes; stores nothing locally. See `/admin/software-catalogue/*` below.

**Customer workflow** (`Customers` → select a customer — vertical nav in the
context navigator, starting with customer identity/tier/coverage/last
evidence time):

| Workflow group | Specialist screens |
|---|---|
| **Priorities** (default) | Ranked signal list + detail inspector, combining tenant health, estate summary and Needs Attention data |
| **Devices** | Device inventory, health, drill-down and historical removal evidence. Cancellation remains available for genuinely pending historical removals. Needs Attention remains an aggregation consumed by Work and Priorities, not a visible destination; stale hashes canonicalise to Device Inventory |
| **Software governance** | Software policy, Browser Extensions, Application Control (entitlement-gated) and Protected Software. Software policy records approved/unapproved decisions, new-app review and policy drift only; Protected Software (PAT-1820) is the per-tenant effective set of software an estate's endpoint controls must never remove or disable (shared baseline plus tenant additions), with an audited baseline override-remove and a changelog; none of these start package, rollout, self-service or direct app-removal execution |
| **Assurance** | Compliance Status, CIS Controls, CVE Findings |
| **Evidence** | Reports, Issued Reports, Software Metering, Enforcement Evidence, Shadow IT |
| **Customer setup** | Account, Customer Access, Deploy Agent, Webhooks, Runbook |

Issued Reports (`evidence-issued`, PAT-1613) is the frozen-evidence view against
`docs/design/console-redesign/07-evidence.html`: the issued-reports table (hash,
frozen coverage, supersession), a read-only schedule summary and the assessor
pack checklist. Reports (`reports`) keeps ownership of schedule/contact CRUD
and the pre-1613 combined artifact/delivery history.

There are 19 active tenant `data-tab` values. Stale `#tenant/{id}/approved-software`,
`#tenant/{id}/new-apps` and `#tenant/{id}/software-catalogue` hashes canonicalise
to Software policy. A stale `patch-deploy` hash canonicalises to CVE Findings,
not the quarantined deployment panel.

**Device workspace:** a diagnostic frame — compact identity header
(preserves guarded revoke/delete actions) plus a narrow vertical device
navigator: Summary, Hardware, Software, Patching, Compliance and Activity
(`data-ddtab="overview"` is unchanged; only its visible label is now
"Summary"). Summary is a split investigation view (ranked issues/signals,
selected-issue evidence, recent activity + device facts) — it no longer
computes a synthetic 0-100 "posture" score; Patching/Compliance tiles show
only real, already-sourced counts. Security inventory is under Hardware,
browser extensions are under Software, and agent logs are under Activity.
Existing revoke, delete, removal, patching and log-request safeguards
remain unchanged. At narrow widths both the customer workflow nav and the
device navigator become full-width stacks; nothing is ever unreachable
without hover.

**PAT-1481 quarantine:** The global Catalogue, package verification/hosting/mirror,
Patch & Deploy, rollout/ring, Self Service Catalogue and direct app-removal
surfaces are not console destinations. Their historical read routes may remain
for evidence and recovery, except the catalogue and hosting routes, which
PAT-2249 removed outright (see "Catalogue review, hosting and discovery
pipeline (retired, PAT-2249)" below). The central proxy gate returns HTTP 410 with
`code="legacy_execution_quarantined"` for legacy authority-increasing
mutations, before an upstream call or local write. Tenant Software policy is
retained separately for policy classification: approved/unapproved decisions,
new-app review and drift evidence. It does not offer required-state, install,
deploy, Self Service or removal actions. The software execution path is
retired (PAT-2299): Patched records policy only.

---

## Route groups

### `/admin/tenants/*` — tenant CRUD, RBAC-guarded proxy to the Go admin API

Covers tenant list/create/update/restore/purge, devices, findings, CVE findings, active finding dispositions (CIS by device + rule; CVE by tenant-aggregate CVE), allowlist, app policies + drift, enrollment tokens, trials, software metering, ring rollouts, webhooks, reports/report-schedules/report-records, delivery contacts, authored assessment artifact approval/token issue, account (billing tier, contacts, onboarding), service engagement, stale-digest and ring config, enforcement audit, browser extensions, browser-extension policies + scan (PAT-826), protected software + changelog (PAT-1820), subscription tier, attestations, portal-users (PAT-128, see below), the portal welcome email (PAT-1990, see below), and agent decommission state (PAT-1111, see below). All platform-backed routes proxy to `example-api-host.example-tailnet.ts.net:8443` over Tailscale; service engagement is a dashboard-local operating snapshot. **Auth:** session cookie or Bearer + RBAC.

`GET /admin/tenants/{tenant_id}/finding-dispositions` returns active, non-superseded disposition records and accepts optional `finding_kind=cis|cve`. `POST` records a new disposition and supersedes the prior active one for the same identity. CIS requests use `device_id` + `rule_key`; CVE requests use tenant-aggregate `cve_id`; both require `status` (`acknowledged`, `risk_accepted`, or `closed`) and `recorded_by`, with optional `reason`. Writes are owner-only.

**Rollout history (PAT-1398).** Legacy rollout and ring reads remain available
for evidence. Resumption, skip, emergency dispatch and ring configuration
writes are quarantined at the dashboard boundary with the stable
authenticated-owner 410 response; pause and other authority-reducing recovery
operations are not broadened by this quarantine. PAT-2249 removed the Console's
rollout-create prompt: it matched updates against the retired catalogue review
model, and PAT-2246 had already removed the platform's create route. PAT-2299
removed the quarantined `POST /admin/tenants/{id}/ring-rollouts` create proxy
and its quarantine and audit rules; the collection path still answers `GET`,
so a `POST` to it is now a `405`.

**Authored assessment delivery (PAT-1405).**

- `POST /admin/tenants/{id}/assessment-artifacts/approve` accepts a PDF or DOCX
  multipart upload plus engagement reference, document version and generation
  timestamp. It requires a named owner session; shared Bearer auth is refused.
  The platform derives the path and owns the immutable bytes/provenance.
- `POST /admin/tenants/{id}/assessment-artifacts/{artifact_id}/download-tokens`
  issues a named-recipient, expiring, single-use token from a named owner
  session. The success response is projected onto a fixed field allowlist
  (`token`, `expires_at`, `recipient`, `artifact_id`, plus the dashboard-added
  `download_url`) rather than relayed verbatim, so "never receives a
  filesystem path" is structural rather than merely true of today's platform
  response shape.

Both writes are owner-only and enter `admin_audit_log` through the destructive
route classifier. Both require an inbound `Content-Type` matching what they
accept (`multipart/form-data` / `application/json` respectively, checked
before the body is read) — this repo has no app-wide CSRF-token mechanism;
SameSite=Lax on `patched_session` (shared by every `/admin/*` write route) is
the primary cross-site control, and the Content-Type check is defense-in-depth
against body-smuggling techniques independent of that. Approve additionally
caps the request body at `_ASSESSMENT_APPROVE_BODY_MAX_BYTES` (25 MiB document
+ 1 MiB multipart overhead, mirroring the platform's own
`maxAssessmentArtifactBytes` ceiling) and reads it via a running size cap that
rejects an oversized upload mid-stream, before it is fully read — but this
bounds the *accepted* size, it does not avoid full in-memory buffering: a
body within the cap is still accumulated as a list of chunks and then
`b"".join`'d into a single ~26 MiB bytes object before being forwarded. They
do not add a customer-facing authoring UI.

**Token consumption is irreversible once the platform redeem call is made.**
The platform marks a `/reports/download/{token}` assessment token used in the
same DB transaction that hash-verifies the artifact, committed before any
response is returned — there is no un-redeem/reissue endpoint, so a
dashboard-side validation failure after a successful platform redemption
cannot be recovered from this side alone. The dashboard's own post-receipt
checks are pinned to the platform's actual guarantees (size ceiling, filename
character class) so this should not trigger in normal operation; see the
comment in `public_report_download` (main.py) for the full analysis.

**`/admin/tenants/{id}/service-engagement` (PAT-1051)**: retained compatibility contract, with no active Console surface under PAT-1965. `GET` returns `{engagement: null|{...}}`; `PUT` upserts the current customer service, named specialist/cadence, posture review, and 90-day plan snapshot. Updates carry the `updated_at` value last read as `expected_updated_at`; stale writers receive 409 plus the current snapshot, preventing silent lost updates. Successful writes audit the complete before/after snapshots. `DELETE` is owner-only, destructive-audited and requires `X-Confirm-Resource` to match the tenant; it removes only this snapshot and audits the prior resource against JSON `null`. An authenticated consultant may read and maintain the snapshot, while a support-impersonation session is restricted to its selected tenant. Customer service names are the exact public catalogue names and remain separate from the technical tier/entitlement model. `decisions`, `owners`, and `exceptions` are bounded string arrays. `project_links` and `escalation_links` accept only absolute HTTP(S) `{label,url}` references; there is no project, task or CRM workflow behind them. The orphan preview and repair routes retain their owner-only, audited recovery semantics.

**`/admin/tenants/{id}/decommission[/devices]` (PAT-1111)**: staff-only thin proxies to the platform contract landed under PAT-1108. There is no portal surface.

- `GET /admin/tenants/{id}/decommission` returns the current directive: `{tenant_id, mode, expires_at, purge, reason, set_by, set_at}`. `mode` is `none`, `expiry`, or `immediate`.
- `GET /admin/tenants/{id}/decommission/devices` returns `{tenant_id, total, devices}`. Every registered device is included, even when it has never reported. A device entry is `{device_id, hostname, status, last_reported_outcome, last_reported_at, terminal_without_acknowledgement}`. `status` is `pending`, `acknowledged`, `removed`, `failed`, or `expired_unreachable`.
- `PUT /admin/tenants/{id}/decommission` accepts `{mode, expires_at, purge, reason}`. The dashboard discards any client-supplied `actor` and injects the authenticated session email or `bearer-token`; the platform records that value as the claimed actor in its append-only decommission audit. `expires_at` is required, validated as a future timezone-bearing RFC3339 timestamp, and forwarded only for `mode="expiry"`; immediate effect must use `mode="immediate"`. `reason` is nullable text capped at 500 characters. Immediate removal additionally requires `X-Confirm-Resource` to match a resolved human tenant name; the path tenant identifier is not accepted as confirmation, and an unresolved identity fails closed as not found or temporarily unavailable rather than as a confirmation mismatch. The route is owner-only and is also recorded in the dashboard `admin_audit_log`. Before and returned-after snapshots are accepted only as JSON objects whose `tenant_id` matches the route; bounded `read_error` markers are recorded when a read is unavailable, mismatched, or invalid. Before dispatch, the audit holds the validated attempted contract; a connection failure retains that bounded marker. A failed HTTP response records only its status and the attempted `{mode, expires_at, purge, reason}` under a non-authoritative `write_error` marker, never the upstream error body.

The Account view uses `mode="expiry"` for assessment expiry and `mode="immediate"` for the separately confirmed Remove agents action. Both actions present `purge` as an explicit operator choice that defaults to `false`. With purge off, the endpoint removes only its Patched uploader/service; with purge on, it also removes local Patched credentials, queued uploads and cached artefacts. Neither setting purges the server-side tenant or history. Customer offboarding remains `DELETE /admin/tenants/{id}` and never calls the decommission write. Its confirmation explicitly directs an operator who also needs agent removal to complete and verify the separate device-count and tenant-name-confirmed removal step first, because offboarding can prevent devices collecting a later directive. The Console reads the response back before showing success, merges `last_seen` from all paginated normal-device inventory pages (500 devices per page, capped at 20 pages) for operator context, and keeps `failed` (a reported hard removal failure) distinct from `expired_unreachable` (offline or not seen). If inventory enrichment fails, the state table remains available but shows `Unavailable` for Last seen and a summary warning instead of presenting missing enrichment as a device that has never reported.

**`/admin/tenants/{id}/portal-users[/{email}]` (PAT-128)** — Customer Access tab. Proxies to the go-service's own admin CRUD for `portal_users` (PAT-693, `internal/handlers/portal_users.go`) — the email -> tenant mapping `internal/portalauth/middleware.go` checks on every portal request. This dashboard adds no new auth/session/role system; it just lets an operator view/grant/revoke that mapping per tenant. `GET`/`POST` always use the `{id}` from the URL path (never a client-supplied tenant). The upstream create endpoint is an upsert-by-email that silently MOVES an already-mapped email to whatever tenant re-POSTs it, so `POST` here 409s with `{"error":"already_mapped_elsewhere","current_tenant_id":...}` if the email is currently active under a *different* tenant, unless the body includes `"force": true` — the UI surfaces this as a confirm-and-retry step rather than moving a customer's access silently. `DELETE` (revoke) first confirms the email belongs to `{id}` before calling the upstream disable endpoint, because that endpoint is email-only (not tenant-scoped) — without this check, tenant A's tab could disable a tenant B user; a failed upstream membership check itself 502s (distinct from a genuine 404 not-found). "Grant access" does not send any email — becoming a real Cloudflare Access identity is a separate, manual, out-of-band step in Patched's directory. Telling the customer they are in, once both steps are done, is `/welcome` below.

**`/admin/tenants/{id}/portal-users/{email}/welcome` and `/welcome-context`, `/admin/tenants/{id}/portal-welcomes` (PAT-1990)** — the verified welcome email. `POST .../welcome` sends a design partner their portal sign-in instructions; `GET .../welcome-context` is a read-only preflight running the same checks so the confirmation modal never offers a send the server will then refuse; `GET /portal-welcomes` lists the local welcome state so the Customer Access table can show a `Welcome sent` badge (recorded send, not recipient receipt).

The send is gated, in this order, and there is no override on any of it:

1. **Named individuals only.** The local part is matched case-insensitively (including the pre-`+` segment of a plus-addressed mailbox) against `it`, `admin`, `support`, `info`, `helpdesk`, `security`, `office`, `accounts`, `team`, `all`. A hit 422s before any upstream call. Portal sign-in is a one-time PIN mailed to the address itself, so a shared mailbox means an unbounded set of people can read a customer's estate posture.
2. **Customer Access membership** under this tenant, and not disabled (404 / 409). An upstream lookup failure is a 502, never a "not a member".
3. **Cloudflare Access membership**, checked live against `GET /accounts/{acct}/access/apps/{app}/policies` using the same `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_ACCESS_APP_ID` read credential the `portal_auth` monitor already uses (PAT-837/PAT-1712) — no new credential. The address must appear **exactly** (case-insensitively) in an `email` Include rule of an **Allow** policy. An `email_domain`, `email_list` or `everyone` rule does **not** count: "somebody at this domain may sign in" is not the claim this gate makes, and One-time PIN is the only login method enabled on that application, so identity is the exact address. An exact match in the same policy's `exclude` overrides the include. Every read failure — missing credential, unreachable API, non-200, unparseable body, no Allow policy present at all — is a refusal (412 for a genuine negative, 502 for an unverifiable one), because an incomplete read of the policy is not authority to claim the address is present.
4. **`PORTAL_WELCOME_CLOUDFLARE_SENDER` must be set** (503 otherwise) — see the note in `RUNBOOK-portal-auth-healthcheck.md`.
5. **`EMAIL_DRY_RUN` refuses** (503, `{"dry_run": true}`) rather than pretending. `_send_email()` returns `True` under dry run (PAT-1010), so recording `welcomed_at` off that return would mark a customer welcomed who was never written to.

`X-Confirm-Resource` must echo the recipient address (kind `portal_recipient`, resolved purely locally), and the route is in `_DESTRUCTIVE_RULES`, so it is owner-only and carries the usual central `admin_audit_log` row. It **also** writes one row per attempt to the local `portal_welcome_audit_log` — `sent`, `refused`, `failed`, `dry_run` or `sent_unrecorded` — with the reason. `welcomed_at`/`welcomed_by` land in `portal_user_welcomes` only after `_send_email()` returns `True` with delivery live; a failed send leaves state untouched and returns the real error (the PAT-815 shape). Sender is `MAIL_SENDER` (`noreply@patched.im`); `Reply-To` is `andy@patched.im`. **Resend takes the identical path** — same Cloudflare check, same confirmation — because a person's policy membership can be removed between the first send and the second.

### `/admin/software-catalogue/*` — Software identities screen (PAT-2404)

The Intelligence screen **Software identities** (`#software-identities`, sidebar item after Homebrew review) is a cross-tenant staff review of software identities that devices have reported into the platform's curated identity catalogue. The console stores nothing: each route proxies to `PATCHED_API_INTERNAL` with the internal bearer token. This is an identity catalogue, not a package catalogue; no installer, label, deployment or update field exists on the screen or the routes. The screen shows a macOS/Windows switch, a search box, a "Reported by devices" table (a Review button for promotable rows; a greyed row with the platform's blocked reason otherwise) and a "Reviewed" table with a Retire action (reason plus confirm step). Review and Retire controls carry `owner-only`, so consultants see both tables read-only. Observed names, publishers and vendors are endpoint-influenced and are rendered with `textContent` only (`static/js/console-software-identities.js`).

| Route | Notes |
| --- | --- |
| `GET /admin/software-catalogue/candidates?platform=macos\|windows&query=&limit=` | `platform` is required; missing or unknown is 400 here, before the platform is called. `query` and `limit` (digits only) pass through. |
| `GET /admin/software-catalogue/aliases` | Reviewed identities, live and retired. |
| `POST /admin/software-catalogue/reviews` | Owner-only, in `_DESTRUCTIVE_RULES` (audit-logged). Only `platform`, `identity_kind`, `identity_value_normalized`, `companion_value_normalized`, `canonical_name`, `vendor_name`, `reason` are forwarded; anything else is dropped. `actor` is always the server-resolved staff email (`_mirror_actor_email`), whatever the client sent. The four identity fields name the candidate and are carried from the row, never typed. |
| `POST /admin/software-catalogue/aliases/{alias_id}/retire` | Owner-only, in `_DESTRUCTIVE_RULES`. `alias_id` must be a UUID (400 without calling the platform). Only `reason` is forwarded, plus the server-resolved `actor`. |

Responses: 2xx passes through; a platform 4xx (422 below the evidence bar, 409 duplicate or already retired, 404, 400) keeps its status and only its `{"error"}` message so the operator sees why; any other status (5xx, an unreachable platform) becomes a fixed 502 `{"error"}` and the platform body is never reflected.

### `/admin/impersonation/*`, `/admin/tenants/{id}/impersonation/*`, `/admin/tenants/{id}/support-access`

Support-impersonation session management (PAT-137) — start/end a read-only (optionally write-enabled) session viewing a tenant's data as that tenant. `/start` and `/end` are the GET-navigation exemptions noted above.

### `/admin/shadow-it/*`

### Retired Console surfaces and removal capability (PAT-1965)

The Console no longer renders or navigates Service engagement, billing, renewals,
charges, leads, deployment catalogue, Patch & Deploy, Application Control,
Enforcement Evidence or Runbook. Their backend routes remain compatibility
contracts. Protected Software and Removal Campaigns remain available only when
the tenant overview supplies `removal_capability` as the boolean `true`; absent,
false and malformed values fail closed and route the UI back to Software policy.

**Catalogue review, hosting and discovery pipeline (retired, PAT-2249).** The
catalogue was quarantined from the Console under PAT-1481; PAT-2249 removed its
backend routes as well, so each now returns `404` and never reaches
example-api-host:

- The local Software Catalogue: `GET /admin/catalogue`,
  `PUT /admin/catalogue/{label}/mirrored`, `POST /admin/catalogue/apps`,
  `DELETE /admin/catalogue/apps/{label}` and `POST /admin/catalogue/refresh`,
  with the embedded `CATALOGUE_APPS` seed and its reconcile.
- PAT-960 hosting operations and vendor outreach:
  `GET|PATCH /admin/catalogue/hosting-reviews/{label}`,
  `GET /admin/catalogue/hosting-reviews`,
  `POST /admin/catalogue/hosting-reviews/{label}/{draft-email,approve-email,send-email}`,
  `POST /admin/catalogue/hosting-reviews/draft-all` and
  `POST /admin/catalogue/hosting-replies/sync`.
- The public `GET /public/supported-apps.json` feed. The website stopped
  consuming it when its supported-apps page was retired (it now redirects to
  `/`). PAT-2299 removed its nginx exact-match block, so once
  `deploy/nginx-dashboard.conf` is refreshed on the box the path falls into the
  `/public/` redirect to scan.patched.im, like every other old `/public/` URL.
- The platform catalogue proxies (PAT-852, PAT-1315, PAT-1547):
  `GET /admin/catalogue/{products,candidates,target-operations}` and
  `POST /admin/catalogue/{add,review,review/bulk,dismiss,revoke}`.
- The dead PAT-660 per-tenant proxy `GET|POST /admin/tenants/{id}/catalogue`
  and `DELETE /admin/tenants/{id}/catalogue/{package_id}`, whose platform
  route and `tenant_catalogue` table PAT-1561 had already removed.
- The PAT-1548 `GET /admin/tenants/{id}/execution-policies` proxy and the
  Software policy "Execution policies" view that read it.

Their quarantine, audit and confirm rules went with them. `init_db()` no longer
creates `catalogue_apps` or the `catalogue_hosting_*` tables; a box's leftover
tables and rows are left alone, unread. The retired `#catalogue` hash still
lands on Home.

The tenant Software Catalogue consumes installed identity from
`GET /admin/tenants/{tenant_id}/allowlist/scan`. Each app must carry the
platform-derived `app_identity` and its matching `team_id`, `bundle_id`, or
name evidence. Policy lookup follows `team_id > bundle_id > name`; a legacy or
inconsistent response is shown as `Identity unresolved` and cannot stage a
policy mutation. Dashboard `POST /allowlist` bodies are limited to 8192 bytes
and `PUT /allowlist/{entry_id}` bodies to 4096 bytes, matching the upstream
route limits. Both accept exactly one JSON object and reject trailing data,
overflow, and ambiguous case-variant or duplicate `enforcement` fields before
forwarding. Recognisable `marked_for_uninstall` requests retain the central
legacy-execution 410 response and one terminal privileged audit row.

Shadow IT is tenant-scoped and combines three thin proxy reads in the Evidence
workspace:

- `GET /admin/shadow-it/findings/{tenant_id}` returns current risk-catalogue matches plus every recorded allowed exception. Matches retain hostname, immutable device ID, application identifier and first/last observation.
- `GET /admin/tenants/{tenant_id}/app-policy-drift` supplies authoritative `unapproved_present` policy drift. The Console labels this separately from a risk-catalogue match and merges duplicate application/machine evidence client-side.
- `GET /admin/tenants/{tenant_id}/app-policies` supplies the configured policy count so an empty drift response is not presented as a clean approved-software result when no policy exists.
- `PUT /admin/shadow-it/{tenant_id}/{label}` records or revokes one catalogue exception. The request carries `policy`, `reason` and the signed-in email as a claimed actor; the platform establishes the authoritative actor and writes the append-only audit. The Console states explicitly that this is reporting policy, not proof of block, removal or endpoint delivery.

**Retired (PAT-852):** the PAT-627 "Suggested" tab and its local-SQLite `catalogue_suggestions` table/endpoints (`/admin/catalogue/suggestions[/sync|/{id}/dismiss|/{id}/promote]`) are gone — superseded by the PAT-850 review model, itself retired in PAT-2249.

**Retired (PAT-847):** the dead pre-PAT-850 `/admin/mirror/{candidates,approved,approvals}` proxies (PAT-794, backed by patched.im's separate `mirror_eula_approvals` table) — the console had stopped calling them at PAT-852 and they served no further purpose, so they're gone (404) along with their `_DESTRUCTIVE_RULES` entries.

**Also retired (PAT-847):** this dashboard's own local `catalogue_mirror_approvals` SQLite table (PAT-500/794 — an operator-toggled "EULA approved for mirroring" flag on the Apps tab, unrelated to the platform-side review model) — `init_db()` no longer creates it, `PUT /admin/catalogue/{label}/mirror-approval` is gone (404), the Apps-tab checkbox that wrote to it is removed, and `GET /admin/catalogue` (the Apps-tab list) no longer returns a `mirror_eula_approved` field. It fed nothing besides that checkbox — mirror status had been pull-derived from bucket manifests + platform review state since PAT-852. PAT-2249 later removed that derivation, the `catalogue_apps` table code and the `PUT /admin/catalogue/{label}/mirrored` route along with the rest of the catalogue.

### `/admin/billing/*`, `/admin/tenants/{id}/contracts*`, `/admin/tenants/{id}/time-ledger*`, `/admin/conversion-events`

Retained compatibility routes only, with no active Console navigation under PAT-1965: rate config, billing summary, renewals, charges and Calendly-lead conversion. PAT-1101: `contracts` is the source of truth for what a *signed* tenant is billed. `monthly_at_signature` and `advisory_hours_at_signature` are frozen at contract creation, and `api_billing_summary` reads them instead of the live band lookup once a tenant has an active contract. `GET /admin/billing/renewals` retains its 60-day/overdue contract response. `POST /admin/tenants/{id}/contracts` is owner-only by default; one active contract per tenant, superseded explicitly via `?supersede=true`.

### `/admin/automations/*`, `/admin/health/proxy`, `/admin/metrics/proxy`

Scheduled-job run history plus service health and metrics proxies for the
Infrastructure/Automations screens. The four legacy execution job names are
not triggerable and have no expected interval: they render as quarantined or
retired historical evidence rather than 24-hour scheduled automation.

### `GET /admin/logs` — owner-only

Unified, interrogable feed over `admin_audit_log`, `impersonation_audit_log`,
`report_send_audit_log`, the four outbound-alert
idempotency ledgers (merged into one logical `alert_sent` source), remote
`/admin/automations` run history, `conversion_events`, and
`device_log_requests`. Query params: `source`/`outcome` (repeatable and/or
comma-separated), `q` (free text), `since`/`until` (ISO8601), `limit`
(default 200, max 1000), `offset`. Owner-only via `_OWNER_ONLY_GET` — 403s for
`consultant` even though consultants get every other `GET` by default;
impersonation session records make this feed as sensitive as a destructive
write. Degrades gracefully if the automations API is unreachable —
`sources.automation_run.available` is `false` with an `.error` string rather
than a 500.

### CVE scans (`/api/scan/*`) — unchanged design since PAT-572

- `GET /api/metrics` — aggregate stats for Home (scans, CVEs, devices, 10 most recent).
- `POST /api/scan/upload` — kicks off a scan from an uploaded Intune "All devices" CSV (required) + optional detected-apps JSON. No tenant credentials — matched against a local NVD SQLite dataset. Inserts a `scans` row (`status='running'`), runs in a background thread, returns `{"job_id": ...}` immediately.
- `GET /api/scan/{job_id}/status` — polls in-memory job state (`JOBS` dict). 404 if the process restarted since the job was queued.
- `GET /api/scan/{job_id}/download` — serves the generated `.docx`. **`/download` — exempt from the `api_bearer_auth` middleware** (browser `<a href>` navigation can't carry an `Authorization` header), but PAT-1217 added an explicit in-app `patched_session` cookie check to the handler itself, so it no longer depends on CF Access alone. No Bearer accepted here — see `AGENTS.md`.

### `/api/tenant/{id}/*`

Cert inventory (`/certs`, classified 7 types, live expiry), cert-digest config, agent config (GET/PATCH), device signal/request-logs/log-bundle download.

### `/api/credentials`, `/api/leads`, `/api/leads/{id}/convert`

Stored-credential inventory; Calendly-sourced leads list + manual convert-to-customer action. (Note: this `leads` surface is unrelated to the old `leads/contracts/recruiters` CRM tables removed it's a newer, narrower Calendly-integration feature. Don't conflate the two when reading history.)

### `/api/admin/fleet-summary`, `/api/admin/fleet-tenants`, `/api/admin/service-health`

Estate-wide aggregate stats and per-tenant health rows backing the Home screen's top-line numbers (PAT-673/674/675/678/708). The route paths and internal names still say `fleet` — that's an established internal naming pattern in code (routes, JS variable names, DB-adjacent identifiers) that hasn't been renamed; **user-facing copy and prose docs should say "estate"**, per the Patched copy convention, even though these route names are `fleet-*`.

### `/api/ops/data`, `/api/ops/firewall-apply`

Backing data for the Infrastructure screen; manual trigger for the Hetzner firewall-rule refresh.

### `/api/home/triage`, `/api/config/freshness`, `/api/news`

Home screen's needs-attention rollup; shared device-freshness threshold config (keeps the on-screen view and the stale-endpoint email digest from drifting apart, PAT-697); news/changelog feed.

### `GET /reports/download/{token}`

Single-use, token-only-authenticated external download link (PAT-370/PAT-1405) — distinct from the `/admin/tenants/{id}/report-records/{id}/download` proxy. **No CF Access, no session/Bearer** — the UUID token in the path is the only credential, by design: external recipients (customers, brokers, auditors) who don't have a Patched.im CF Access account still need to reach this. The Cloudflare Access policy must have an explicit bypass rule for this path prefix, or external recipients will hit the CF Access challenge instead of the report. Existing dashboard-local generated-report tokens are resolved first. If absent, the route redeems a platform-owned authored-assessment token and accepts only a safe PDF/DOCX attachment contract. Both paths are single-use; a replay 410s. Authored bytes remain on `example-api-host`, are hash-verified there before token consumption and are relayed byte-identically with `no-store`, `nosniff` and `no-referrer` headers.

### `/api/smoke/health`

Smoke-test hook — returns the scheduler heartbeat plus outbound-email state:
`email_dry_run` (raw flag, kept for compatibility) and `email_delivery`
(`live` / `dry_run` / `unconfigured`). The `email_delivery` smoke module
asserts `live`, since "not suppressed" and "actually deliverable" are
different claims (PAT-1346).

### Public prospect funnel — moved out (PAT-866)

The anonymous `/public/*` CVE-scan + Intune-upload funnel (`public_router.py`) was removed from this repo under PAT-866. It now lives at `scan.patched.im`, a standalone service in the `portal` repo (`scan/`) with its own Turnstile/OTP/rate-limit stack — see that repo's `AGENTS.md` and `deploy/RUNBOOK-scan.md`. This is unrelated to `GET /public/supported-apps.json` above, which stays.

---

## What's NOT here

- **No `/openapi.json` / `/docs` (Swagger UI).** Disabled in production. Enable locally with `docs_url="/docs", openapi_url="/openapi.json"` if needed for development.
- **No write API for CVE scans.** Scans are immutable once written.
- **No exhaustive per-route reference below the group level above.** With 150+ routes, `main.py` itself (route decorators + docstrings) is the accurate source for request/response shape of any individual endpoint — treat the groups above as a map, not the full spec.

---

## Gotchas

- **`/api/scan/{id}/status` returns 404 after a process restart**, even for jobs that completed successfully. Job state lives in an in-memory dict (`JOBS`), not the DB. Query `GET /api/metrics` (last 10) for a historical scan, or extend `scan_status` to fall back to the DB.
- **`POST /api/scan/upload` is fire-and-forget.** The response returns as soon as the row is inserted; the scan runs in a background thread. If the process dies mid-scan, the row stays `status='running'` forever — there's no janitor.
- **A route returning `{"error":"Unauthorized"}` doesn't tell you which layer failed** without checking headers — see the auth model table above.
- **`console.html` build-ID redirect** — if you're testing against a stale bookmarked `/console/{old-rev}` URL, you'll get bounced to the current build. That's expected, not a bug.
