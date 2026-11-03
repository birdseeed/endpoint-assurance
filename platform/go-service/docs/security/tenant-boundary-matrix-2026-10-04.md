# Tenant-boundary and role matrix, isolated local deployment, PAT-2367

Date: 4 October 2026. This is internal evidence, not an external penetration test and not an acceptance of readiness.
Severities are the implementer's proposal for the parent to adjudicate. Nothing was fixed.

## Pinned commits

| Service | Commit |
| --- | --- |
| Platform (this worktree, branch andy/pat-2367-isolated-matrix) | `080a121431dcf9cfb9824e3b2e7d962ef425e3f8` |
| Portal (pinned copy of origin/main; the live checkout was two commits behind at `822ffb6`) | `6e9acf7378784241d3f42810b8d5dca82467d119` |
| Staff console (pinned copy of origin/main) | `381b475e21f55b8d49f5156480d1871bc1619c4f` |

Raw results: `matrix-results-20261004T211941.json`, kept with the run evidence in the `workspace-governance` repository under
`.claude/linear-runs/evidence/claude-queue-20261004/PAT-2367-matrix-results.json` (not in this repository).
sha256 `8575273e3468932fbc19cc3e271f41084ae5a815a3794990f1380f13e4c217f4`. It comes from one clean `./ib all` run.
The findings are tracked as PAT-2407 (viewer enrolment, medium) and PAT-2408 (four low-severity items).

## What was built

Harness in `go-service/scripts/isolated-boundary/` (commands in its README). One command brings up, one tears down.

- A local identity issuer: an HTTPS JWKS on 127.0.0.1 with a generated RSA key, plus a minter for email tokens and the
  email-less service-token shape. The platform and the portal trust only this issuer and audience, through
  `PORTAL_ACCESS_TEAM_DOMAIN` and `PORTAL_ACCESS_AUD`.
- The real platform binary on its own Postgres 16, migrated from zero (447 migrations), connected as a non-superuser, with
  public and internal listeners on loopback ports and a generated admin token. The real extractor runs beside it, so
  inventory goes through the real ingestion path. The envelope key is enabled, as in production.
- The real portal and staff console from pinned copies. The console reaches the internal API through a recording proxy.
  Staff identities are supplied as the console expects behind Access: the `CF-Access-Authenticated-User-Email` header on
  `GET /console/{rev}`, from which the console mints its own session cookie. Owner and consultant roles come from
  `DASHBOARD_OPERATORS`.
- Two tenants, A and B, each with an admin, a viewer, a disabled user and a domain-fallback user, three devices with
  canary hostnames, applications, extensions and formula-leading and markup values, and one object of each kind. The
  service identity is bound to tenant A. Tenants, users and domains were created through the platform's admin API and data
  through signed ingestion and the portal API. No SQL was used for seeding. SQL (psql) was used only to apply migrations.
- The product has two portal roles, admin and viewer. There is no separate owner role.

Deviations from production, all deliberate: the platform build has a one-file overlay trusting the harness CA (no product
file changed); Postgres listens on loopback TCP because the scratch path exceeds the unix socket length limit; rate limits
are raised; feedback delivery is disabled; outbound traffic to anything non-loopback is sent to a dead proxy; the console's
background threads ran with no tokens configured.

## Matrix summary

| Boundary | Checks | Pass | Fail | Observation |
| --- | ---: | ---: | ---: | ---: |
| A credentials and JWT denial | 3620 | 3620 | 0 | 0 |
| B cross-tenant reads and writes | 4069 | 4069 | 0 | 0 |
| C roles and actor attribution | 133 | 120 | 13 | 0 |
| D reports and exports | 576 | 576 | 0 | 0 |
| E browser, Origin and CSRF, stored markup | 340 | 340 | 0 | 0 |
| F staff console | 1274 | 1267 | 5 | 2 |
| G internal router isolation | 1712 | 1711 | 1 | 0 |
| Total | 11724 | 11703 | 19 | 2 |

The 19 failed rows collapse to five distinct findings below.

What each boundary covered:

- A: 19 token variants on every platform portal route and every portal route (no token, malformed, expired, not yet valid,
  wrong issuer, wrong audience, rogue key with the right kid, unknown kid, alg none, HS256 with the public key as secret,
  tampered payload, no email, empty email, wrong service common name, no membership, disabled membership in each tenant),
  token in the wrong place, forged identity headers, cookie handling, email case and whitespace variants, and the service
  identity on every non-GET route (24 platform, all portal POST routes). All refused as expected. Six further rows check that a
  token carrying both an email and the service common name is judged as the person (role from the membership, never the
  read-only service identity), on the platform and the portal, and that an unmapped email with that claim is refused 403.
- B: every platform portal route and every portal route, as the admin, viewer, domain-fallback user and (for A) service
  identity of each tenant against the other tenant's three device ids, certificate, declaration, report, enrolment key,
  alert id and device-list entry id, with tenant-naming query parameters, headers and body fields. Foreign object ids answer
  403 or 404 with no foreign marker. Two snapshot comparisons (14 portal reads each) show no object of the victim tenant changed. Ingestion
  credentials mixed across tenants, a stale timestamp, a replayed nonce and a payload naming the other tenant were refused or
  stored under the authenticating tenant only. Positive controls show each tenant's own data and ids resolve, so the foreign
  refusals are meaningful.
- C: actor attribution held on eight writes (retirement, device list, enrolment key create and revoke, declaration,
  notifications, approvals, and retirement through the portal) with spoofed headers and body fields; the recorded actor is
  the token email. Role results are in the findings.
- D: every report type generated for both tenants (28 generation rows, each expecting 201, all met) and downloaded by every principal through platform and portal (PDF text
  decoded; both tenants' own markers were found, so absence of foreign markers is meaningful), every portal CSV, PDF and
  download route (147 export requests), and formula neutralisation: 79 seeded formula-leading cells for A and 35 for B
  appeared in CSV exports and none begins with `=`, `+`, `-`, `@`, tab or carriage return.
- E: Origin and CSRF on every portal POST route (missing, wrong, other-session and duplicated token; cross-site, null, other-port
  and production-style Origin; no Origin and cross-site Referer; oversized body; GET refused; positive control), including
  multipart routes. In Chromium: 45 pages rendered with seeded script and image-handler payloads (inert text, no dialog, no
  injected element, 10 pages showing the payload as text), a real cross-origin form post and fetch with the session cookie
  (refused 403, no state change), and a same-origin positive control. Screenshots are in the scratch `shots/` directory.
- F: all 226 console method-routes without identity, with the identity header alone, with a forged session MAC and with wrong
  bearers; a tampered session; consultant refused on every non-allowlisted write and the two owner-only reads, including all
  destructive-rule routes; confirmation-header behaviour; tenant id pass-through; inbound headers not relayed; admin bearer on
  every upstream call; staff attribution in the console's audit log.
- G: all 244 internal method-routes answer 404 on the public listener (except the health and token-redemption routes that are
  mounted on both by design) and 401 without the exact bearer on the internal listener, for six bad credential shapes.

## Findings

All were reproduced in the single final run. Reproduce with `./ib up && ./ib seed && ./ib run --only <boundary>` at the
commits above.

1. Viewer role can mint an agent enrolment token that enrols a device (proposed severity: medium). Routes:
   `POST /v1/portal/enrolment` (portal `POST /install/enrolment`). Check ids: `C-PLAT-A.viewer-POST-/v1/portal/enrolment`,
   `C-PLAT-A.domain-POST-/v1/portal/enrolment`, `C-IMPACT-viewer-enrolment-token-redeems`. Impact: a read-only portal user
   (and a domain-fallback user with no membership row) receives a single-use token. Redeeming it at `POST /v1/enrol` returned
   device credentials, and inventory sent with them appeared in tenant A's device list. Confined to the caller's own tenant.
   The newer `enrolment-keys` routes are admin-only, and `contracts/portal-api.md` states that viewers are read-only, but
   its enrolment-token section names no role rule, so the intended behaviour needs a ruling. Commit `080a121` (platform),
   `6e9acf7` (portal passes it through).
   Update 2026-10-04: fixed by PAT-2407. The route is now admin only (`403 admin_role_required` for any other role).
2. Viewer role can generate reports and change report schedules (proposed: low). Routes: `POST /v1/portal/reports`,
   `PUT /v1/portal/reports/schedule`, `PUT /v1/portal/reports/schedules/{reportType}` (portal `POST /reports/generate`,
   `POST /reports/schedule`). Check ids: `C-IMPACT-viewer-report-generate`, `C-IMPACT-viewer-schedule-change`. Impact, as measured:
   a viewer adds a report of the tenant's own data to the tenant's list, and changes the tenant's schedule (hour 3 became 9;
   the harness restored it). Own tenant only. These predate the PAT-2007 role rule.
   Update 2026-10-05: ruled and fixed by PAT-2408 and PAT-2406. The ruling: "Viewers can generate reports but only admins
   change schedules; the Local Admin report is admin-only." Both schedule PUT routes are now admin only
   (`403 admin_role_required`, nothing written; reading a schedule stays open to every role), so
   `C-IMPACT-viewer-schedule-change` now expects 403 on both routes and an unchanged schedule. Generating stays open to a
   viewer, so `C-IMPACT-viewer-report-generate` now expects 201 and one record for an ordinary report, and 403 with no
   record for `local-admin`; `C-PLAT-<viewer>-POST-/v1/portal/reports` expects 201, and the two "changed nothing" rows
   ignore the report history, which a viewer may add to. The Local Admin report prints the roster's account names, so
   new rows `C-ROLE-*` and `C-PLAT-<viewer>-report-generate-local-admin` check that a viewer, a domain-fallback user and
   the service identity cannot generate it, download a stored copy in either format, see it in the history or be
   offered it in the catalogue, and the `D-PLAT-download-*` and `D-PORTAL-download-*` rows expect 403 for that type for
   every identity that is not an admin. Scheduled reports are emailed to nobody (delivery is deferred), so a schedule
   cannot hand the report to a viewer.
3. Internal listener accepts the admin token without the `Bearer ` prefix (proposed: low). Route: every internal route. Check
   ids: `G-INTERNAL-raw-token-no-scheme`, `G-INTERNAL-wrong-bare-token`. The same secret is still required: a wrong bare value
   is refused with 401 (`G-INTERNAL-wrong-bare-token` passes). Only the scheme prefix is not enforced.
   Update 2026-10-05: fixed by PAT-2408. The `Bearer` scheme is now required, so the bare admin token is refused with 401
   and `G-INTERNAL-raw-token-no-scheme` is expected to pass.
4. Staff console serves API documentation without an identity (proposed: low). Routes: `GET /docs`, `/redoc`,
   `/openapi.json`. Check ids: `F-NOID-open-GET-/docs`, `/redoc`, `/openapi.json`. Confirmed 200. The OpenAPI document is
   125 kB and lists 181 paths with methods, parameter names and 62 operation descriptions plus three request schemas. It
   contains no tenant data (no canary, no tenant id). Whether Access also fronts these paths cannot be shown locally.
5. Console forwards two odd tenant-id forms to the platform as a different path than the route named (proposed: low). Check
   ids: `F-PASS-hostile-tenant-id-enc_dotdot`, `F-PASS-hostile-tenant-id-enc_question`. Recorded side by side, from the
   recording proxy, as an owner session:

   | Raw request line received by the console | Path forwarded to the internal API | Upstream answer |
   | --- | --- | --- |
   | `GET /admin/tenants/%2e%2e/agent-health` | `/admin/agent-health` (the dot segment was resolved by the console's HTTP client) | 404 |
   | `GET /admin/tenants/a%3Fx%3D1/agent-health` | `/admin/tenants/a?x=1/agent-health` (the platform reads path `/admin/tenants/a`, query `x=1/agent-health`) | 405 |
   | `GET /admin/tenants/a%2fb/agent-health` | not forwarded | 404 from the console |

   Both forwarded requests carried the admin bearer. Neither reached a different route that exists: the platform has no GET
   `/admin/agent-health`, and its `/admin/tenants/{id}` route is DELETE only. Comparing every console route of the form
   `/admin/tenants/{id}/<rest>` with the platform's routes, only three have an upstream `/admin/<rest>` counterpart (portal
   users list, create and delete), and the console builds those upstream calls from fixed templates with the tenant in a query
   or body, so the dot segment does not apply. The tenant segment forwarded is always the one the caller named. This is
   recorded as inconsistent path handling with no reachable effect today; a future platform route at `/admin/<rest>` would
   change that.

### Observations, not findings

- The console mints an owner or consultant session from `CF-Access-Authenticated-User-Email` for any caller that can reach it
  (`F-EDGE-header-mints-session-for-anyone`). This is a design dependency on the console being reachable only through
  Cloudflare Access. It is listed under unproven locally.
- The platform sees only the shared admin bearer from the console, never the staff identity. Staff attribution exists only in
  the console's own audit log (checked: owner and consultant rows carry the session email; spoofed headers and body fields
  were ignored; the shared console API key records the actor `bearer-token` with role owner).
- One destructive rule (`installomator_sync` trigger) names a route that is not mounted. It is inert.
- Console routes `impersonation-log` and `support-access` are answered inside the console from its own database and make no
  upstream call, so there is nothing to record for them.
- The platform's `DASHBOARD_OPERATORS` source comment says the variable is unset on prod-01, which would make every staff
  user an owner. This was read from source, not tested, and production state is not visible here.

### Rows that were harness mistakes during development (fixed in the harness, not product behaviour)

Not-found pages echoing the id the attacker supplied, and a page echoing a supplied `tenant_id` query value (reflection, not
leakage; supplied values are now removed before scanning); an own-tenant schedule write counted as foreign; a volatile
`until` timestamp in snapshots; multipart routes probed with urlencoded bodies and too many form fields; PDF text written in
UTF-16 (positive control failed until decoded); a fixed replay nonce reused across runs; the device-scoped removal-task
routes answered 401 to tenant credentials because they need device credentials, which were not minted, so those two rows
prove nothing about device scoping.

## Routes enumerated versus covered

| Inventory | Enumerated | Covered |
| --- | ---: | ---: |
| Platform portal router method-routes | 87 | 87 |
| Platform internal router method-routes | 244 | 244 |
| Platform public router method-routes (all) | 112 | portal 87, plus ingestion routes listed below |
| Portal method-routes | 92 | 91 (`/healthz` is checked separately; `/static` is a mount) |
| Staff console method-routes | 226 | 226 for unauthenticated and credential checks; 12 consultant-allowlisted writes not executed |

Not exercised, and why: the 12 console writes a consultant may perform by design (they would write to the platform); owner
destructive writes such as tenant purge (only the confirmation-required and wrong-confirmation answers were checked, and both
tenants were confirmed intact); public routes needing device-scoped credentials or external senders
(`/v1/agent-config`, `/v1/posture`, removal-task routes, `/v1/agent-logs`, `/v1/events`, `/v1/provenance`,
`/v1/agent/artifact*`, Jamf and Linear webhooks, `/v1/trial/provision`, `/v1/backup-health`), of which only inventory,
agent-config, posture and removal-task routes got cross-tenant credential probes; and the 12 console allow-listed writes
above. Feedback routes are disabled in this deployment.

## Limits of the harness itself

Recorded from the independent review of the harness (NVIDIA Nemotron Ultra, 4 October 2026), so the results are not read as
stronger than they are:

- The cross-origin form and fetch checks in boundary E run from another port on 127.0.0.1. Browsers treat that as the same
  site, so those rows exercise the portal's Origin and CSRF-token checks and say nothing about SameSite cookie behaviour.
- The platform JSON export check runs tenant A's principals against tenant B's data only. The portal export checks and
  boundary B run in both directions.
- The HS256 key-confusion variant uses the PEM text of the public key as the secret. A DER-bytes variant was not tried.
- Five destructive admin routes were not executed against seeded evidence; they were checked for refusal only.
- No read route exposes the portal access log, so the audit name recorded for the service identity was not verified.

## Unproven locally

- Cloudflare Access policies, bypass destinations, and that the portal, console and API are reachable only through Access.
- Real identity-provider sessions, Access token lifetimes and key rotation.
- Production configuration values (for example `DASHBOARD_OPERATORS`, audience tags, service-token allowlist).
- nginx, ufw, Hetzner firewalls, Tailscale placement and the console's network exposure, including that the console trusts the
  Access email header.
- Timers, scheduled reports delivery, email and webhook destinations, notification sweepers and other background jobs in
  production, and revocation races under load.
- CVE and vulnerability data (feed sync was not run), device-scoped agent credentials and the per-device routes.
- Real controlled-identity membership denial on the deployed boxes (PAT-2379 operating acceptance).
- Dependency status of the portal, console and operating systems.
- Support and impersonation: the console's impersonation routes were unauthenticated-checked only.
