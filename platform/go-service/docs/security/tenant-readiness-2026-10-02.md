# Tenant isolation readiness evidence, PAT-2367

## Scope and provenance

**Readiness is not established.** This record reconciles retained source and
synthetic test evidence. It is not a new security scan, a deployed staging
acceptance, or an external penetration test.

The original 2 October source audit used platform commit
`5fc47a4ffeada452aab074257cc54fb27aee2e10`. Its preserved donor worktree held
334 staged additions: a mounted-router sweep, an audit record, an opt-in
identity-disable reproducer and an isolated PostgreSQL runner. This reconciliation
recovers only the 68-line mounted-router sweep and updates this record against
main `b9e92be2` on 4 October. The donor is retained untouched. The old copied
integration harness and runner are not carried forward.

The donor record reported 77 portal and 228 internal method/routes, 19 portal
write routes, and passing synthetic auth, tenant/object, role, report, schedule,
enrolment and replay checks. It also reported a Go dependency check with
`govulncheck@v1.8.0`, Go 1.27.1 and the vulnerability database dated 1 October:
no reachable or imported-package vulnerabilities, eleven in required modules
without reachable calls. These are historical reported results, not checks
repeated or independently accepted in this reconciliation. They establish
neither portal/dashboard/OS dependency status nor current deployment behaviour.

## Current mounted-router checks

From `go-service`:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools go test -count=1 -v ./cmd/patched-api -run 'Test(TenantReadinessEveryRouteAuthBoundary|PortalEveryWriteRouteRefusesServiceIdentity)$'
DEVELOPER_DIR=/Library/Developer/CommandLineTools go build ./...
```

The retained `cmd/patched-api/tenant_readiness_test.go` walks the actual shipping
constructors. On the pinned main above, 81 portal and 229 internal method/routes
returned 401 for missing and invalid credentials and 503 for unconfigured auth.
Health/metrics and non-portal public routes are explicitly excluded. All newly
mounted in-scope routes inherit the sweep. Databases are nil: unexpected handler
entry cannot masquerade as successful credential rejection. No authorised
request reaches a handler or database.

The existing `TestPortalEveryWriteRouteRefusesServiceIdentity` independently
walked 22 portal write routes and checked both 403 and the central read-only
refusal body using a synthetic service JWT. This proves that service identity
writes are rejected; it does not prove human JWT row isolation.

A temporary negative control added an unguarded GET route under `/v1/portal`
to the test's real public router. The unchanged sweep failed twice on HTTP 200
where 401 was required. The control was removed and the original donor test
restored byte for byte. This demonstrates detection of a missing route auth
boundary; it is not a production vulnerability or a feature red/green claim.
Local verbose logs contain the exact enumerated method/path inventory and
belong with the independent review evidence. This reconciliation runs no DB
integration suite and claims no fresh database-backed acceptance.

## Historical F1 and current main

The original audit reproduced disabled explicit portal users falling back to a
claimed email domain, retaining same-tenant reads or becoming another tenant's
viewer. Its provisional severity was High. It concerned `DELETE
/admin/portal-users/{email}` followed by `GET /v1/portal/me` and
`GET /v1/portal/devices` with the same synthetic valid JWT at the audited base.
The recorded impact was continued reads after disable, not admin-role escalation.

That source finding is superseded by PAT-2379, commit `f00ba59`, merged in PR
#719 (`fe4cce4`). Current `internal/portalauth/middleware.go` treats an explicit
disabled or revoked membership as terminal denial before domain fallback.
Current `integration/portal_disable_adversarial_test.go` retains the same-tenant
and cross-tenant denial reproducer in ordinary integration coverage, alongside
the expanded membership-denial coverage in the current harness. These current
files are preserved unchanged. Do not restore the donor's opt-in tag, old copied
router, or stale statement that the bypass remains present on main.

The [architecture current-state record](../architecture.md) reports successful
owned synthetic denial/data-isolation and DB-error checks, independent NVIDIA
review, and installation of the PAT-2379 source. It explicitly retains the
missing deployed denial proof using a real controlled identity. This document
relies on that dated repository record for those results, not a fresh installed
readback. PAT-2379 operating acceptance remains a gate for PAT-2367.

## Coverage limits and remaining acceptance

| Boundary | Retained evidence | Still required |
| --- | --- | --- |
| JWT and credential denial | Real mounted-router sweep; local RSA/JWKS service guard | Real authorised JWT, issuer/audience, Cloudflare policy and edge placement |
| Tenant/object reads and writes | Historical synthetic isolation and current PAT-2379 denial tests | Two disposable tenants across actual platform, portal and staff routes |
| Roles | Historical viewer/admin checks; current service write guard | Owner/admin/viewer/staff browser matrix and actor attribution |
| Reports, exports and background jobs | Historical report/schedule/enrolment checks | Real downloads, export scope, timers, destinations and revocation races |
| Inputs, secrets and dependencies | Historical scoped checks | Browser CSRF/XSS, resource limits, all output/log sinks and current dependencies |
| Support/impersonation | No support-session route identified in the historical platform inventory | Actual cross-service routes, consent, expiry, revoke, scope and logs |

Required access is an explicitly authorised isolated deployment of platform,
portal and staff console at pinned commits, two disposable tenants and synthetic
owner/admin/viewer/staff principals. Recommend completing that environment and
matrix before onboarding: local constructor checks cannot establish installed
proxy policy, browser sessions or cross-service identity. No customer production
attack, manual data write, credential change or public activation is authorised
by this reconciliation.

The acceptance matrix, installed runtime receipts, real controlled-identity
membership denial, browser screenshots, actionable-finding dedupe and links to
PAT-2081/PAT-2292, and a second model/session's evidence review remain required.
Unresolved critical/high auth or tenant-boundary findings prevent onboarding.
Do not mark PAT-2367 Done from these local results.

External pentest scope should agree exact hosts, pinned commits and test accounts
for portal, staff console, ingestion/enrolment and internal API. Include JWT
and service identities, staff policy and attribution, tenant/object substitution
across UI/API/report/export/download, support sessions, jobs and destinations,
enrolment replay/revocation, browser sessions/CSRF/XSS, input limits, secrets and
dependencies. Exclude customer data, destructive payloads, availability attacks,
credential rotation, payments and unapproved callback destinations. The internal
pass does not replace that assessment.
