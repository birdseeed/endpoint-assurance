# Portal read API contract (PAT-693)

Customer-scoped, read-only endpoints on the **public** listener of
`api.patched.im`, consumed by the `app.patched.im` portal. This document is
the contract the portal app builds against — response shapes here are exact.

Spec: PAT-330 (locked). Parent: PAT-331. Network posture: PAT-410.

## Auth model

Every `/v1/portal/*` request carries a Cloudflare Access identity JWT:

```
Cf-Access-Jwt-Assertion: <RS256 JWT>
```

The header is set by CF Access when it fronts the route directly, and
forwarded verbatim by the portal server otherwise. The platform validates:

| Check | Source |
|---|---|
| Signature (RS256) | JWKS fetched and cached (1 h TTL) from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` |
| `iss` | `https://<PORTAL_ACCESS_TEAM_DOMAIN>` (bare team name accepted; `.cloudflareaccess.com` appended) |
| `aud` | `PORTAL_ACCESS_AUD` env |
| `exp`, `nbf` | zero leeway; `exp` required |
| `email` claim | required; lowercased |

The verified email — and **only** that — resolves to a tenant. No
client-supplied tenant identifier exists anywhere on this surface. Resolution
order (PAT-127):

1. **`portal_users`** (migration 0059) — an explicit email -> tenant row.
   This is the manual-override path and always wins: it's how a cross-domain
   edge case (e.g. a consultant using a shared admin email that doesn't
   belong to any one tenant's domain) is handled — add one override row,
   independent of the email's domain. An existing row is authoritative even
   when disabled or attached to a revoked tenant: either state denies access
   with `403`, with no domain fallback, including to the same tenant.
2. **`tenant_email_domains`** (migration 0075) — falls back to the tenant
   that has registered the email's domain **only if no explicit user row
   exists**, so an SSO login (Microsoft or
   Google via CF Access — PAT-127) from a domain a tenant has claimed
   resolves without an operator adding every individual user to
   `portal_users` by hand first. A domain actively claimed by more than one
   tenant never resolves (prevented at write time by a partial unique index
   on `tenant_email_domains`; `portalauth.DBLookup` also refuses ambiguous
   matches defensively).

Disabled mappings (`disabled_at` set on either table) and revoked tenants do
not resolve. Database lookup failures fail closed with `500`; they never
trigger domain fallback. Email lookup trims surrounding whitespace and
lowercases before matching. Both tables are admin CRUD on the **internal** listener only
(`/admin/portal-users`, `/admin/tenant-email-domains`) — never reachable from
`app.patched.im`.

### Pre-membership routes (PAT-1883)

Three routes under `/v1/portal/signup` are for a person who may not belong
to any tenant yet: someone creating their first organisation, or accepting an
invitation. They sit in their own route group, a sibling of the rest of
`/v1/portal`, with their own middleware. It applies exactly the same JWT
checks as the table above and the same per-email rate limit (the same limiter,
so one person has one budget across both groups), and then stops: it resolves
no tenant. The handlers act on the verified email alone.

Nothing else is reachable through that group. It mounts the three sign-up
handlers only, and it hands them a different kind of caller (an applicant with
an email and no tenant), which every tenant-scoped handler refuses. A person
who belongs to no tenant still gets `403` from every other `/v1/portal` route.

These requests are audit-logged to `portal_access_log` with a NULL
`tenant_id`. The read-only service identity is refused on all three (`403`).
The whole feature is off unless `SELF_SERVICE_SIGNUP_ENABLED` is set; see
"Self-service organisation sign-up and access" below.

### Read-only service identity (PAT-2257)

The one exception to "the email resolves the tenant" for tenant data. A Cloudflare Access
**service token** JWT carries `common_name` (the token's client id) and no
`email`. It passes exactly the same signature, `iss`, `aud`, `exp` and `nbf`
checks as above, and is then accepted only when:

- it has no `email` claim (a token with one is always a person's), and
- `common_name` equals `PORTAL_SERVICE_TOKEN_COMMON_NAME` exactly
  (constant-time compare).

It maps to a fixed identity, never through `portal_users` or
`tenant_email_domains`: tenant `PORTAL_SERVICE_TOKEN_TENANT_ID` only (tenant
zero in production; refused `403` if that tenant is revoked) and role
`service_readonly`. `portalauth.Middleware` refuses it every method but `GET`
and `HEAD` with `403` ("the service identity is read-only") before any
handler runs, so no write route (current or future) is reachable by it. Reads
behave as a `viewer`: an admin-only read such as `/local-admins` answers
`403 admin_role_required`. Audit rows in `portal_access_log` record it as
`service:<common_name>`, never as a person. Both env vars unset leaves the
feature off (a service token is `401`, as an email-less token always was);
only one set, or a tenant id that is not a UUID, logs an error at startup
and leaves it off.

### Session lifetime (PAT-127)

SSO sessions (Microsoft/Google via CF Access) are scoped to 8 hours; the
existing email one-time-PIN session length (weekly) is unchanged for tenants
not using SSO. This is enforced entirely by **Cloudflare Access policy
configuration** — CF Access supports a distinct `session_duration` per
Access **policy** within one application, so the Access app for
`app.patched.im` carries two policies (one scoped to the Microsoft/Google
login methods at 8h, one scoped to the one-time-PIN method at the existing
weekly duration). There is no application code involved in this split; see
`docs/ANDY-TODO-sso-cf-access-setup.md` for the exact policy configuration.

### Which IdP was used

The Cf-Access-Jwt-Assertion JWT itself does not carry which identity
provider authenticated the user — only Cloudflare's
`/cdn-cgi/access/get-identity` endpoint exposes that (an `idp` object). The
portal's `auth.py` has a best-effort helper for this (PAT-127) used only for
display ("Signed in via Microsoft") — it is never used for any authorization
decision, and a failure to fetch it never blocks a request.

### Status codes (whole surface)

| Status | Meaning |
|---|---|
| `503` | `PORTAL_ACCESS_TEAM_DOMAIN` / `PORTAL_ACCESS_AUD` unset — surface fails **closed** |
| `401` | Missing/invalid/expired/mis-issued JWT, or no email claim |
| `403` | JWT verified but email has no active `portal_users` mapping |
| `404` | Resource missing **or belongs to another tenant** — deliberately indistinguishable (no existence oracle). Also every route of a feature that is switched off (`/feedback`, and the PAT-1883 `/signup` and `/access` routes) |
| `409` | The request is well formed and allowed, and the current state refuses it (already a member, an invitation already pending, an owner's access). The body's `error` says which |
| `410` | PAT-1883: an invitation that has been used, withdrawn or has expired |
| `429` | Per-identity rate limit exceeded (`Retry-After` header set). Config: `PORTAL_RATE_LIMIT_RPM` (default 120), `PORTAL_RATE_LIMIT_BURST` (default 30), keyed by verified email. `POST /v1/portal/enrolment` additionally has its own, much tighter per-**tenant** limit — see PAT-453 below |
| `400` | Malformed JSON body or failed validation (POST /v1/portal/reports, PUT /v1/portal/reports/schedule, POST /v1/portal/enrolment) |

Every authenticated request (including 403/404 denials past JWT verification)
is audit-logged to `portal_access_log` (email, tenant, method, route, status).

Timestamps are RFC 3339 UTC. IDs are UUIDs (as strings).

---

## GET /v1/portal/overview

Tenant-wide posture summary.

```json
{
  "tenant_name": "Acme Ltd",
  "generated_at": "2026-07-02T17:00:00Z",
  "devices_total": 12,
  "devices_reporting_24h": 11,
  "oldest_successful_ingest": "2026-12-15T09:00:00Z",
  "devices_retired": 1,
  "devices_degraded": 0,
  "cis_score_current": 87.5,
  "cis_trend": [
    { "date": "2026-12-03", "score": 84.2 }
  ],
  "findings_open": { "critical": 0, "high": 2, "medium": 5, "low": 3 },
  "patch_status": { "up_to_date": 9, "pending": 3, "failed": 0 }
}
```

- `oldest_successful_ingest` — the least-recently-heard-from device still
  counted in `devices_total`, `null` when the tenant has zero devices. This
  is the "absence requires authority" signal: a stale value means the
  coverage claim is weaker than the raw device count implies. Since PAT-2135
  a device the customer has retired does not set it (`null` when every
  device is retired).
- `devices_retired` (PAT-2135) — devices the customer has retired (see
  "Device retirement and the customer device list"). They are still counted
  in `devices_total` and still listed on the roster; a quiet retired device
  is the customer's decision, not a coverage gap. `devices_reporting_24h` is
  unchanged: it counts every device that reported, retired or not.
- `devices_degraded` — count of devices with an admitted agent-side
  collection fault (from the internal `device_agent_health` table). `0` is
  the common case and is not itself a bad sign.
- `cis_trend` — daily fleet-average CIS score over the last 30 days,
  ascending by `date` (`YYYY-MM-DD`). Days with no evaluations are absent.
  `[]` when no data (never `null`).
- `findings_open` — open (currently failing) compliance findings by severity.
- `patch_status.failed` — always `0` until patch-failure telemetry exists
  (documented degradation).
- `unapproved_present` (PAT-2009) — number of distinct products the tenant
  has marked Unapproved that at least one device currently reports.
  `unapproved_present_devices` is the number of distinct devices carrying at
  least one. Both are `null` when the figure could not be assessed (for
  example the estate is over the inventory load cap), which is not zero.
  Since PAT-2095 these three fields are read from a summary Patched keeps
  up to date on ingest and on every policy change, with the same answer as
  resolving the whole inventory. For the few seconds after a policy change
  while the summary is rebuilt, the figure is computed from the whole
  inventory as before, so it is never stale; only that window is subject to
  the load cap.
- `unapproved_present_items` (PAT-2009) — up to five of those products, most
  widespread first: `type`, `product_key`, `name`, `platform` or `browser`,
  `device_count`, `since` (when it became Unapproved and present, see
  `/software/drift`). `[]` when there are none, never `null`.

- `unapproved_alerts_open`, `unapproved_alerts_acknowledged` (PAT-2097) —
  tracked unapproved software alerts by status, one per (episode, device),
  counted on the tenant's own existing devices only (a deleted device's
  alerts go with it and are never resolved as not observed). `null` when the
  count could not be read. These are **not** the same measure as
  `unapproved_present`: that counts distinct products (by `product_key`)
  the live inventory resolves to Unapproved, while an alert is one episode
  of one policy on one device, so one product on three devices is 1 present
  and 3 alerts. The device sets can also differ, on purpose:
  - with the tenant's unapproved alert turned off, nothing is raised but the
    product still counts as present;
  - an application removed from the inventory by a report that was not
    authority for alerts (no `collection_status.apps`, or not `complete`)
    stops counting as present while its alert stays open until a complete
    report proves it gone;
  - a browser extension proven gone by an authoritative report still counts
    as present (the overview reads every stored extension row, and those
    rows are never deleted) while its alert resolves;
  - a device first seen with an Unapproved product before 0183 ran and not
    reported since is tracked (`trigger: "baseline"`) and counted in both;
  - between a report committing and its post-commit alert check.

  Outside those cases, with the alert on, every device in
  `unapproved_present_devices` has exactly one open or acknowledged alert
  per Unapproved policy it carries, and no other device has one. Neither
  figure changes on acknowledge.

```json
{
  "unapproved_present": 1,
  "unapproved_present_devices": 2,
  "unapproved_alerts_open": 1,
  "unapproved_alerts_acknowledged": 1,
  "unapproved_present_items": [
    { "type": "application", "product_key": "application:macos:org.torproject.torbrowser:MADPSAYN6T",
      "name": "Tor Browser", "platform": "macos", "device_count": 2, "since": "2026-09-24T14:05:00Z" }
  ]
}
```

### New software by urgency (PAT-2093)

`new_software` is products first seen on the tenant in the last 14 days, or
since the tenant's last review when that is more recent (the shorter window),
each with an urgency level. `null` when the block could not be computed,
which is not "nothing new".

- **Window.** First seen and "last review" are exactly
  `GET /v1/portal/software/new`'s: first seen is the earliest
  `software_installations.first_seen_at` for the product across every device,
  removed installations included; the last review is the most recent approval
  decision any customer user recorded (`software_approval_decisions`).
  Operator policy writes through the admin API are not reviews.
  `since_basis` is `default_window` (14 days, `window_days`) or `last_review`.
  The window is `since` exclusive to `until` inclusive.
- **Excluded**, from both the list and `counts`: products resolving to
  Approved or Ignored (same resolver as every other governance surface), and
  Patched's own agent (the `agentidentity` list: macOS bundle
  `im.patched.updater.menubar` and `.selfservice`, Windows display name
  `Patched Agent`), whatever its policy. `excluded` counts each. Unapproved
  and Mandatory products are listed.
- **Bound.** `products` is the top 50 (`limit`) by urgency, then newest first
  seen. `total` and `counts` cover every classified product. At most 1000
  products in the window are classified, newest first; `truncated: true` says
  the window held more, and `counts` are then a floor.
- `coverage` is the `/software/new` coverage object: when `complete` is false
  the estate is not fully reporting and "nothing new" is not an estate-wide
  fact.

```json
"new_software": {
  "since": "2026-09-10T12:00:00Z", "since_basis": "default_window", "until": "2026-09-24T12:00:00Z",
  "window_days": 14, "last_review_at": null,
  "coverage": { "...": "as /software/new" },
  "total": 3,
  "counts": { "critical": 0, "high": 2, "not_assessed": 0, "medium": 1, "low": 0 },
  "excluded": { "approved": 2, "ignored": 0, "patched_agent": 1 },
  "truncated": false, "limit": 50,
  "products": [
    { "name": "Tool", "platform": "macos", "identifier": "com.example.tool", "team_id": null,
      "product_key": "application:macos:com.example.tool", "identity_basis": "identifier",
      "approval_state": "unreviewed", "first_seen_at": "2026-09-23T08:00:00Z", "device_count": 1,
      "urgency": "high",
      "reasons": [
        { "code": "signing_unknown", "level": "high", "detail": "the collector could not establish a signing authority on 1 of 1 installations (codesign could not read it, or an agent too old to say whether it is unsigned or ad hoc signed)" },
        { "code": "unknown_publisher", "level": "high", "detail": "no Team ID reported" },
        { "code": "cve_not_assessed", "level": "not_assessed", "detail": "no CVE mapping covers this product, so no CVE statement can be made" }
      ],
      "trust": { "trusted": false, "signing": "unknown", "signer_class": null, "notarisation": "unknown",
                 "publisher": null, "publisher_basis": "none", "publisher_has_approved_products": false,
                 "installations": 1 },
      "cve": { "state": "not_assessed", "finding_count": null, "severity": null } }
  ]
}
```

**Identity.** `identifier`, `team_id` and `product_key` follow
`GET /v1/portal/software`'s PAT-2104 rule and are what
`PUT /v1/portal/software-approvals` takes. `identifier` is the normalised
identity value (lower case), `null` for a `name_only` product. `team_id` is
macOS only, set when every installation reports the same valid Team ID.
`product_key` is `null` for a name-only product and for a macOS product whose
installations disagree on, or report a malformed, Team ID.

**Urgency.** `urgency` is the most severe level any reason sets. `reasons`
lists every applicable reason, most severe first.

| Level | Reason codes |
| --- | --- |
| `critical` | `cve_critical_or_high` (a known critical or high CVE); `unsigned` (macOS: an installation the collector reported `signing_status: "unsigned"`; Windows, PAT-2116: an installation the agent reported `signature_state: "unsigned"`; see below); `unidentifiable` (known by display name only, with no identifier, publisher or Team ID) |
| `high` | `adhoc_signed` (macOS: an installation reported `signing_status: "adhoc"`, signed with no identity); `notarisation_not_confirmed` (Developer ID signed, not every installation reported `notarization_status: "notarized"`); `untrusted_signer` (signed, but not by a Developer ID, App Store or Apple distribution identity -- including a macOS installation reported `signing_status: "untrusted"`, PAT-2117: the signature validates but the certificate chain does not anchor to Apple); `signature_invalid` (macOS: an installation reported `signing_status: "invalid"`, the signature does not validate against the code, PAT-2117); `signing_unknown` (an installation carries no signing evidence, or the collector could not establish a signing authority); `authenticode_invalid` (Windows: an installation's Authenticode signature does not match the file, PAT-2113); `authenticode_not_collected` (Windows: an installation with no Authenticode verdict, see below); `enterprise_root` (Windows, PAT-2116: an installation signed through an enterprise root the device trusts; not independently verifiable); `unknown_publisher`; `cve_medium`; `cve_low_or_unrated` |
| `not_assessed` | `cve_not_assessed` (no CPE mapping); `cve_pending` (mapped, not yet matched at every installed version) |
| `medium` | `trusted_publisher_no_known_cves`: trusted, CVE state `assessed` with zero findings, publisher not yet approved |
| `low` | `publisher_has_approved_products` (macOS): as medium, and the product's Team ID is on an approved application policy in this tenant; `authenticode_publisher_has_approved_products` (Windows, PAT-2121): as medium, and the product's Authenticode publisher key is on an approved Windows application policy for a different product in this tenant (see below) |

- **Not assessed is never "no CVEs".** A product is `medium` or `low` only
  when its CVE state is `assessed` with `finding_count: 0`. A trusted product
  whose CVE state is `not_assessed` or `pending` reads `not_assessed`, which
  sorts above `medium`. On a product already at `critical` or `high` for
  another reason, the CVE state is still carried in `cve` and in `reasons`.
- **Any known CVE blocks medium and low.** Low severity and unrated CVEs set
  `high`, like medium ones; the ticket's rules did not place them and quiet
  levels require no known CVEs. `version_unverified` findings count: they
  are on the findings page too.
- **Missing trust evidence is unknown, never trusted.** Trust is rolled up
  across the product's current installations (all installations when every
  one has been removed), worst instance first: one unsigned installation
  makes the product unsigned.
- **Trusted, macOS**: every installation reports a signing authority; every
  authority is Developer ID (`Developer ID Application: …`), App Store
  (`Apple Mac OS Application Signing`, `Apple iPhone OS Application Signing`)
  or Apple (`Software Signing`, `macOS Software Signing`); a Developer ID
  product was reported `notarization_status: "notarized"` on every
  installation; and the publisher is one valid Team ID, or Apple for
  Apple-signed software.
- **macOS signing evidence (PAT-2112, PAT-2117).** The collector reports each
  app's `signing_status` (`signed`, `adhoc`, `unsigned`, `error`, `untrusted`,
  `invalid`; see PAYLOAD_SCHEMA.md). `unsigned` sets `unsigned` (`critical`)
  and `trust.signing: "unsigned"`; `adhoc` sets `adhoc_signed` (`high`) and
  `trust.signing: "adhoc"`. `signed_by: "Unknown"` with `signing_status`
  `error` (codesign failed: unreadable bundle, TCC denial, broken signature)
  or with no `signing_status` at all (an agent before PAT-2112) is not
  evidence of unsigned and reads `signing_unknown` (`high`), as does a missing
  `signed_by` (rows backfilled from `device_apps`). `untrusted` (PAT-2117: the
  signature validates but the certificate chain does not anchor to Apple)
  sets `untrusted_signer` (`high`) and `trust.signing: "untrusted"`; `invalid`
  (PAT-2117: the signature does not validate against the code at all) sets
  `signature_invalid` (`high`) and `trust.signing: "invalid"`. Neither
  `untrusted` nor `invalid` ever counts as trusted or sets a publisher basis,
  even when `signed_by` or `team_id` reads as a genuine Developer ID: a
  forged or tampered certificate can carry either. Every applicable signing
  reason is listed; `trust.signing` is the worst installation: `unsigned`,
  then `invalid`, then `untrusted`, then `adhoc`, then `unknown`.
- **macOS notarisation (PAT-2112).** Only `notarization_status: "notarized"`
  confirms notarisation (Gatekeeper accepted the app as a notarised Developer
  ID app, or a stapled ticket when Gatekeeper could not answer).
  `not_notarized`, `unknown` and an absent status read as not confirmed, so a
  Developer ID product reads `high` with `notarisation_not_confirmed`. The
  legacy `notarized` boolean is not read: no collector before PAT-2112 could
  set it true, so products reported only by older agents stay not confirmed
  until those devices update. App Store and Apple-signed products need no
  notarisation. An `untrusted` or `invalid` installation is never in the
  `signed` state, so `trust.notarisation` reads `unknown` for it regardless
  of what `notarization_status` the collector reported (`not_notarized` and
  `unknown` respectively, PAT-2117): the same "notarisation is not the
  question here" reading `unsigned` and `adhoc` already get.
- **Windows (PAT-2113, PAT-2116).** Trust comes from the agent's
  per-installation Authenticode `signature_state` (`valid`, `invalid`,
  `unsigned`, `unknown`) and, beside `valid`, the root it chains to
  (`root_kind` `microsoft`, `public` or `enterprise`, and `root_thumbprint`;
  see PAYLOAD_SCHEMA.md). Agents from updater #668 send it for every
  installed app; older agents only for reviewed evidence targets (none
  today). Every applicable reason is listed and the worst installation wins.
  - **Trusted** when every installation is `valid`, they all report one
    signer (the leaf Subject DN), none chains to an `enterprise` root, and
    every installation that reports a `microsoft` or `public` root reports
    the same root thumbprint: `trust.signing: "signed"`, `trust.publisher`
    the signer with `publisher_basis: "authenticode_signer"`. With a clean
    assessed CVE state that is `medium`. An installation `valid` with none
    of the PAT-2116 publisher fields (an agent older than updater #668, which
    sends no root) is read as before: its agreed signer alone counts, so an
    estate mid-upgrade does not regress.
  - **Low (PAT-2121).** A trusted product whose every installation is
    pinned to one `microsoft` or `public` root has an Authenticode
    publisher key, `authenticode:<root thumbprint>:<leaf Subject DN>` (the
    DN trimmed, every whitespace run collapsed to one space, case and RDN
    separators kept as sent). When an approved Windows application policy
    in this tenant, for a different product, carries the same key, the
    product reads `low` with `authenticode_publisher_has_approved_products`
    and `trust.publisher_has_approved_products: true`. The key on a policy
    is derived by the server from this tenant's own evidence when the
    policy is set to approved (`PUT /v1/portal/software-approvals` below),
    never sent by a client. An `enterprise` root never has a key and never
    reaches `low`; nor does a product with any installation from an agent
    older than updater #668 (no root reported). Another tenant's approvals
    never count.
  - `unsigned` on any installation (the agent's conservative verdict: no
    embedded signature and a proven clean catalog miss) sets `unsigned`
    (`critical`) and `trust.signing: "unsigned"`, whatever the other
    installations report.
  - `invalid` on any installation sets `authenticode_invalid` (`high`) and
    `trust.signing: "invalid"`.
  - `root_kind: "enterprise"` on any installation sets `enterprise_root`
    (`high`), and the product is never trusted, however Microsoft-like its
    signer: an enterprise root is one only the device's own trust store
    vouches for (a Group Policy or locally added root, or a chain the agent
    could not classify), so the signer is not independently verifiable.
    `publisher_basis` stays `none`.
  - `unknown`, or no evidence at all, on any installation sets
    `authenticode_not_collected` (`high`); `trust.signing` is `unknown` when
    one was reported unknown, otherwise `not_collected`.
  - `unknown_publisher` (`high`) when valid signatures disagree on, or omit,
    the signer; when installations reporting a `microsoft` or `public` root
    disagree on, or omit, its thumbprint; or when an installation carries
    PAT-2116 publisher fields but no recognised `root_kind`.
  - `trust.signing` is the worst installation: `unsigned`, then `invalid`,
    then `unknown`, then `not_collected`, then `signed`.
  - Without Authenticode trust, `trust.publisher` is the registry
    `Publisher` string with `publisher_basis: "registry_publisher_unverified"`,
    a claim, not a signature; it is never matched against approved Team IDs
    or publisher keys, and `unknown_publisher` is set when no installation
    reports one.
  Critical rules (CVEs, name-only identity) apply as on macOS.
- `trust.signing`: `signed`, `unsigned` (macOS PAT-2112, Windows PAT-2116), `adhoc` (PAT-2112), `untrusted`
  (macOS, PAT-2117), `unknown`, `invalid` (macOS PAT-2117 or Windows
  PAT-2113 -- the same value on both, a signature that is present but wrong)
  or `not_collected` (Windows). `trust.signer_class`: `developer_id`, `app_store`, `apple`,
  `other`, `mixed`, or `null`. `trust.notarisation`: `confirmed`,
  `not_confirmed`, `not_applicable` (App Store, Apple, Windows) or `unknown`
  (not signed). `trust.publisher_basis`: `team_id`, `apple_signature`,
  `authenticode_signer` (Windows, PAT-2113), `registry_publisher_unverified`
  or `none`.
- `cve` is the product's estate-wide CVE assessment, the rollup behind
  `/software`'s `cve_assessment` (same mappings, queue, assessments and
  findings), keyed by the normalised identity. `severity` is distinct CVEs per
  recorded severity (`critical`, `high`, `medium`, `low`, `unrated`) plus
  `version_unverified` (any severity), `null` when `not_assessed`. A
  name-only product is always `not_assessed`: device_apps, which the CVE
  matcher reads, never stores an application without an identifier.

Cost: the `/software/new` query, one set-based trust evidence query over the
window's products, the estate CVE assessment for them, and the tenant's
policies, all tenant scoped.

## GET /v1/portal/overview/cards

PAT-2207. The Overview information cards read model for the Brand v3
Overview (PAT-2190). It is a separate route behind the same `portalauth`
middleware as `/overview`, so `/overview` and its consumers are unchanged.
The tenant comes only from the verified portal identity. No query parameter,
header or body is read.

The point of this endpoint is that the portal never infers health from
absent or partial data. Every card says what it knows, where that came from,
how fresh it is and whether it covers the scope it names.

```json
{
  "generated_at": "2026-09-28T10:00:00Z",
  "thresholds": {
    "active_within_hours": 24,
    "silent_after_days": 14,
    "exception_review_due_within_days": 30
  },
  "cards": {
    "devices": {
      "state": "value",
      "source": "devices.last_seen",
      "scope": "current_snapshot",
      "window": null,
      "freshness": {"generated_at": "2026-09-28T10:00:00Z", "observed_at": "2026-09-28T09:58:12Z"},
      "completeness": {"complete": true, "reason": null},
      "values": {"total": 6, "active": 2, "stale": 1, "silent": 1, "unknown": 1, "retired": 1},
      "unavailable_signals": []
    },
    "os_updates": { "...": "..." },
    "vulnerabilities": { "...": "..." },
    "cis_posture": { "...": "..." },
    "browser_extensions": { "...": "..." },
    "high_risk_software": { "...": "..." },
    "software_awaiting_approval": { "...": "..." },
    "exceptions_review": { "...": "..." },
    "agent_health": { "...": "..." },
    "recent_activity": { "...": "..." }
  }
}
```

All ten cards are always present, and every card carries every key below.
A key with nothing to say is `null` (or `[]`), never absent.

| Key | Meaning |
| --- | --- |
| `state` | `value`, `zero`, `unknown`, `unavailable` or `partial`. See below. |
| `source` | The named platform source. Present on every card, including unavailable ones. |
| `scope` | `current_snapshot` (the current estate) or `bounded_window` (only what happened inside `window`). |
| `window` | For `bounded_window`: `since`, `until`, `days` (the longest the window can be; `since` may be later, see `basis`) and `basis`. `null` for `current_snapshot`, and for an unavailable card. |
| `freshness.generated_at` | Platform (database) time the card was computed. Never browser time. |
| `freshness.observed_at` | Newest evidence the figure rests on, `null` when the source records no such time. |
| `completeness.complete` | `true` exactly when `state` is `value` or `zero`. |
| `completeness.reason` | A bounded reason code (snake_case, at most 64 characters) when not complete, `null` when complete. |
| `values` | A card-specific object for `value`, `zero` and `partial`; `null` for `unknown` and `unavailable`. |
| `unavailable_signals` | Signals this card deliberately does not carry yet, as `{signal, reason}`, whatever the card's own state. |

### States

These are distinct on the wire and must not be collapsed by a consumer.

- `value`: a complete, authoritative figure that is not zero.
- `zero`: checked, complete, and there is nothing. The only state a portal
  may render as "none" or healthy.
- `partial`: a real figure over incomplete coverage. `values` is present
  and is a floor or a partial view. `reason` says why.
- `unknown`: the source works but holds no evidence to decide from (for
  example no CIS evaluations yet). `values` is `null`.
- `unavailable`: the source failed, is not supported yet, is not migrated,
  or refused the estate. `values` is `null`.

Failure isolation: only the base device query (the `devices` card) fails
the response with a 500. Any other card whose source fails degrades to
`unavailable` with reason `query_failed`, and the platform logs the cause.

### Reporting thresholds

Buckets on the `devices` card are mutually exclusive and sum to `total`,
evaluated on the database clock against `devices.last_seen` (the server
receipt time of the device's latest report):

| Bucket | Rule |
| --- | --- |
| `retired` | The customer retired the device (PAT-2135), whatever its last report. |
| `unknown` | No usable report time: `last_seen` is null, or later than the database clock. Normally 0; `last_seen` is `NOT NULL` today. |
| `active` | Reported within `active_within_hours` (24, the same window as `/overview`'s `devices_reporting_24h`). |
| `stale` | Last report older than 24 hours but within `silent_after_days`. |
| `silent` | No report for more than `silent_after_days` (14, the same threshold as `softwaregov.StaleAfter`, the stale endpoints report and the software `coverage.stale_after_days`). |

`total` applies the tenant's platform switches exactly as `/overview`'s
`devices_total` does, so the two agree. Note the naming: what the software
coverage figures call `devices_stale` (over 14 days) is `silent` here.

### Cards

| Card | Source | Values | State rules |
| --- | --- | --- | --- |
| `devices` | `devices.last_seen` | `total`, `active`, `stale`, `silent`, `unknown`, `retired` | `zero` when `total` is 0, otherwise `value`. `observed_at` is the newest report at or before now. |
| `os_updates` | `device_os_update, devices.pending_updates` | `up_to_date`, `pending`, `unknown` | Never `value` or `zero`: counts alone do not establish version-level coverage, until PAT-2133/PAT-2191. `unavailable` (`no_update_evidence`) when no device has a usable update verdict, otherwise `partial` (`version_evidence_pending`). |
| `vulnerabilities` | `device_cve_findings` | `critical`, `high` (distinct confirmed CVEs, the `/overview` `cve_attention` rule) | `unavailable` (`source_not_migrated`) when the CVE store is absent. A zero is only authoritative after a completed full match: without one it is `unknown` (`no_completed_match_run`). `observed_at` is the last completed full match. |
| `cis_posture` | `compliance_evaluations` | `score` (the `/overview` `cis_score_current`), `evaluations` | `unknown` (`no_evaluations`) when there are no evaluations, otherwise `value`. `observed_at` is the latest evaluation. `unavailable_signals`: `material_regression` / `not_yet_supported`. |
| `browser_extensions` | `device_browser_extensions` | `elevated`, `total` (extension and browser pairs) | `unavailable` (`estate_too_large`) when `/extensions` fails closed; `partial` (`truncated`) when its row cap cut the list, so `elevated` is a floor; `zero` when nothing is elevated. |
| `high_risk_software` | `software_installations.first_seen_at` | `critical`, `high`, `classified` | `bounded_window`: products first seen in the last 14 days, or since the last review when that is later (`window.basis` is `default_window` or `last_review`). Never the whole estate, until PAT-2182. `partial` (`truncated`) or (`coverage_incomplete`) per the `/overview` `new_software` coverage. |
| `software_awaiting_approval` | `software_governance_estate` | `products` (distinct unreviewed products of any type), `devices` | `unavailable` (`estate_too_large`) over the estate load cap; `partial` (`coverage_incomplete`) when the software `coverage.complete` rule fails (a device silent over 14 days, or with no application inventory). |
| `exceptions_review` | `tenant_software_exceptions` | `review_overdue`, `review_due_soon`, `no_review_date`, `unaccepted`, `total` | Dates compared with the database's UTC date, the same calendar `/exceptions` uses for `review_overdue`. Due soon is within `exception_review_due_within_days` (30), inclusive. `zero` when nothing is overdue or due soon. `unavailable_signals`: `expiry` / `not_modelled` (exceptions have a review date, no expiry). |
| `agent_health` | `device_agent_health` | `devices_degraded`, `devices_reporting` (active plus stale), `devices_not_reporting` (silent plus unknown), `oldest_successful_ingest` | `unavailable` (`source_not_migrated`) when the table is absent (never a false zero). `unknown` (`no_devices`) with no non-retired devices. `partial` (`devices_not_reporting`) when any device is silent or unknown, because a fault on a device that stopped reporting cannot be seen. |
| `recent_activity` | `activity_feed` | none | Always `unavailable` (`not_yet_supported`) until PAT-2197. |

The OS update card reuses the executive report's three-state counts and existing
platform-enabled device population (PAT-2341). Explicit OS rows take precedence
over legacy arrays, including unknown, unavailable, unrecognised and stale rows.
Only recognised current/pending verdicts no older than seven days are usable;
age is measured from the earlier of `checked_at` and server `reported_at`, with
NULL `checked_at` falling back to receipt. Legacy arrays apply only without an
OS row. These counts do not change the report's patch-history median or establish
version-level completeness. `observed_at` remains the newest device report time,
not a claim that every OS verdict is fresh.

Reason codes: `query_failed`, `source_not_migrated`, `not_yet_supported`,
`not_modelled`, `no_update_evidence`, `version_evidence_pending`,
`no_completed_match_run`, `no_evaluations`, `estate_too_large`, `truncated`,
`coverage_incomplete`, `devices_not_reporting`, `no_devices`. New codes may be
added; a consumer must treat an unfamiliar code as "incomplete, reason
unknown", never as complete.

Cost: the base device aggregate plus the queries behind `/overview`'s
patching, compliance, `cve_attention` and `new_software` figures,
`/extensions`, the software governance estate load and two small
aggregates, all tenant scoped.

## GET /v1/portal/ce-readiness

PAT-1927. Cyber Essentials v3.3 readiness, per device, for the portal. It
lists what stands between each device and the v3.3 14-day update rule, and
the malware protection, firewall and secure configuration controls the
platform can evidence. Same `portalauth` middleware as `/overview/cards`,
same conventions: reporting buckets and thresholds on the database clock,
every value names its source and freshness, and missing evidence is
`unknown` or `not_evidenced`, never healthy.

Single tenant only: the tenant comes only from the verified portal
identity. There is no partner rollup. The only query parameter is
`format` (`json`, the default, `csv` or `pdf`); any other parameter, including a
tenant hint, is refused with `400 invalid_request`. Repeated formats and malformed
query strings are also refused (including `format=csv&format=pdf`). All existing
portal read roles, including the
read-only service identity, can download the PDF.

### What this does not claim

This endpoint gives no verdict. It never says a device or the estate
passes, is compliant, is ready or is certified, and no key or value is
named that way. A device is at most `no_outstanding_items_evidenced`: the
platform found nothing outstanding in the evidence it holds, which is not
the same as nothing outstanding. The estate block is counts only. It
covers only confirmed CVE matches for software the matcher knows about;
OS update posture is `unknown` everywhere until version-level evidence
lands (PAT-2133/PAT-2191); unconfirmed (`version_unverified`) matches are
not items; and Cyber Essentials areas the platform does not evidence here
(user access control, and secure configuration beyond the rules listed
below) are not assessed at all. Patched does not close the 14-day
obligation: remediation belongs to the customer's own Intune, Jamf, Patch
My PC or Robopack. Only a Cyber Essentials assessor certifies.

```json
{
  "generated_at": "2026-09-28T10:00:00Z",
  "thresholds": {"update_due_after_days": 14, "active_within_hours": 24, "silent_after_days": 14},
  "cve_matching": {"state": "evidenced", "reason": null, "source": "cve_match_runs.full_match", "observed_at": "2026-09-28T01:10:00Z"},
  "estate": {
    "devices_total": 3, "not_passing": 1, "with_outstanding_items": 1, "with_controls_not_passing": 0,
    "unknown": 1, "no_outstanding_items_evidenced": 1, "retired_excluded": 0,
    "source": "devices",
    "freshness": {"generated_at": "2026-09-28T10:00:00Z", "observed_at": "2026-09-28T09:58:12Z"}
  },
  "devices": [{
    "device_id": "…", "hostname": "mac-01", "platform": "macos",
    "state": "not_passing", "state_reasons": ["outstanding_items"],
    "reporting": {"bucket": "active", "source": "devices.last_seen", "observed_at": "2026-09-28T09:58:12Z"},
    "cve_evidence": {"state": "evidenced", "reason": null, "source": "device_cve_findings", "observed_at": "2026-09-28T01:10:00Z"},
    "os_update_evidence": {"state": "unknown", "reason": "version_evidence_pending", "source": "device_os_update", "observed_at": null},
    "items": [{
      "kind": "cve", "cve_id": "CVE-2026-1234", "severity": "critical",
      "product": "Example App", "installed_version": "1.0.0", "fixed_version": "1.0.5",
      "published_at": "2026-09-08T10:00:00Z", "due_basis": "advisory_published_plus_14_days",
      "due_at": "2026-09-22T10:00:00Z", "age_days": 20, "days_overdue": 6,
      "kev": {"state": "not_listed", "source": "cisa_kev", "fetched_at": "2026-09-28T00:30:00Z", "reason": null},
      "source": "device_cve_findings", "observed_at": "2026-09-28T09:58:12Z"
    }],
    "controls": [
      {"control": "xprotect_running", "category": "malware_protection", "state": "not_evidenced",
       "reason": "no_evaluation", "source": "compliance_evaluations", "rule_key": "cis_macos_5_10_xprotect_running", "observed_at": null}
    ]
  }]
}
```

Arrays are always arrays (`[]` when empty); a key with nothing to say is
`null`, never absent.

### The 14-day rule and the due date

An item is a critical or high CVE on the device that is confirmed under
the `/overview` `cve_attention` rule: a CVE counts only when no in-scope
finding for it in the tenant is `version_unverified`, and low-tier Homebrew
rows take no part in that vote. Severity is the feed's
(`cve_feed_entries.severity`). It is an item when its advisory was
published more than 14 days before `generated_at`.

`due_basis` is always `advisory_published_plus_14_days`: `due_at` is
`published_at` (`cve_feed_entries.published_at`, the advisory publication
date) plus 14 days. **This is a conservative proxy.** The platform does not
store the date a fix was released, and a fix can ship after its advisory,
so `due_at` can be earlier, and `age_days` and `days_overdue` larger, than
the true figures measured from fix availability. `days_overdue` is never
presented without `due_basis` beside it, in JSON or CSV. `age_days` is
whole days since `published_at`; `days_overdue` is `age_days - 14`.

A confirmed critical or high finding with no `published_at` cannot be
dated. It is not an item; instead the device's `cve_evidence` is
`unknown` (`advisory_date_unknown`). No date is invented.

`fixed_version` is the finding's fixed version, `null` when unknown.
`kev.state` is `listed` or `not_listed` against the retained CISA KEV
snapshot, and `unknown` (reason `source_unavailable`, `source_failed` or
`source_stale`) when that snapshot is missing, failed or older than 48
hours, the same freshness rule as the exploitation evidence (PAT-1871).
`kev.fetched_at` is the snapshot's fetch time.

### Device state

Retired devices (PAT-2135) are excluded and counted in
`estate.retired_excluded`. Platform switches apply as on `/overview`.
`reporting.bucket` uses exactly the `/overview/cards` `devices` buckets
(`active` under 24 hours, `stale` up to 14 days, `silent` beyond, `unknown`
with no usable report time).

| State | Rule |
| --- | --- |
| `not_passing` | At least one item, or at least one control `not_passing`. Positive evidence wins whatever the device's freshness. |
| `unknown` | Otherwise, when the device is not `active`, or its `cve_evidence` is `unknown`: no completed full match (`no_completed_match_run`), CVE store absent or failing (`source_not_migrated`, `query_failed`), observations still queued for matching (`cve_match_pending`), or an undated finding (`advisory_date_unknown`). |
| `no_outstanding_items_evidenced` | Otherwise. |

`state_reasons` lists every reason that applied: `outstanding_items`,
`control_not_passing`, `device_stale`, `device_silent`,
`device_no_report_time`, and the `cve_evidence` reason. `os_update_evidence`
is `unknown` (`version_evidence_pending`) on every device until
PAT-2133/PAT-2191 and does not itself decide the state.

### Controls

Controls appear only where the platform has a rule that evidences them.
Each is the latest evaluation of one rule (`source`
`compliance_evaluations`, `observed_at` the evaluation time):

| Platform | Control | Category | Rule |
| --- | --- | --- | --- |
| Windows | `defender_realtime_protection` | `malware_protection` | `cis_win_18_9_45_defender_realtime` |
| Windows | `defender_cloud_protection` | `malware_protection` | `cis_win_18_9_47_4_1_defender_cloud_protection` |
| Windows | `defender_definition_age` | `malware_protection` | `nist_win_si3_defender_definition_age` |
| Windows | `firewall_domain`, `firewall_private`, `firewall_public` | `firewalls` | `cis_win_9_1_1_firewall_domain`, `cis_win_9_2_1_firewall_private`, `cis_win_9_3_1_firewall_public` |
| macOS | `xprotect_running` | `malware_protection` | `cis_macos_5_10_xprotect_running` |
| macOS | `xprotect_data_auto_update` | `malware_protection` | `cis_macos_1_6a_xprotect_data_auto` |
| macOS | `gatekeeper` | `secure_configuration` | `cis_macos_2_5_2_1_gatekeeper` |
| macOS | `system_integrity_protection` | `secure_configuration` | `cis_macos_2_5_3_sip` |
| macOS | `firewall` | `firewalls` | `cis_macos_2_5_2_2_firewall` |
| both | `edr_coverage` | `malware_protection` | none: `devices.security_inventory` via the EDR coverage report (PAT-2226) |

| State | Rule |
| --- | --- |
| `evidenced_ok` | The latest evaluation passed, or EDR is `covered`. |
| `not_passing` | The latest evaluation failed with an observed value (`evaluation_failed`). |
| `not_evidenced` | Anything else: no evaluation (`no_evaluation`), an undetermined failure with no observed value (`undetermined`, PAT-1762), `not_applicable`, an evaluation error (`evaluation_error`), EDR `unrecognised` (`edr_unrecognised`) or `unknown` (`no_edr_evidence`), or a failing source (`query_failed`). |

A device on another platform carries no controls.

### CSV (`?format=csv`)

`text/csv` attachment `ce-readiness-YYYY-MM-DD.csv`, with
`X-Patched-Export-Rows`. One row per device per item (`row_kind` `item`),
or exactly one row for a device with no items (`row_kind` `device`, item
columns empty) stating its state. Columns: `device_id`, `hostname`,
`platform`, `device_state`, `state_reasons` (`;`-joined),
`reporting_bucket`, `device_last_seen`, `cve_evidence_state`,
`cve_evidence_observed_at`, `os_update_evidence_state`, `row_kind`,
`cve_id`, `severity`, `product`, `installed_version`, `fixed_version`,
`published_at`, `due_basis`, `due_at`, `age_days`, `days_overdue`,
`kev_state`, `kev_fetched_at`, `item_source`, `item_observed_at`,
`controls_not_passing`, `controls_not_evidenced` (`;`-joined control
names), `generated_at`. Free-text cells go through the formula-injection
guard (a leading `=`, `+`, `-`, `@`, tab or CR gets a `'` prefix).

### Dated evidence PDF (`?format=pdf`)

PAT-2364. `application/pdf` attachment `ce-readiness-YYYY-MM-DD.pdf`, dated from
`generated_at` in UTC, with `Cache-Control: private, no-store`. It renders only
this authenticated tenant's fetched read model, in memory, with no retained
report, database write, extra evidence query or new control mapping. The
existing JSON response and CSV columns are unchanged.

The customer header, embedded report fonts, page breaks and page numbers follow
the existing insurance evidence pack. The PDF includes generation time and
thresholds; all count-only estate figures, their source and generated/observed
times; and the global CVE matching state, source, reason and observation time.
Each device carries its identity, reporting bucket/source/time, state/reasons,
CVE and OS-update evidence state/source/reason/time, every existing control's
category/state/reason/source/rule key/time, and every outstanding item's kind,
CVE/severity/product/installed and fixed version, source/observation,
publication/due dates, age/overdue days, due basis and KEV state/source/fetched
time/reason. Missing values explicitly read `not recorded`; unknown, stale,
silent and not-evidenced states remain visible. Each device begins a new page. Controls and items stay together when their
font-measured wrapped content fits on a fresh page; larger blocks continue
across pages without dropping entries or fields.
Endpoint/feed text is printed as text, never HTML or active links. Characters outside the embedded Inter font coverage (including supplementary
Unicode), and non-printing controls other than line breaks, appear as explicit
`[U+XXXX]` codepoint escapes with at least four hexadecimal digits, extending
to five or six as needed (for example `[U+1F600]`). Literal `[` is encoded as
`[U+005B]`, so the escape representation is reversible. CRLF is normalised to
one line break; a lone carriage return is explicitly `[U+000D]`. The pack
explains the convention once. Other characters remain unchanged. Rendering failures return 500 before PDF headers
or bytes are sent, rather than a partial evidence pack.

The limitations above apply unchanged: no estate verdict, pass or certification
promise, no additional evidence collection, no assumptions that an unknown or
empty result is healthy. Due and overdue figures retain their explicit
`advisory_published_plus_14_days` basis, explained as a conservative proxy that
can overstate overdue time because Patched stores no fix-release date. The PDF
covers the complete fetched model rather than silently imposing an export row
limit; it is a snapshot, not evidence of changes after generation.

Failure isolation: only the base device query fails the response with a
500. A failing findings, evaluations, KEV or EDR source degrades what rests
on it (`query_failed`), which can only move a device towards `unknown` or
`not_evidenced`, never towards `no_outstanding_items_evidenced`.

## GET /v1/portal/insurance-evidence

PAT-2258. The cyber insurance evidence pack: answers to the endpoint
questions common to cyber insurance renewal forms, each from evidence
Patched already holds, with its source, freshness and the number of devices
it could not speak for. Same `portalauth` middleware and role rule as
`/ce-readiness`: every portal role can read it. The tenant comes only from
the verified portal identity; the only query parameter is `format` (`json`,
the default, `csv` or `pdf`), and any other parameter, including a tenant
hint, is refused with `400 invalid_request`.

### Rules

- **One calculation.** Every answer is read off an existing read model with
  that model's own per-device classification: EDR from the EDR coverage
  report (`FetchEDRCoverageReport`), encryption from the encryption posture
  report, whose per-device state is `FetchEncryptionStates`, the same
  function the Devices roster and the device page read (PAT-2496, see
  `encryption_ok` under `GET /v1/portal/devices`), update speed from
  `/ce-readiness` items,
  unsupported software from `/reports/software/unsupported`, local admin
  rights from the local admin report, remote access from
  `/reports/software/remote-access`, and the inventory from the
  `/ce-readiness` device list. Nothing is re-derived.
- **One estate.** The in-scope devices are the `/ce-readiness` devices: not
  retired, on an enabled platform. `retired_excluded` says how many were
  left out.
- **Unknown is never compliant.** A device that has not reported within
  `reporting_window_days` (14), or has no evidence for a question, is counted
  in that question's `unknown_devices` and never towards `answer.value` or
  `answer.percentage`. Percentages are over every in-scope device.
  `patching_speed` keeps `/ce-readiness`'s own stricter rule: a device with
  nothing outstanding counts only when it reported within 24 hours and its
  CVE evidence is complete.
- **Named devices (PAT-2496).** An answer's `answer_text` may name devices.
  Today only `disk_encryption` does: when one or more in-scope devices that
  reported within `reporting_window_days` are observed with encryption off, the
  sentence "N device(s) report(s) encryption turned off." is followed by
  `Encryption is turned off on: HOST-A, HOST-B.`, hostnames sorted without
  regard to case. At most ten are named; past that the sentence ends
  `HOST-A, ... HOST-J and 3 more.` A device with no hostname is shown as
  `(no hostname)`, never as an empty item. Devices that are unknown, not
  reporting, encrypted or retired are never named. The names are free text the
  agent supplied, with control characters replaced by spaces and otherwise
  unaltered; the CSV form applies the usual formula guard to the whole
  `answer_text` cell, and the PDF form prints the same text. `answer.counts` is
  unchanged and carries no names. A client must not parse the sentence; the
  counts are the structured figures.
- **Nothing omitted.** MFA, email security, backups, incident response and
  training are always present with `status: not_evidenced_by_patched`.
- **No verdict.** `status` says how much of the estate the evidence covers
  (`evidenced` only when every in-scope device has a determinate answer,
  `partial`, `unknown`), never whether the answer is good. Nothing states or
  implies that the organisation qualifies for cover or for better terms.
  `remote_access_tools` is never better than `partial` (reason
  `catalogue_limited`) because detection covers only catalogued tools.
- **Failure isolation.** Only the tenant lookup or the `/ce-readiness` read
  can fail the request (`500`). Any other source failing makes its question
  `unknown` with reason `source_unavailable` (or `estate_too_large`) and no
  figures.

The question list and wording live in one Go slice,
`insuranceQuestions` in `go-service/internal/report/insurance_evidence.go`.

```json
{
  "generated_at": "2026-09-29T04:10:02Z",
  "statement": "This pack states what Patched's endpoint evidence showed when it was produced, …",
  "reporting_window_days": 14,
  "devices_in_scope": 4,
  "retired_excluded": 1,
  "questions": [
    {
      "id": "edr_coverage",
      "group": "evidenced_by_patched",
      "title": "EDR and anti-malware",
      "question": "Do all of your endpoints have endpoint detection and response (EDR) or anti-malware protection?",
      "status": "partial",
      "reason": null,
      "answer": {
        "value": 1, "unit": "devices", "percentage": 25,
        "counts": {"devices_in_scope": 4, "covered": 1, "unrecognised_tool": 1, "no_evidence": 1, "not_reporting": 1}
      },
      "unknown_devices": 3,
      "as_of": "2026-09-29T04:10:02Z",
      "oldest_evidence_at": "2026-09-29T03:10:02Z",
      "source": {"label": "Cyber Essentials readiness (EDR coverage)", "path": "/ce-readiness"},
      "headline": "1 of 4 devices (25.0%)",
      "answer_text": "1 of 4 devices (25.0%) reports endpoint protection that Patched recognises. 3 devices are unknown (…) and are not counted in your favour.",
      "basis": "Security tools each device reported, matched against the endpoint protection products Patched recognises …"
    },
    {
      "id": "mfa",
      "group": "not_evidenced_by_patched",
      "title": "Multi-factor authentication",
      "question": "Is multi-factor authentication enforced for email, remote access and privileged accounts?",
      "status": "not_evidenced_by_patched",
      "reason": "outside_patched_evidence",
      "answer": {"value": null, "unit": "", "percentage": null, "counts": {}},
      "unknown_devices": null,
      "as_of": null,
      "oldest_evidence_at": null,
      "source": null,
      "headline": "Answer from your own records",
      "answer_text": "Not evidenced by Patched. Patched collects evidence from your endpoints and holds nothing that answers this question. Answer it from your identity provider or email platform's sign-in settings.",
      "basis": "Outside the endpoint evidence Patched collects."
    }
  ]
}
```

Question ids, in order: `edr_coverage`, `disk_encryption`, `patching_speed`,
`unsupported_software`, `local_admin_rights`, `remote_access_tools`,
`asset_inventory`, `mfa`, `email_security`, `backups`,
`incident_response`, `security_training`. `source.path` is a portal path.
`as_of` is the source read model's generation time; `oldest_evidence_at` is
the oldest device report behind the figures.

`?format=csv` is one row per question in that order, columns
`question_id, group, title, question, status, reason, headline, answer_text,
value, unit, percentage, counts, unknown_devices, as_of, oldest_evidence_at,
source_label, source_path, basis, generated_at`; `counts` is
`key=value` pairs joined with `;`. Free text goes through the spreadsheet
formula escaping every portal CSV uses. `?format=pdf` is the customer PDF,
the same renderer as the `insurance-evidence` report type below.

## GET /v1/portal/control-coverage

Tenant-wide live control-coverage read model. This is separate from
`/overview`: it describes which controls are configured for automated
evaluation, and does not alter `cis_score_current` or its unknown-evidence
denominator. The response is additive: the established `controls` fields and
`total_zero` remain unchanged, with new `measurements` and `identifiers`
objects at the aggregate and benchmark/version levels.

Explicit no-applicable-rules response:

```json
{
  "generated_at": "2026-09-20T17:00:00Z",
  "platforms": [],
  "controls": {
    "total": 0,
    "evaluated": 0,
    "out_of_scope": 0,
    "undetermined_evaluations": 0
  },
  "measurements": {
    "pass": 0,
    "fail": 0,
    "undetermined": 0,
    "not_applicable": 0
  },
  "identifiers": {
    "cis_mapped": 0,
    "cis_unmapped": 0,
    "non_cis": 0
  },
  "benchmarks": [],
  "total_zero": true
}
```

- `platforms` is the tenant's enabled platform mix (`macos`, `windows`), not
  an inventory assertion. Rules for disabled platforms are excluded from every
  count; an enabled platform may still have no devices.
- `controls.total` counts enabled rule-library rows for the enabled platform
  mix. `evaluated` is every T1 rule plus a T2 rule with an enabled,
  non-suppressed tenant rule. T3 is always shown separately as
  `out_of_scope`, never silently treated as evaluated.
- `undetermined_evaluations` counts latest per-device, per-rule rows only
  where the rule is enabled and applicable to the tenant's enabled platform,
  the device OS matches that rule platform, `status = "fail"`, and
  `observed_value IS NULL`. It is evidence the collector could not determine,
  not an asserted non-compliant setting; it does not change the existing CIS
  score, `treat_unknown_as`, or `treat_not_configured_as` semantics.
- `measurements` is additive to the legacy `controls` object. Its unit is a
  latest, applicable per-device, per-rule evaluation row, so a control can
  contribute a row for each device. `pass` is `status = "pass"`; `fail` is
  `status = "fail"` with a non-null observed value; `undetermined` is a fail
  without an observed value or `status = "error"`; and `not_applicable` is
  `status = "not_applicable"`. These are the four observed measurement
  states. The legacy `undetermined_evaluations` retains its narrower,
  fail-without-observation definition. `out_of_scope` remains the separate configuration dimension in
  `controls`, yielding the five customer-visible states without treating a
  missing result as a pass.
- `identifiers` is additive and has a different unit: enabled control
  definitions in the same platform-filtered `controls.total` denominator,
  never evaluation rows. A definition belongs to exactly one bucket:
  `cis_mapped` has a persisted `control_identifier` and a benchmark in the
  `CIS ` namespace; `cis_unmapped` is in that namespace but has no persisted
  identifier; `non_cis` is outside it. The API provides these buckets so a
  client never infers them from rule keys or returned strings. The three
  identifier counts sum to `controls.total`.
- `benchmarks` is ordered by `benchmark`, then `benchmark_version`, and
  preserves multiple active benchmark/version pairs rather than inventing a
  global estate-wide benchmark. Each item has `benchmark`,
  `benchmark_version`, the legacy `controls` object, and additive
  `measurements` and `identifiers` objects with the same fields as the
  top-level aggregate. This preserves mixed-platform and mixed-version
  context rather than inventing one estate-wide benchmark.
- `total_zero` is explicit. When true, `controls.total` is zero and
  `benchmarks` is `[]`; every `measurements` and `identifiers` field is zero.
  It means no enabled rule rows match the tenant's enabled platforms, not that
  the estate achieved zero-percent compliance.

### Rule-count source of truth

The counts above are deliberately live queries over `compliance_rules` and
`tenant_rules`, filtered by the tenant platform switches. They are not a
hardcoded product claim. To determine a deployment's current inventory,
apply the ordered SQL migrations then query the live database, for example:

```sql
SELECT platform, benchmark, benchmark_version, collection_tier, COUNT(*)
FROM compliance_rules
WHERE enabled = true
GROUP BY platform, benchmark, benchmark_version, collection_tier
ORDER BY platform, benchmark, benchmark_version, collection_tier;
```

Migration history and catalogue prose can describe the pack that existed when
they were written, but neither is a current count. This method resolves the
older differing CIS-count snapshots in the architecture, scoring, catalogue,
and security documents without treating any snapshot as runtime fact.

## GET /v1/portal/devices

Device roster, paginated: `?limit=` (default and max 500), `?offset=`.

```json
{
  "generated_at": "2026-07-02T17:00:00Z",
  "total": 12,
  "limit": 50,
  "offset": 0,
  "devices": [
    {
      "device_id": "0b39cbe5-…",
      "hostname": "LT-0042",
      "platform": "macOS",
      "os_version": "15.5",
      "last_seen": "2026-07-02T16:41:09Z",
      "cis_score": 91.3,
      "findings_open": 4,
      "encryption_ok": true,
      "patch_pending": false,
      "device_class": "workstation",
      "os_caption": null,
      "retirement": null,
      "evidence": {
        "observed_at": "2026-07-02T16:40:42Z",
        "received_at": "2026-07-02T16:41:09Z",
        "sections": {
          "certificates": "complete",
          "hardware_health": {
            "battery": "complete",
            "storage": "partial",
            "disks": "unavailable"
          }
        },
        "authority": "section_scoped",
        "freshness": "fresh"
      }
    }
  ]
}
```

- `retirement` (PAT-2135) — `null` unless the customer has retired the
  device, otherwise `{"retired_at", "retired_by", "reason",
  "reported_after_retirement"}`: when and by whom (the verified portal email,
  as the approval history shows it), the optional reason, and whether the
  device's latest received report (`last_seen`, the report's server receipt
  time) is after `retired_at`. A device that reports again is never
  unretired automatically; only the customer can reverse it. A retired
  device stays on the roster and in `total`.
- `encryption_ok` — latest disk-encryption evaluation (FileVault /
  BitLocker): `true` = pass, `false` = a real evidenced fail/error (the
  device was checked and found unencrypted), `null` = not evaluated OR
  undetermined (PAT-1762: the collector could not read the encryption state —
  an absent signal, or its "Unknown" sentinel — so this reads the same as
  "not evaluated" rather than a false "not encrypted"). PAT-2496: this is one
  of three outcomes (encrypted, not encrypted, unknown) produced by one
  function, `FetchEncryptionStates` in
  `go-service/internal/report/encryption_state.go`, over the latest evaluation
  of the FileVault and BitLocker CIS rules for macOS and Windows alike. The
  insurance evidence pack and the Encryption & Disk Posture report (its
  counts, PDF and CSV `state` column) read the same function, so every
  surface gives the same answer for a device. `true` is `encrypted`, `false`
  is `not_encrypted`, `null` is `unknown`.
- `patch_pending` (PAT-1805, source extended by PAT-2294): whether the device
  has OS updates outstanding: `true` = yes, `false` = checked and up to date,
  `null` = update state not reported. The source is
  the device's explicit `device_os_update` verdict first, including when it
  is unknown or stale. Only when no OS row exists does it fall back to
  `devices.pending_updates`: an empty array is `false`, a non-empty array is
  `true`, and NULL is `null`. For explicit OS verdicts (the agent's
  `os_update` block, see `go-service/docs/PAYLOAD_SCHEMA.md`): state
  `up_to_date` is `false`;
  `update_recommended`, `update_required`, `deadline_passed` and
  `unsupported_hardware` are `true`; `unknown`, a state the server does not
  recognise, and a verdict older than seven days (the same
  window as `evidence.freshness`, measured from the agent's `checked_at`,
  capped at the server's receipt time) are `null`. `null` is never "up to
  date".
- `device_class` and `os_caption` (PAT-2324) — whether the device is a server
  or a workstation, and the operating system edition string.
  `device_class` is always exactly one of `server`, `workstation` or `unknown`:
  never null, never any other string. It is the class the agent collected
  (`devices.device_class`, set at ingest) with one exception. A macOS device
  whose stored class is `unknown` or empty reads `workstation`, because macOS
  has no server edition and the Mac agent sends no class; that value is
  derived from the operating system family, not collected. A Windows device
  with no reported class stays `unknown`, because Windows ships both editions
  and a missing class is not evidence of either. A stored `domain_controller`
  reads `server`, because a domain controller is a Windows Server. Any other
  stored value reads `unknown`.
  `os_caption` is the stored edition caption, trimmed, for example
  `Microsoft Windows Server 2022 Standard`, or `null` when the device has not
  reported one (every Mac today). It is never derived. The same two fields
  appear under `device` on `GET /v1/portal/devices/{deviceID}`, from the same
  function, so the two routes cannot disagree.
- `findings_open` — failing + errored evaluations for the device. PAT-1762:
  a "failing" evaluation with no observed value (unreadable evidence) is
  excluded from this count — it is not the same claim as a real,
  evidenced failure — though it still counts against `cis_score`'s
  denominator, so unreadable evidence never raises the score.
- `evidence` (PAT-1867) — additive evidence authority envelope. Older portal
  readers may ignore it. It is a statement about the newest immutable payload
  successfully linked to this device, not a new agent payload or an actuation
  contract.
  - `observed_at` — endpoint-reported `collected_at` from the selected payload,
    parsed as RFC3339, or `null` when it is unusable. It records when the
    endpoint observed the evidence.
  - `received_at` — server timestamp of that payload's `raw_payloads` record,
    or `null` when no immutable payload is linked to the device. It records
    when Patched received the evidence and is intentionally distinct from
    `observed_at`.
  - `sections` — exact collection-status values explicitly present in the same
    raw payload as both timestamps. The only current names are `certificates`
    and `hardware_health.{battery,storage,disks}`; each reported value is
    `complete`, `partial`, or `unavailable`. Missing keys remain omitted and
    confer no authority. A malformed value fails the whole section map closed
    to `{}` rather than falling back to an older payload. A merged
    `devices.collection_status` snapshot is deliberately not used because its
    keys can originate from different payloads.
  - `freshness` — `fresh` when `observed_at` is no more than seven days old,
    `stale` when older, or `unknown` when observation time is missing,
    malformed, or in the future. Freshness is intentionally based on endpoint
    observation time, not upload time: an old observation uploaded today is
    still stale. Fresh does not upgrade incomplete evidence.
  - `authority` — current absence-claim boundary, not a remediation command:
    `section_scoped` when fresh evidence contains at least one named `complete`
    section; `presence_only` when its strongest explicit status is `partial`;
    `unavailable` when all explicit sections are unavailable; `unknown` when
    there is no valid section status, observation time, or receipt evidence;
    and `stale` when named section evidence is older than seven days.

`section_scoped` is deliberately not device-wide authority. An absence or
finding may be cleared only for a named section whose own `sections` value is
`complete`. A `partial` section can support observed presence only. An
`unavailable` section and every unlisted domain have no absence authority.
In particular, this envelope says nothing about completeness or absence for
apps, updates, CIS signals, browser extensions, or any future domain that is
not explicitly named in `sections`.

The envelope reads one immutable raw receipt/collection record. It does not
mutate findings, change tenant scoping, or alter the `limit`/`offset`
pagination contract. It needs no schema migration. Older payloads that do not
carry the explicit collection-status fields safely project as
`sections: {}` and `authority: "unknown"`.

## GET /v1/portal/devices/{deviceID}

One device with compliance signals and vulnerable apps. `404` for unknown,
malformed, or other-tenant device IDs.

```json
{
  "generated_at": "2026-07-02T17:00:00Z",
  "device": {
    "device_id": "0b39cbe5-…",
    "hostname": "LT-0042",
    "serial": "C02XL0GTJGH5",
    "platform": "macOS",
    "os_version": "15.5",
    "os_build": "24F74",
    "first_seen": "2026-11-01T09:12:44Z",
    "last_seen": "2026-07-02T16:41:09Z",
    "cis_score": 91.3,
    "findings_open": 4,
    "encryption_ok": true,
    "patch_pending": false,
    "device_class": "workstation",
    "os_caption": null,
    "retirement": {
      "retired_at": "2026-09-25T10:00:00Z",
      "retired_by": "admin@example.com",
      "reason": "Written off after theft",
      "reported_after_retirement": false
    },
    "evidence": {
      "observed_at": "2026-07-02T16:40:42Z",
      "received_at": "2026-07-02T16:41:09Z",
      "sections": {
        "certificates": "complete"
      },
      "authority": "section_scoped",
      "freshness": "fresh"
    }
  },
  "identity": {
    "status": "complete",
    "serial": "C02XL0GTJGH5",
    "hardware_model": "Mac16,1",
    "computer_name": "Alice's MacBook Pro",
    "architecture": "arm64",
    "os_name": "macOS",
    "os_version": "15.5",
    "os_build": "24F74",
    "agent_version": "0.19.22",
    "first_seen": "2026-11-01T09:12:44Z",
    "last_seen": "2026-07-02T16:41:09Z",
    "evidence": {
      "observed_at": "2026-07-02T16:40:42Z",
      "received_at": "2026-07-02T16:41:09Z",
      "freshness": "fresh"
    }
  },
  "hardware": {
    "status": "complete",
    "evidence": {
      "observed_at": "2026-07-02T16:40:42Z",
      "received_at": "2026-07-02T16:41:09Z",
      "freshness": "fresh"
    },
    "cpu": { "status": "complete", "model": "Apple M2", "cores": 8 },
    "memory": { "status": "complete", "total_gb": 16 },
    "disks": {
      "status": "complete",
      "items": [
        { "device": "disk0", "smart_status": "Verified", "internal": true, "solid_state": true }
      ]
    },
    "volumes": {
      "status": "complete",
      "items": [
        { "mount": "/", "total_bytes": 494384795648, "free_bytes": 32135159808, "used_pct": 93 }
      ]
    },
    "battery": {
      "status": "complete",
      "present": true,
      "cycle_count": 30,
      "condition": "Normal",
      "max_capacity_pct": 100
    }
  },
  "compliance_signals": [
    {
      "rule_id": "cis_macos_2_5_1_1_filevault",
      "title": "Enable FileVault",
      "severity": "critical",
      "status": "pass",
      "advisory": "FileVault encrypts the system volume…",
      "undetermined": false
    }
  ],
  "apps_with_findings": [
    {
      "app": "ExampleApp",
      "version": "1.2.3",
      "cve_ids": ["CVE-2026-0001", "CVE-2026-0002"],
      "max_severity": "high",
      "match_confidence": "version_confirmed",
      "fixed_version": "1.2.4"
    }
  ],
  "agent_health_degraded": [
    {
      "kind": "tcc_denied",
      "subject": "browser_extensions",
      "reason": "full_disk_access_missing",
      "first_seen": "2026-09-20T09:00:00Z",
      "last_seen": "2026-09-24T09:00:00Z",
      "count": 5
    }
  ],
  "firmware": {
    "status": "unavailable",
    "reported_at": "2026-09-29T09:00:00Z",
    "observed_at": "2026-09-29T08:59:40Z",
    "errors": ["bios_query_failed", "system_query_failed", "baseboard_query_failed"],
    "bios": {
      "status": "complete",
      "reported_at": "2026-09-28T09:00:00Z",
      "manufacturer": "LENOVO",
      "version": "N3HET82W (1.54 )",
      "smbios_version": "3.2",
      "release_date": "2023-05-12",
      "release_date_raw": null
    },
    "system": {"status": "complete", "reported_at": "2026-09-28T09:00:00Z", "manufacturer": "LENOVO", "model": "20XW0026UK"},
    "baseboard": {"status": "complete", "reported_at": "2026-09-28T09:00:00Z", "manufacturer": "LENOVO", "product": null}
  },
  "kernel_drivers": {
    "status": "complete",
    "reported_at": "2026-09-29T09:00:00Z",
    "observed_at": "2026-09-29T08:59:40Z",
    "errors": [],
    "enforcement": {
      "vulnerable_driver_blocklist": "disabled",
      "hvci": "off",
      "smart_app_control": "off",
      "code_integrity_policy": "off",
      "blocklist_enforced": "no"
    },
    "lists": [
      {"source": "microsoft_driver_blocklist", "source_url": "https://aka.ms/VulnerableDriverBlockList", "status": "succeeded",
       "fetched_at": "2026-09-29T01:00:00Z", "attempted_at": "2026-09-29T01:00:00Z", "list_version": "10.0.29545.0", "entry_count": 1124, "stale": false},
      {"source": "loldrivers", "source_url": "https://www.loldrivers.io/api/drivers.json", "status": "failed",
       "fetched_at": "2026-09-26T01:00:00Z", "attempted_at": "2026-09-29T01:00:00Z", "list_version": "sha256:4be1...", "entry_count": 4630, "stale": true}
    ],
    "summary": {"drivers": 612, "hashed": 610, "unhashed": 2, "listed": 1, "listed_malicious": 0, "unknown": 2},
    "drivers": [
      {
        "path": "C:\\Windows\\Temp\\helper.sys",
        "service_name": "helper",
        "service_type": "kernel",
        "start_type": "demand",
        "loaded": true,
        "sources": ["service", "loaded"],
        "hash_status": "hashed",
        "unhashed_reason": null,
        "version": "1.0.0.1",
        "sha256": "…",
        "authenticode_sha256": "…",
        "reported_at": "2026-09-29T09:00:00Z",
        "first_seen_at": "2026-09-27T09:00:00Z",
        "match_status": "listed",
        "unknown_reason": null,
        "matches": [
          {"source": "loldrivers", "source_url": "https://www.loldrivers.io/api/drivers.json", "category": "vulnerable",
           "entry_id": "…", "entry_name": "gdrv.sys", "hash_kind": "sha256", "hash": "…",
           "list_version": "sha256:4be1...", "list_fetched_at": "2026-09-26T01:00:00Z", "list_stale": true}
        ]
      }
    ],
    "drivers_truncated": false
  }
}
```

- `compliance_signals[].undetermined` (PAT-2496) is a boolean on every entry,
  additive: `status` and every other field are unchanged. It is `true`
  exactly when the rule's `status` is `fail` only because the value could not
  be read (an absent signal, or the collector's "Unknown" sentinel, so no
  value was observed), and `false` for every other entry, including a
  `fail` on an observed value and a `fail` on "NotConfigured". It is the
  predicate the roster's `encryption_ok`, the reports and the findings counts
  already use (`isUndeterminedEval` in `go-service/internal/report/pdf.go`,
  `EvalRow.Undetermined`). A client shows an `undetermined` entry as unknown,
  not as a failure; `device.encryption_ok` is `null` for the same device.
  An older client that ignores the field keeps reading `status` as before.

- `device.findings_open`, `device.encryption_ok` and `device.patch_pending`
  (PAT-2294) are the same three figures, with the same meaning, that
  `GET /v1/portal/devices` returns for this device (see the field list under
  that route, including the Windows `patch_pending` source). They come from the
  same query and the same derivation as the roster row, so the list and the
  device page cannot disagree. `findings_open` is a number; `encryption_ok`
  and `patch_pending` are `true`, `false` or `null`, and `null` means not
  evaluated or not reported, never healthy. Additive: every other field is
  unchanged, and the tenant is still the verified caller's, never taken from
  the URL.

- `device.device_class` and `device.os_caption` (PAT-2324) are the roster's
  `device_class` and `os_caption` for this device, with the same values and the
  same rules, including the macOS derivation by operating system family. They
  are read through the same query and the same function as the roster row.
  `device_class` is always `server`, `workstation` or `unknown`; `os_caption`
  is a string or `null`. Additive: every other field is unchanged.

- `device.evidence` (PAT-1867): the same additive, section-scoped evidence
  authority envelope as the device roster. Its timestamp, freshness, section,
  and absence-claim semantics are defined under `GET /v1/portal/devices` above.
  It is derived only from the newest immutable payload linked to this exact
  tenant-scoped device; it neither broadens the detail route's existing `404`
  anti-enumeration behaviour nor grants device-wide authority.

- `identity` and `hardware` (PAT-2141) are additive: every field documented
  above this point is unchanged. Both are sourced from the same data
  `GET /admin/devices/{deviceID}` and the portal PDF's Hardware health section
  (PAT-2130) already read — `report.Fetch`'s `Device`, `Hardware` and
  `HardwareHealth` fields, unchanged — so this ticket added no new query and
  no migration. **`hw_uuid` is never included** in either block or anywhere
  else on this route.
  - Each block, and each hardware sub-block, carries a `status` drawn from
    the same vocabulary the evidence envelope's `sections` values already
    use — `"complete"`, `"partial"`, `"unavailable"` — plus one more this
    ticket adds, `"not_collected"`, for a block with no stored data and no
    explicit collection status at all. A block's arrays are never empty or
    zeroed as a silent stand-in for "not collected"; `status` always says so
    explicitly next to them (root `AGENTS.md`: "Absence requires
    authority").
  - `identity.status` is `"complete"` once this device has delivered at
    least one inventory payload ever (every identity field is validated
    together at ingest, so there is no partial state for this block), or
    `"not_collected"` when the device row exists (e.g. freshly enrolled) but
    no payload has ever been received.
  - `identity.hardware_model` carries `devices.hw_model` verbatim — the
    identifier form (`sysctl -n hw.model` on macOS, e.g. `"Mac16,1"`; WMI
    `ComputerSystemProduct.Name` on Windows). There is no separate "model
    identifier" field or column anywhere in this platform today: `hw_model`
    already **is** the identifier. A human-readable model name (e.g. "MacBook
    Pro") is not collected or stored, so it is not fabricated here.
  - `identity.evidence` is the same `observed_at`/`received_at`/`freshness`
    timing as `device.evidence` above, reduced to just that timing (no
    `sections`/`authority`, which stay device-wide at `device.evidence`).
  - `hardware.status` is a rollup across the five sub-blocks below:
    `"not_collected"` only when every one of them is; `"partial"` when any
    is `partial` or `unavailable`; `"complete"` otherwise. Always read a
    sub-block's own `status` for the actual claim about that sub-block — the
    top-level rollup is a glance-level summary, not a substitute for it.
  - `hardware.cpu` / `hardware.memory` — from `devices.hardware` JSONB
    (`cpu_model`, `cpu_cores`, `ram_gb`), which carries no per-run collection
    status of its own: either the whole object was sent this ingest or it
    wasn't, so these two sub-blocks are only ever `"complete"` or
    `"not_collected"`, never `"partial"`/`"unavailable"`. Populated on macOS
    today; absent on Windows (schema_version 3 sends no `hardware` object),
    which reads as `"not_collected"`, not a Windows-specific error.
  - `hardware.disks` / `hardware.volumes` / `hardware.battery` — from
    `device_hardware`/`device_disk`/`device_storage_volume`, the same tables
    `fetchHardwareHealth` (`internal/report/report.go`) already reads for
    the admin endpoint and the PAT-2130 PDF section. Each sub-block's
    `status` is the latest payload's explicit `hardware_health
    .collection_status.{battery,storage,disks}` value when the most recent
    payload carried one (PAT-1720 vocabulary: `complete`/`partial`/
    `unavailable`); otherwise stored-data presence stands in for
    `"complete"` (an absent `collection_status` key means the section was
    collected in full, per `PAYLOAD_SCHEMA.md`); `"not_collected"` only
    when there is neither an explicit status nor any stored row — this
    device has never reported `hardware_health` at all.
  - `hardware.disks.items[].device` deliberately has no model or capacity
    field: `device_disk` stores only the device node, SMART status,
    `internal` and `solid_state` — the macOS collector's `diskutil` read
    carries no disk model or size today. Adding either needs a new collector
    field and a migration; out of scope for PAT-2141.
  - `hardware.battery` fields (`present`, `cycle_count`, `condition`,
    `max_capacity_pct`) are `null`/omitted together, never a false `present`
    standing in for "no battery data", when `status` is `"not_collected"`.

- `status` ∈ `pass | fail | not_applicable | error`;
  `severity` ∈ `low | medium | high | critical`.
- `apps_with_findings` — one row per (app, version); `cve_ids` sorted;
  `max_severity` lowercased worst severity across those CVEs. `match_confidence`
  is `"version_unverified"` if any bundled CVE is unverified, else whichever
  confirmed value the bundle carries (e.g. `"version_confirmed"` or
  `"version_vendor_confirmed"` — not a fixed two-value enum); `fixed_version`
  is the highest fixed version across the bundled CVEs, `""` when none is
  known.
- `agent_health_degraded` (PAT-2099): this device's currently open rows from
  the `agent_health.degraded` channel (PAT-1064), tenant-scoped — a device
  belonging to another tenant can never appear here, enforced by the same
  `device_id`/`tenant_id` join the roster and evidence queries use, not only
  by the route's own ownership check. One entry per distinct
  `(kind, subject)`; `kind`/`subject`/`reason` are the documented-not-enforced
  vocabulary in `go-service/docs/PAYLOAD_SCHEMA.md` (e.g. macOS-only
  `tcc_denied`/`browser_extensions`/`full_disk_access_missing`, and the same
  triple for `mcp_servers`, `ide_extensions`, `package_managers`). Empty
  array, never omitted or null, when the device has no open faults. An entry
  that clears (the agent stops reporting it, or sends an explicit all-clear)
  disappears from this list on the next successful extraction — there is no
  separate "resolved" state to read here.
- `firmware` (PAT-2262): what the device's firmware reports about itself,
  from `device_firmware_current`, tenant-scoped. Observation only: no field
  says whether a firmware version is current, outdated or vulnerable. Always
  present. `status` is the newest report's block status: `not_reported`
  (the device has never sent the block: an agent older than PAT-2262, or
  macOS, which does not collect it yet; every other field is null and
  `errors` is `[]`), `unavailable` (the agent tried and read nothing),
  `partial` or `complete`. `reported_at`/`observed_at` are that report's
  received and collected times; `errors` its fixed codes. `bios`, `system`
  and `baseboard` are null until a report has read that section; once read,
  each carries its own `status` (`complete` or `partial`, the report that
  last wrote it) and `reported_at`, which can be older than the block's,
  because an unavailable report never blanks values an earlier one read.
  Values are explicit nulls when not populated or not read. `release_date`
  is `YYYY-MM-DD`; `release_date_raw` is set only when the agent could not
  parse the firmware's date. No roster or estate list carries firmware yet
  (none carries hardware fields today).
- `kernel_drivers` (PAT-2263): the device's kernel and file-system drivers
  matched by hash against Microsoft's recommended driver block rules and
  loldrivers.io, and whether Windows enforces the vulnerable driver
  blocklist. Always present. `status` is the newest report's list status:
  `not_reported` (never sent the block: an agent older than PAT-2263, or
  macOS; `enforcement` is null, `drivers` `[]`), `unavailable` (the agent
  could not read its driver list; `enforcement` is still reported),
  `partial` or `complete`. `enforcement` is the newest report's
  (`blocklist_enforced` is `yes`, `no` or `unknown`; see PAYLOAD_SCHEMA.md
  "Kernel drivers object" for how each value is read). `lists` gives both
  sources' provenance: `status` (`succeeded`, `failed` for the latest
  attempt, `never_fetched`), `fetched_at` (the last successful fetch, kept
  through failures), `list_version` and `stale` (older than 48 hours, or
  the latest refresh failed; a failed refresh never empties a list).
  `drivers` holds listed rows (malicious first) then Unknown rows, at most
  200 (`drivers_truncated`); rows with no match are counted in `summary`
  only. Per row, `match_status` is `listed` (a reported hash equals a
  listed hash of the same kind: flat or Authenticode SHA-256, or SHA-1 only
  where the list record has no SHA-256), or `unknown` with `unknown_reason`
  `not_hashed` (the agent could not hash the file: it is missing, a reparse
  point, unreadable or over a bound) or `lists_unavailable` (no list has
  ever been fetched). File names play no part in matching. The portal must
  not render a driver with no match as safe or "not on Microsoft's list":
  Microsoft's signer and file-attribute rules are not evaluated, and a
  list can be stale. Each match carries its list's version, fetch time and
  staleness, the matching hash and its kind, and `category` (`vulnerable`,
  or `malicious` for loldrivers.io malicious-driver entries).

## GET /v1/portal/driver-findings (PAT-2263)

Every role reads. The tenant's kernel drivers whose reported hash is on
Microsoft's recommended driver block rules or loldrivers.io, one row per
(device, driver), paginated with `?limit`/`?offset` (the same
`parsePagination` convention as `/v1/portal/findings`), ordered malicious
first, then loaded, then by hostname and path.

```json
{
  "generated_at": "2026-09-29T10:00:00Z",
  "limit": 50,
  "offset": 0,
  "total": 1,
  "lists": [ ...same objects as the device view's kernel_drivers.lists... ],
  "summary": {
    "devices_reporting": 40,
    "devices_unavailable": 1,
    "devices_with_listed_drivers": 1,
    "devices_with_unhashed_drivers": 3,
    "listed_drivers": 1,
    "listed_malicious_drivers": 0,
    "blocklist_enforced": {"yes": 31, "no": 6, "unknown": 3}
  },
  "findings": [
    {
      "device_id": "…", "hostname": "WS-0142",
      "path": "C:\\Windows\\Temp\\helper.sys", "service_name": "helper", "start_type": "demand",
      "loaded": true, "version": "1.0.0.1", "sha256": "…",
      "reported_at": "2026-09-29T09:00:00Z", "first_seen_at": "2026-09-27T09:00:00Z",
      "category": "vulnerable",
      "blocklist_enforced": "no",
      "matches": [ ...same objects as the device view's matches... ]
    }
  ]
}
```

`summary` counts only devices that have sent the block
(`devices_reporting`); a device that never has is not counted as clean.
`devices_with_unhashed_drivers` is the Unknown count: those devices have at
least one driver the agent could not hash. `blocklist_enforced` counts
devices by their newest report. An empty `findings` list is "no reported
hash is on either list as fetched", never "no vulnerable driver present".

## GET /v1/portal/findings

Open CVE findings across the fleet, one row per (CVE, app, version), ordered
by CVSS descending (`cve_id`, then `app` as stable tie-breakers, so rows
don't reorder across pages). Degrades to an empty list when CVE matcher data
is absent.

**Paginated (PAT-1201):** `?limit=` (default and max 500), `?offset=` —
identical convention to `GET /v1/portal/devices` above (same `parsePagination`
helper server-side). Omitting both params returns page 1 at the default limit
(500) — this is a deliberate PAT-1201 behavior change from the earlier
unpaginated shape (which always returned the full set): pre-launch, with no
live customers depending on the old shape, defaulting to a bounded first page
is safer than re-shipping a table that had already grown to 709 rows /
646KB on one tenant. There is no search/filter query param — the portal's
CVE/app/severity search box stays client-side, scoped to whichever page is
currently loaded (Andy, 2026-08-10); the server has no server-side search to
match against.

```json
{
  "generated_at": "2026-07-02T17:00:00Z",
  "total": 709,
  "limit": 50,
  "offset": 0,
  "findings": [
    {
      "cve_id": "CVE-2026-0001",
      "severity": "critical",
      "cvss": 9.8,
      "app": "ExampleApp",
      "version": "1.2.3",
      "match_confidence": "version_confirmed",
      "fixed_version": "1.2.4",
      "devices_affected": 3,
      "devices": [
        {"device_id": "0b39cbe5-…", "hostname": "LT-0042"}
      ],
      "devices_truncated": false,
      "first_seen": "2026-12-20T04:00:00Z",
      "summary": "Heap overflow in …",
      "description_source": "nvd",
      "exploitation": {
        "status": "actively_exploited",
        "evidence": [
          {
            "cve_id": "CVE-2026-0001",
            "source": "cisa_kev",
            "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "fetched_at": "2026-07-02T01:00:08Z",
            "source_revision": "2026.07.02",
            "match_basis": "cisa_kev_catalogue:cve_id_exact"
          }
        ]
      }
    }
  ]
}
```

- `total` — the full unfiltered row count (across all pages), for building a
  pager (`page = offset / limit + 1`, `total_pages = ceil(total / limit)`,
  `has_next = offset + limit < total`). **Caveat:** if `offset` is requested
  past the last row (an empty page), `total` comes back as `0`, not the true
  count — the same quirk `GET /v1/portal/devices` and the admin CVE-findings
  endpoint already have, because the total is carried on each result row via
  `COUNT(*) OVER()` and there are no rows to carry it on. Don't request an
  `offset` beyond `total` from a previous response and expect `total` to
  still read correctly; clamp client-side instead.
- `cvss` — number or `null` (no CVSS v3 data); `severity` may be `""` when
  the feed carries none.
- `match_confidence` — `"version_confirmed"` when the installed version was
  matched directly against a known-vulnerable range, `"version_unverified"`
  when it couldn't be confirmed (not a fixed two-value enum — a third value,
  `"version_vendor_confirmed"`, also occurs from vendor security-bulletin
  confirmation; treat anything other than `"version_unverified"` as
  confirmed). Do not treat `"version_unverified"` as "the finding is
  unreliable" — only that the version match itself is unconfirmed.
- `fixed_version` — the version that resolves the CVE, `""` when unknown;
  never fabricated.
- `source`, `confidence_tier`, `install_reasons` (PAT-2023): present only
  on Homebrew findings, whose `app` reads `"<name> (Homebrew formula)"` or
  `"<token> (Homebrew cask)"`; absent for applications and the OS. `source`
  is `"homebrew_formula"` or `"homebrew_cask"`. `confidence_tier` is
  `"high"` (curated mapping, version inside an NVD range) or `"low"`
  (version not confirmable: a HEAD build, a pre-release or other version
  the comparator cannot order against the NVD bound, such as `3.0.0-rc1`,
  or no NVD range data; OpenSSL letter releases such as `1.1.1w` compare
  exactly since PAT-2044), the weakest across the aggregated
  devices. `"medium"` is reserved and never produced: only curated mappings
  match. Low-tier Homebrew rows are left out of the overview's critical and
  high attention count, so they cannot hide a confirmed CVE there. `install_reasons` lists the distinct `"on_request"`,
  `"dependency"` and `"unknown"` values across those devices.
- `mapping_basis` (PAT-2138): `"auto"` when the finding comes only from a CPE
  mapping Patched published automatically (a model chose the CPE from NVD's
  dictionary with high confidence AND the product's signer independently
  named the same vendor); absent otherwise, which means a person curated the
  mapping. Show it: an automatic finding must read as "from an automatic
  mapping", never as a curated one. If staff revoke the automatic mapping,
  the finding disappears and its lifecycle records `withdrawn`, never
  `verified_fixed`, with no notification.
- `devices_affected` — distinct device count.
- `devices` — the first `portalFindingsMaxDevices` (50) affected devices by
  hostname (falling back to serial, then device ID, when hostname is unset —
  same convention as `/v1/portal/extensions`), for linking to
  `GET /v1/portal/devices/{deviceID}`. `devices_truncated` is `true` when
  `devices_affected` exceeds that cap — same convention as
  `/v1/portal/extensions`' own `devices`/`devices_truncated` below.
- `exploitation.status` is tri-state: `actively_exploited`,
  `not_known_exploited`, or `unknown`. Only a fresh exact-CVE CISA KEV or SOFA
  match can produce `actively_exploited`; severity and CVSS are never inputs.
  `not_known_exploited` requires fresh, successfully parsed CISA KEV and SOFA
  sources and carries auditable catalogue/list-absence evidence from both. When
  either source is missing, its latest fetch failed, or it is older than 48
  hours, the result is `unknown`, `evidence` is an empty array, and
  `unavailable_reason` is respectively `source_unavailable`, `source_failed`,
  or `source_stale`. Positive evidence carries the authoritative source URL,
  retrieval time, source revision when published, and exact match basis.
  Evidence decorates only CVE IDs returned by the tenant-scoped findings query;
  it cannot introduce another tenant's finding.

## CVE assessment state (PAT-2024, extended by PAT-2028)

Additive on three existing endpoints, plus `GET /v1/portal/software`
(PAT-2028; see its own section for the estate-wide row shape). No existing
field changes meaning. A CVE finding list is only a statement about software
Patched could assess, so each endpoint now says how much of the software that
is.

Per observed product (one display name on one device), `state` is one of:

- `assessed`: a CPE mapping covers the product and the matcher has matched its
  currently installed versions. `finding_count` is the number of known CVEs
  and `last_matched_at` is when it was matched. `finding_count: 0` means no
  known CVEs for that product.
- `pending`: the product is mapped but its current versions have not been
  matched yet (queued, or waiting for the next match run). `finding_count` and
  `last_matched_at` are `null`.
- `not_assessed`: no CPE mapping covers the product, so no CVE statement can
  be made. `finding_count` and `last_matched_at` are `null`, never `0`.

PAT-2138 adds two optional fields per product, both additive:

- `mapping_basis`: present whenever the product is mapped (`assessed` or
  `pending`). `"auto"` when only automatically published mappings cover it on
  the device's platform, `"curated"` otherwise. An `assessed` product with
  `mapping_basis: "auto"` and `finding_count: 0` reads "assessed via
  automatic mapping, no known CVEs", never an unqualified "no known CVEs".
- `reason`: present only on `not_assessed`. `"mapping_under_review"` when a
  mapping proposal for the product is waiting (pending, or with staff): read
  "Not yet assessed: mapping under review". `"no_mapping"` otherwise (never
  proposed yet, rejected by staff, or NVD has no CPE for it).

`GET /v1/portal/devices/{deviceID}` adds `cve_assessment` with a `products`
list; `GET /v1/portal/devices` adds the same object per device without
`products`:

```json
"cve_assessment": {
  "state": "assessed",
  "last_matched_at": "2026-09-22T21:40:00Z",
  "finding_count": 1,
  "assessed_products": 2,
  "pending_products": 0,
  "not_assessed_products": 1,
  "products": [
    {"app": "Google Chrome", "versions": ["120.0.6099.130"], "state": "assessed",
     "last_matched_at": "2026-09-22T21:40:00Z", "finding_count": 1},
    {"app": "In-House Tool", "versions": ["3.1"], "state": "not_assessed",
     "last_matched_at": null, "finding_count": null, "reason": "mapping_under_review"}
  ]
}
```

The device object also carries `auto_mapped_products` (assessed or pending
products covered only by automatic mappings) and `under_review_products`
(not_assessed products with a waiting proposal), PAT-2138.

`finding_count` counts the product's current CVE matches, the same set
`/v1/portal/findings` and `apps_with_findings` list. A CVE that is
acknowledged or risk-accepted but still installed is still counted; its
disposition is reported by `/v1/portal/finding-lifecycle` (see "Finding
lifecycle event types" below). OS pseudo-apps
(`macOS`, `Windows`) are matched by the vendor-advisory path, not by this
change-driven path.

Device `state` is `pending` when any mapped product is pending, otherwise
`assessed` when at least one product is assessed, otherwise `not_assessed`.
Device `finding_count` is the sum over assessed products and is `null` unless
the device is `assessed`. Device `last_matched_at` is the oldest
`last_matched_at` across its assessed products (every assessed product was
matched at least that recently). Read `not_assessed_products` alongside an
assessed device with `finding_count: 0`: it is the part of the device the CVE
statement does not cover.

`GET /v1/portal/findings` adds a tenant-level `cve_assessment`:

```json
"cve_assessment": {
  "last_feed_sync_at": "2026-09-22T01:04:12Z",
  "last_full_match_at": "2026-09-22T01:09:40Z",
  "queued_observations": 0,
  "assessed_products": 180,
  "pending_products": 3,
  "not_assessed_products": 412,
  "coverage": {
    "installed_products": 107,
    "assessed_products": 41,
    "auto_mapped_products": 6,
    "under_review_products": 58,
    "not_assessed_products": 66,
    "coverage_ratio": 0.383
  }
}
```

`coverage` (PAT-2138) is the "N of M installed products assessed" figure. It
counts distinct products (each platform and normalised display name once),
not device observations, so it is not comparable with the three
per-observation counts beside it. `assessed_products` are those a CPE mapping
covers on their platform (assessed or pending in the per-device view), of
which `auto_mapped_products` rely only on automatic mappings;
`not_assessed_products` have none, of which `under_review_products` have a
waiting proposal. `coverage_ratio` is `assessed_products /
installed_products`, `null` when nothing is installed.

`last_feed_sync_at` and `last_full_match_at` are estate-wide (the CVE feed and
the full match are not per tenant) and are `null` until the first run records
them. The product counts cover every device of the tenant, not only the
returned page.

Freshness: a product change reported by an agent is queued at extraction and
matched by `patched-extractor` within one poll cycle; a published or changed
CPE mapping re-matches every active device carrying the product; a feed sync
re-matches only products whose mapping resolves to a changed CPE. The nightly
full match remains the backstop. On a database without migration 0161 the
fields degrade to `not_assessed` per device and a zero-valued tenant object.

## GET /v1/portal/unapproved-apps

The tenant's unapproved-policy apps, one row per app, each carrying the count
of devices it's currently installed on. Reuses the same
`tenant_app_policies` x `device_apps` matching the staff-side app-policy-drift
report already computes, so a customer's unapproved-app list is never out of
sync with what an operator actually configured. Degrades to an empty list
(never an error) when the tenant has no unapproved policy entries configured.

```json
{
  "generated_at": "2026-07-02T17:00:00Z",
  "total": 1,
  "apps": [
    {
      "app_name": "BitTorrentClient",
      "enforcement_tier": "app_management",
      "devices_affected": 2,
      "evidence_basis": "identifier_match",
      "identifier_matched_devices": 2,
      "name_matched_devices": 0,
      "removal_state": "not_available"
    }
  ]
}
```

- `devices_affected` — distinct device count across the tenant's estate.
- `evidence_basis` (PAT-1725) — how the aggregated device matches for this
  row were tied to the policy. Three values, no others:
  - `"identifier_match"` — every matched device was tied to the policy
    through a real identifier: `device_apps.identifier` (bundle ID / package
    ID) or `device_apps.team_id` (signing identity), never through display
    name alone.
  - `"name_match_only"` — at least one matched device was tied only by
    `lower(name) = lower(policy.name)`, with no identifier match backing it.
    **A row is only as strong as its weakest instance**: if the row has ten
    identifier-matched devices and one name-only match, the row reads
    `name_match_only`, not a mix or an average.
  - `"unknown"` — no device matched at all (`devices_affected` is `0`).
    There is no evidence to grade; this value is never a default for a row
    that did match — it only occurs when nothing did.
  - **This is identity evidence, not version evidence.** `identifier_match`
    means the platform's own matcher tied this row to a product through a
    real identifier — it says nothing about which version is installed. Do
    not render it as "version confirmed" in the portal; that phrase belongs
    to the separate, unrelated `match_confidence` field on
    `GET /v1/portal/findings` above, which is genuinely about version
    matching against a CVE range. Honest portal copy for `identifier_match`
    is closer to "product identity confirmed" or similar; `name_match_only`
    is where a "name match only, ask us to confirm first" treatment applies.
  - `identifier_matched_devices` / `name_matched_devices` — the same
    per-device split that produces `evidence_basis`, exposed for
    transparency. They sum to `devices_affected`; a device counts in
    `identifier_matched_devices` if *any* of its matching installs used a
    real identifier, so a device is never counted in both.
- `removal_state` (PAT-1726) — always `"not_available"`. PAT-1598 added a
  platform record of authorised-removal campaigns (`removal_campaigns` and
  its append-only dry-run and authorisation tables), but deliberately no
  pathway that delivers a removal to a device, and this endpoint is not fed
  from those records: there is still nothing that records a removal being
  requested of, targeted at or completed on an app the way
  `tenant_extension_removal_requests`/`_targets` do for browser extensions.
  `"not_available"` is deliberately
  distinct from `"not_requested"` (the extensions vocabulary below) — the
  latter would claim removal is a capability this app could have used and
  simply hasn't, which is false. **The portal must render `not_available`
  as "no removal pathway" or equivalent, never as "not requested" or an
  empty/blank cell that reads as the same thing as a genuinely-unrequested
  extension.**
- **`enforcement_tier` is not a removal state.** It carries the retired
  internal tier vocabulary (`report` / `app_management` / …) and must never
  be shown to customers, removal-related or otherwise — it predates the
  `assurance`/`managed` enum (PAT-1566) and is exposed here only because
  existing callers of `FetchAppPolicyDriftReport` depend on the field; it
  says nothing about whether removal has been requested, authorised, done,
  or deferred.

## GET /v1/portal/extensions

Browser extensions across the estate, one row per (extension, browser),
each carrying its PAT-826 policy approval state. Reuses the same
`device_browser_extensions` (0018) x `tenant_extension_policies` (0071)
matching rule as the staff-side estate scan, so a customer's "unapproved"
list is never out of sync with what an operator actually configured.
Degrades to an empty list when the tenant has no extension telemetry yet —
but see the fail-closed exception below, which produces an
outwardly-identical empty response for a different reason and must be told
apart via `estate_too_large`.

**PAT-1799 scope note.** This endpoint carries `version_count` (below) but
not a lifecycle-state or CVE-findings-reference field — browser extensions
have no entry in the `software_products` catalogue domain (0111) and
`device_cve_findings` is scoped to `device_apps` only, so neither concept
applies here today. Pagination is unchanged from the fixed 500-row display
cap described below; it does not follow `GET /v1/portal/findings`'s
`?limit`/`?offset` convention — see the equivalent note on
`GET /v1/portal/applications`.

**`device_id` (PAT-2156, optional, UUID).** Narrows the page to one device's
own current extensions, for the device page's Software view (Browser
extensions tab). Same tenant-validated rule as `GET /v1/portal/software`'s
`device_id` above: malformed → `400`; unknown, or another tenant's device →
`404` (the same `404` for both — never an existence oracle). With it, rows
are the (extension, browser) pairs currently installed on that device only,
carrying every existing field (`approval_state`, `risk_level`, `versions`,
`removal_state`, decision provenance, …) — `device_count` and `devices`
naturally read as that one device once the row set itself is device-scoped.
All the abuse-resistance caps above (500 rows, 50-device drill-down,
20-version display cap, the 100,000-row fail-closed source-row guard) still
apply, now scoped to the one device. `search`/pagination semantics are
unchanged (this endpoint has none — see the PAT-1799 note above). Without
`device_id`, behaviour and response bytes are unchanged from before
PAT-2156.

```json
{
  "generated_at": "2026-07-02T17:00:00Z",
  "total": 3,
  "truncated": false,
  "estate_too_large": false,
  "extensions": [
    {
      "extension_id": "cfhdojbkjhnklbpkdaibdccddilifddb",
      "name": "AdBlock Plus",
      "browser": "chrome",
      "risk_level": "elevated",
      "versions": ["3.2.1", "3.3.0"],
      "versions_truncated": false,
      "version_count": 2,
      "device_count": 5,
      "devices": [
        { "device_id": "0b39cbe5-…", "hostname": "LT-0042" }
      ],
      "devices_truncated": false,
      "approval_state": "unapproved",
      "evidence_basis": "identifier_match",
      "removal_state": "requested",
      "removal_targets_total": 5,
      "removal_targets_completed": 0,
      "decided_by": "admin@example.com",
      "decided_at": "2026-12-30T09:12:00Z",
      "justification": "Flagged by security review, ad injection risk"
    },
    {
      "extension_id": "aapocclcgogkmnckokdopfmhonfmgoek",
      "name": "Slack",
      "browser": "chrome",
      "risk_level": "normal",
      "versions": ["1.0.0"],
      "versions_truncated": false,
      "device_count": 12,
      "devices": [ { "device_id": "8e2a11f0-…", "hostname": "LT-0011" } ],
      "devices_truncated": false,
      "approval_state": "approved",
      "evidence_basis": "identifier_match",
      "removal_state": "not_requested",
      "removal_targets_total": 0,
      "removal_targets_completed": 0,
      "decided_by": "admin@example.com",
      "decided_at": "2026-11-14T11:00:00Z",
      "justification": null
    },
    {
      "extension_id": "ghijklmnopabcdefghijklmnopabcdef",
      "name": "TorrentHelper",
      "browser": "chrome",
      "risk_level": "elevated",
      "versions": ["2.0.0"],
      "versions_truncated": false,
      "device_count": 1,
      "devices": [ { "device_id": "9f4d2c11-…", "hostname": "LT-0099" } ],
      "devices_truncated": false,
      "approval_state": "unapproved",
      "evidence_basis": "identifier_match",
      "removal_state": "removal_completed",
      "removal_targets_total": 1,
      "removal_targets_completed": 1,
      "decided_by": "admin@example.com",
      "decided_at": "2026-12-20T08:30:00Z",
      "justification": "Torrent client, policy violation"
    }
  ]
}
```

The third row is the case the `"removal_completed"` bullet below warns
about: a `one_profile`-scoped removal request completed on the one
device/profile it targeted, but the extension is still installed on
`LT-0099` — a different device that either installed it after the request
was made or was never in the request's scope to begin with. `device_count:
1` and the `devices` list are the honest picture; `removal_state` alone
would misleadingly read as "done".

Abuse-resistance caps (GitHub-Non-Author-Review): one authenticated GET can never force an
unbounded aggregate or response body. Both caps are enforced inside the
SQL, before anything is buffered:

- At most **500 extension rows** per response, ordered unapproved first,
  then unreviewed, then approved, then ignored, then by `device_count`
  descending, then name — so the cap always cuts the least-important
  tail, never an unapproved extension. `total` stays the exact pre-cap
  count; `truncated` is `true` when rows were cut.
- At most **50 devices** per extension's `devices` drill-down (the first
  50 by hostname). `device_count` stays the exact distinct-device total;
  `devices_truncated` is `true` on any extension whose list was cut.
- At most **20 distinct versions** per extension's `versions` list
  (lowest-sorting first); `versions_truncated` is `true` when cut.

All aggregation into arrays/JSON happens only for rows that survive the
caps; the pre-cap pass is a streaming scalar aggregate over the tenant's
own telemetry.

**Fail-closed exception, above the source-row cap.** The pre-cap scalar
aggregate above is NOT itself bounded by the 6 MB ingestion payload cap or
per-tenant device limits — `device_browser_extensions` rows are upserted
but never deleted, so a tenant's total raw row count grows for its entire
lifetime and can organically exceed any fixed bound, with zero abuse
required. To keep this endpoint's cost bounded regardless, a cheap
`COUNT(*)` pre-check runs before the real query: if a tenant's raw
(ungrouped) `device_browser_extensions` row count exceeds an internal
100,000-row threshold, the request returns a clean `200` with `total: 0`,
`extensions: []`, `truncated: true`, and **`estate_too_large: true`**,
instead of ever running the GROUP BY.

- `estate_too_large` — `true` only in this fail-closed branch. This is the
  **only** field that distinguishes "the tenant's estate is too large to
  safely aggregate right now" from an ordinary tenant with no extension
  telemetry (both otherwise render as `total: 0`, `extensions: []`,
  `truncated: true`/`false`) — do not infer "no extensions" from an empty
  `extensions` array alone.
- This condition is **permanent** once it fires for a tenant: the
  underlying row count only grows, never shrinks, so there is no
  self-service recovery. It is logged server-side (tenant ID + observed row
  count) when it fires, since the customer-facing response can never carry
  real data in this branch.
- Previously this document (and the `truncated`/`total` fields) implied
  totals stay exact unconditionally; that is now true only below the
  source-row threshold above.

- `approval_state` — one of four values, not three. `approved`,
  `unapproved`, and `ignored` are explicit decisions recorded as a
  `tenant_extension_policies` row (admin console, PAT-826). `unreviewed`
  means **no** policy row matches this extension at all — nobody has made a
  call on it yet. This is a deliberate distinction: `unreviewed` is not the
  same thing as `approved`, and the portal must never collapse the two into
  a single "not flagged" bucket.
- Matching rule (identical to the staff-side scan endpoint,
  `GET /admin/tenants/{id}/extension-policies/scan`): a policy row applies
  when `extension_id` is equal AND (`policy.browser = 'any'` OR
  `policy.browser` equals the observed `browser`). A browser-specific row
  always wins over an `any` row for the same extension.
- **`decided_by` / `decided_at` / `justification` (PAT-1800)** — provenance
  for `approval_state`: who decided it, when, and why. Sourced from the
  matched `tenant_extension_policies` row's `approved_by` / `updated_at` /
  `notes`. All three are `null` on an `unreviewed` row — there is no policy
  row to carry them, never a fabricated value. `approved_by` and `notes`
  are `NOT NULL DEFAULT ''` on that table; an unset (empty-string) value
  reads as `null` here, not as an empty real decision. `decided_at` is
  populated whenever a policy row exists, even one nobody has edited since
  creation — the row's creation itself counts as "last decided".
- `risk_level` — `normal` or `elevated`. `elevated` when ANY install of
  the extension across the tenant's devices is classified elevated by the
  server-side permission-risk classifier (worst-case aggregation, the same
  BOOL_OR convention as the admin browser-extensions view). Values keep
  the raw `device_browser_extensions.risk_level` vocabulary, not the
  admin console's high/low remap.
- `versions` — distinct non-null versions seen across the tenant's
  devices for this (extension, browser) pair, capped at 20 (see above).
  `[]` if none reported.
- `version_count` (PAT-1799) — the exact distinct-version count this
  (extension, browser) pair was observed at, **before** the 20-version
  display cap on `versions` above. Lets the portal show "N devices on M
  versions" without under-reporting M once `versions` itself has been
  truncated; equal to `len(versions)` unless `versions_truncated` is `true`.
- `device_count` — distinct device count for this (extension, browser)
  pair, scoped to the caller's tenant.
- `devices` — one entry per device running the extension (capped at 50,
  see above), for portal drill-down. `hostname` falls back to serial,
  then device ID, in that order (same convention as the admin
  browser-extensions view). Only `device_id` and `hostname` are exposed
  here — cross-reference `GET /v1/portal/devices/{deviceID}` for anything
  more.
- `evidence_basis` (PAT-1725) — always `"identifier_match"`. Extension rows
  are grouped and matched by `extension_id`, the browser store's own
  identifier (Chrome Web Store / Firefox Add-ons ID) — never by display
  name — and ingestion rejects a row with an empty `extension_id`
  (`internal/extractor/validate.go`), so every row reaching this endpoint
  already carries a real identifier. The field exists for a uniform
  contract across both software-identity endpoints (see
  `GET /v1/portal/unapproved-apps` above), not because extensions can
  produce any other value today.
- **`removal_state` (PAT-1726)** — whether removal of this extension has
  been requested, is in progress, or the targeted scope has completed
  (which is a narrower claim than "is done" — see the
  `"removal_completed"` bullet below), derived from
  `tenant_extension_removal_requests` / `tenant_extension_removal_targets`
  (migrations 0074/0093), never from `approval_state`. Populated on every
  row so the portal has one shape to render, but it is only meaningful when
  `approval_state` is `"unapproved"` — a removal request against an
  approved/ignored/unreviewed extension would be an operator error upstream
  of this endpoint, not something this field validates or prevents. One of
  four values:
  - `"not_requested"` — no non-cancelled removal request exists for this
    (`extension_id`, `browser`) pair. This also covers a **cancelled-only**
    history (every request for this pair has been cancelled): the
    create-handler's active-request unique index means a new removal can
    always be requested again after a cancellation, so from the customer's
    point of view a cancelled request and no request ever having existed
    are the same actionable state. The distinct cancellation history stays
    visible to staff via
    `GET /admin/tenants/{id}/extension-removals?include_history=true`; the
    portal's not-wanted list does not need to distinguish it.
  - `"requested"` — at least one active (non-cancelled) removal request
    exists and zero of its captured device/user/profile targets have
    completed yet.
  - `"in_progress"` — at least one captured target has completed but not
    every one has.
  - `"removal_completed"` — every target captured by an active request's
    scope, at request time, has completed. **"Completed" here always means
    verified post-removal evidence, never absence.** A target's
    `completed_at` is written in exactly one place
    (`applyExtensionRemovalEvidence`, `internal/handlers/enforcement_audit.go`)
    and only alongside a non-null `audit_event_id` referencing a real,
    non-dry-run `extension_removed` audit event reported by the agent — the
    platform never infers removal from an extension simply no longer
    appearing in a later inventory upload (root AGENTS.md: "absence
    requires authority"). There is no code path that sets `completed_at`
    without `audit_event_id`.

    **`"removal_completed" does NOT mean the extension is gone from the
    estate.** This row exists in the response at all only because the
    extension is still present in current inventory — extension rows are
    built from `device_browser_extensions`, i.e. what devices currently
    report installed, not from historical removal jobs. So a row reading
    `"removal_completed"` is proof the extension is *still installed
    somewhere outside the completed request's scope*: outside a narrower
    `one_profile`/`one_user` request, on a device that installed it after
    the request was made, or a reinstall after the audit event. A
    genuinely fully-removed extension is never relabelled
    `"removal_completed"` — it simply stops appearing in this list on the
    next fetch, once no device reports it anymore. **The portal must not
    present `"removal_completed"` as proof the extension is gone from the
    estate on its own** — cross-reference `device_count` and `devices` on
    the same row (the remaining install(s)) and treat the audit evidence
    behind `removal_targets_completed` as the only proof, and only for the
    devices it actually covers.
  - There is no `"authorised"` or `"deferred"` value: nothing in the current
    data model records an authorisation step distinct from the request
    itself, or a deliberate deferral distinct from simply not having
    requested removal yet. Do not add either without a schema change to
    back it — inventing a value here would violate "absence requires
    authority" in the other direction, by claiming evidence that doesn't
    exist.
- `removal_targets_total` / `removal_targets_completed` — the counts behind
  `removal_state`, summed across every active (non-cancelled) removal
  request for this (`extension_id`, `browser`) pair.
  `removal_targets_completed` only counts targets with verified evidence,
  per the `"removal_completed"` bullet above. Both `0` when `removal_state`
  is `"not_requested"`.
- **Zero-target requests.** The removal-state aggregation joins
  `tenant_extension_removal_requests` to
  `tenant_extension_removal_targets` with an inner join, so a request with
  zero captured targets would not count toward `"requested"` at all. This
  is safe only because the admin create endpoint
  (`POST /admin/tenants/{id}/extension-removals`) refuses to commit a
  request whose target-capture insert affects zero rows — see
  `internal/handlers/extension_removals.go:310-314` — so no zero-target
  request can exist in the data today. If a future write path ever creates
  one, the aggregation must change to a left join and treat it as
  `"requested"`, not `"not_requested"`.

## GET /v1/portal/software

Paginated, searchable current software inventory and usage-evidence view.
This is deliberately independent of `GET /v1/portal/applications`: it reads
the current `device_apps` projection, is not policy scoped, and has **no
estate-size cap**. Tenant scope is derived only from the verified portal
identity; this endpoint accepts no tenant ID.

Query parameters use the normal portal pagination convention: `limit` is
clamped to `1..500` (default `500`), `offset` defaults to `0`, and `search`
matches product name, identifier, or a directly resolved canonical identity.
It also matches every observed display name retained in `names`, not only the
group's deterministically selected `name`.
After trimming surrounding whitespace, search is at most 256 characters. Rows sort deterministically by `name`, then
`identifier`, then `platform`; `total` is the exact count after search and
before pagination. `coverage` is intentionally for the whole tenant estate,
not merely the filtered page (see the `device_id` exception directly below),
so a narrow search cannot make collection health look better than it is.
`generated_at` is the same captured timestamp used for the freshness and
unused-horizon comparisons in that response.

**`device_id` (PAT-2156, optional, UUID).** Narrows the page to one device's
own current installations, for the device page's Software view. Validated
against the verified portal tenant before any inventory query runs:

- Malformed (not a UUID) → `400`.
- Well-formed but unknown, or a device belonging to another tenant → `404`
  — deliberately the **same** `404` for both, so this parameter can never be
  used as a cross-tenant device-existence oracle (the same rule
  `GET /v1/portal/devices/{deviceID}` already follows).
- A syntactically valid, tenant-owned device with zero installations is a
  normal `200` with `total: 0` and `products: []` — that is a legitimate
  answer, not a 404.

With `device_id` set:

- **Rows** are that device's `device_apps` rows only, grouped the same
  `(identifier, platform)` way as the unfiltered page, with every existing
  field: approval/policy identity (`team_id`/`product_key`/`policy_state`),
  `cve_assessment`, and usage/metering. `cve_assessment` is scoped to this
  device's own installed versions of the product, not rolled up across the
  whole tenant estate the way the unfiltered page's `cve_assessment` is — a
  product assessed on some other device in the tenant does not make this
  device's stale or queued installation of it read as assessed. Every
  other rule is the unfiltered page's own (one implementation, the device
  as a parameter): mappings apply per platform, automatic mappings cover
  only names with exactly their word tokens, and `mapping_basis` and
  `reason` (`mapping_under_review` / `no_mapping`) are set the same way.
- **`first_seen_on_device`** (new field, only present when `device_id` is
  set) — the earliest `device_apps.first_seen` for this product on this
  device. Cheaply available: `first_seen` is a plain column on
  `device_apps`, so this is a `MIN()` over the same grouped rows already
  being aggregated, not an extra query.
- **`coverage`** is scoped to the device (installations of *this device*
  only), not the whole tenant estate — the one exception to "coverage is
  for the whole tenant estate" above.
- `search`, `limit`, `offset` and the sort order are unchanged.

Without `device_id`, behaviour and response bytes are unchanged from before
PAT-2156.

```json
GET /v1/portal/software?device_id=042c97f3-...

{
  "generated_at": "2026-09-25T12:00:00Z",
  "total": 1,
  "limit": 500,
  "offset": 0,
  "coverage": {
    "installation_count": 1,
    "metered_installation_count": 1,
    "unmetered_installation_count": 0,
    "stale_installation_count": 0,
    "unused_installation_count": 0,
    "no_evidence_installation_count": 0
  },
  "products": [{
    "name": "Example App",
    "names": ["Example App"],
    "identifier": "com.example.app",
    "platform": "macos",
    "versions": ["2.1"],
    "unknown_version_installation_count": 0,
    "device_count": 1,
    "installation_count": 1,
    "evidence_at": "2026-09-25T11:00:00Z",
    "last_used_at": "2026-09-24T10:00:00Z",
    "metered_installation_count": 1,
    "unmetered_installation_count": 0,
    "stale_installation_count": 0,
    "unused_installation_count": 0,
    "no_evidence_installation_count": 0,
    "usage_state": "used",
    "removal_candidate": false,
    "canonical_key": null,
    "canonical_name": null,
    "team_id": null,
    "product_key": "application:macos:com.example.app",
    "policy_state": null,
    "first_seen_on_device": "2026-08-01T09:00:00Z",
    "cve_assessment": {
      "state": "assessed",
      "last_matched_at": "2026-09-25T09:00:00Z",
      "finding_count": 0
    }
  }]
}
```

```json
{
  "generated_at": "2026-09-20T12:00:00Z",
  "total": 1,
  "limit": 500,
  "offset": 0,
  "coverage": {
    "installation_count": 12,
    "metered_installation_count": 8,
    "unmetered_installation_count": 4,
    "stale_installation_count": 2,
    "unused_installation_count": 1,
    "no_evidence_installation_count": 3
  },
  "products": [{
    "name": "Example App",
    "names": ["Example App"],
    "identifier": "com.example.app",
    "platform": "macos",
    "versions": ["2.0", "2.1"],
    "unknown_version_installation_count": 0,
    "device_count": 2,
    "installation_count": 2,
    "evidence_at": "2026-09-20T11:00:00Z",
    "last_used_at": "2026-09-19T10:00:00Z",
    "metered_installation_count": 2,
    "unmetered_installation_count": 0,
    "stale_installation_count": 0,
    "unused_installation_count": 0,
    "no_evidence_installation_count": 0,
    "usage_state": "used",
    "removal_candidate": false,
    "canonical_key": "example-app",
    "canonical_name": "Example App",
    "team_id": null,
    "product_key": "application:macos:com.example.app",
    "policy_state": null,
    "cve_assessment": {
      "state": "assessed",
      "last_matched_at": "2026-09-20T09:00:00Z",
      "finding_count": 0
    }
  }]
}
```

- Grouping is exactly `(identifier, platform)`, where `platform` is
  `"macos"`, `"windows"`, or `"unknown"` when the device's reported OS cannot
  be classified. Unknown OS is never treated as macOS. `names` and `versions` retain
  every distinct observed non-empty value; `unknown_version_installation_count`
  makes absent version evidence explicit rather than silently dropping it.
  `device_count` is distinct devices; `installation_count` is current
  `device_apps` rows, so the two are deliberately not interchangeable.
- `evidence_at` is the latest current app evidence in the group. `last_used_at`
  is the latest reported use timestamp, not a claim that every installation was
  used then. `null` is preserved when no launch timestamp was observed.
- `metered_*` means `devices.metering_status = "ok"` and per-app evidence is neither `unmapped` nor `unavailable`; `unmetered_*` covers
  unavailable or unreported collection. `stale_*` means the device's metering
  evidence (`devices.last_seen`) or the app's usage receipt is older than the named 30-day
  `SoftwareMeteringEvidenceFreshness` window. These coverage dimensions can
  overlap and must not be summed as partitions. For legacy app rows without
  `usage_evidence_at`, the app's `last_seen` supplies the receipt fallback;
  a device heartbeat cannot renew that observation (PAT-2361).
- `unused_*` (PAT-2327) counts only installations with positive evidence of
  non-use: the device is fresh and `metering_status="ok"`, the device is not a
  server or domain controller (`devices.device_class`), and `last_used_at` is
  a recorded timestamp older than the 90-day unused horizon. A `null`
  `last_used_at` is never unused: it means no launch record was observed
  (background agents, services, runtimes and drivers never produce one, and
  a Windows Server rarely does), which is absence of evidence, not evidence
  of non-use. A server or domain controller is never unused, whatever its
  `last_used_at`. Unavailable/unreported metering is never unused either. PAT-2328 additionally requires fresh per-app receipt time and complete app collection on newly extracted observations. `no_record` suppresses a retained historical date, and neither partial scope nor an absent new usage reading can re-authorise non-use.
- `no_evidence_*` (PAT-2327, additive on `coverage` and on every product) counts
  fresh, `metering_status="ok"` installations that carry no usable last-use
  evidence: `last_used_at` is `null`, or the device's `device_class` is
  `server` or `domain_controller` and `last_used_at` is older than the 90-day
  horizon (server software runs as services, so an old or missing launch
  record is not a verdict). A server installation with a `last_used_at` inside
  the horizon is positive evidence of use and counts as used, like any other
  device. `no_evidence_*` is disjoint from `unused_*` and from `unmetered_*`,
  and is the metered counterpart of unmetered: nothing is known about use.
  Installations with fresh device and app evidence and complete metering split into unused, no-evidence and
  installations with a recorded use inside the horizon.
- `usage_state` is one of `used`, `unused`, `unmetered`, `mixed`, `stale`, or
  `unknown`; no new value was added for PAT-2327, so existing clients keep
  working. Any stale installation yields `stale`; a group whose installations
  are all unmetered or no-evidence yields `unmetered`; only a group of which
  every installation is positively unused yields `unused`. `mixed` retains
  partial coverage, including any mix of unused or used with unmetered or
  no-evidence installations. Read `no_evidence_installation_count` to tell
  "metered, no launch record" from "not metered" inside an `unmetered` group.
  Do not convert any of those coverage states into a usage verdict.
- `removal_candidate` is `true` only for `usage_state="unused"`, so every
  current installation is positively unused, each with a recorded last-use
  older than the horizon. It is always false for mixed, unmetered, stale, and
  unknown evidence, and so for anything on a server or domain controller
  (a server installation is at most used or no-evidence, never unused).
  The endpoint remains read-only and does not request or perform removal.
- `canonical_key` / `canonical_name` are nullable. They appear only when every
  installation in the group directly matches the same alias with
  `provenance="reviewed"`; migration and system aliases are deliberately not
  customer-facing identity authority. Alias matching is platform-scoped. A
  display name, package label, or partial match never creates identity.
- `cve_assessment` (PAT-2028) is additive: the estate-wide CVE assessment for
  this product, rolled up across every installation in the tenant, using the
  same three-state shape as "CVE assessment state" below (`state`,
  `last_matched_at`, `finding_count`) but without the per-device `products`
  list, `assessed_products`, `pending_products` or `not_assessed_products`
  fields those endpoints carry. `state` is `not_assessed` when no observed
  name in this identifier/platform group resolves to a CPE mapping anywhere
  in the tenant (`finding_count` `null`, never `0`); `pending` when the
  product is mapped and at least one installation is queued or has not been
  matched at its current version (`finding_count` still set, from the last
  completed match; `last_matched_at` `null`); `assessed` when every
  installation is current (`finding_count` the distinct-CVE count across
  every mapped installation; `last_matched_at` the OLDEST timestamp across
  them, i.e. a floor). Computed in one set-based query per page, not one
  query per product row. PAT-2138 adds `mapping_basis` (`"auto"` or
  `"curated"`, set when mapped) and `reason` (`"mapping_under_review"` or
  `"no_mapping"`, set when `not_assessed`), with the same meaning as on the
  per-device products above.
- `team_id` / `product_key` / `policy_state` (PAT-2104) are additive
  identity and governance fields, matching `PUT /v1/portal/software-approvals`
  exactly, so an inventory row can be addressed as a product just like a
  `GET /v1/portal/applications` policy row can. `team_id` is macOS-only Team
  ID identity: `null` on every `"windows"`/`"unknown"` platform product
  (never guessed from `device_apps.team_id`, which on Windows is a publisher
  name, not a signing identity), and `null` on macOS too whenever the
  group's current installations disagree on `team_id` — a disagreement is
  genuine ambiguity, not evidence to average away, so it is never guessed at
  (root AGENTS.md: "absence requires authority"). `product_key` is exactly
  the key PAT-2007's write path computes for this identity
  (`application:<platform>:<lowercased identifier>[:<team_id>]`); `null`
  for a `"unknown"`-platform product, since the write schema has no
  platform value beyond `macos`/`windows`, and also `null` on a macOS
  product whose only observed `team_id` does not have the write schema's
  required shape (10 character Apple Team ID) — `product_key` is omitted
  whenever the row cannot actually be addressed through
  `PUT /v1/portal/software-approvals`, never a key that endpoint would then
  refuse. `policy_state` is this product's
  current governance state, resolved with the identical resolver the write
  path and the PAT-2009 unapproved-software alert use
  (`apppolicy.Index.Resolve`), so it can never disagree with
  `GET /v1/portal/applications`'s `policy_state` or the alert for the same
  product: one of `"approved"`, `"unapproved"`, `"mandatory"`, `"ignored"`
  (`tenant_app_policies`'s `"unmanaged"`, relabelled to the PAT-2007
  vocabulary), or `null` when no policy resolves for this product at all
  (undecided) or the platform cannot be resolved. A non-null `product_key`
  with a `null` `policy_state` is the ordinary "known identity, no decision
  yet" case, not an error.

## GET /v1/portal/tagged-products

PAT-2015 (part of PAT-2001). The caller's software that carries a live
category tag, grouped by product. The first category is `ai_tooling`, with
subtypes `desktop_app`, `browser_extension`, `ide_extension`, `cli`,
`local_runtime` and `mcp_server`; the AI Tooling tab (PAT-2022) reads this
endpoint. Tags come from global, staff-curated match rules and product-identity
tags, applied server side on ingest and by backfill when a rule is published,
so a newly recognised product appears without an agent release or a new device
report. Tenant scope is derived only from the verified portal identity; this
endpoint accepts no tenant ID. It is read-only: approval state is read from the
existing policy tables and never written here.

Query parameters, all optional: `category` and `subtype` (lower-case keys;
anything else is `400`), `limit` `1..1000` (default `200`), `offset` (default
`0`). Rows sort by `device_count` descending, then `name`, then `product_key`.
`total` is the exact count before pagination.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "category": "ai_tooling",
  "subtype": null,
  "total": 2,
  "limit": 200,
  "offset": 0,
  "estate_too_large": false,
  "distinct_device_total": 7,
  "products": [{
    "category": "ai_tooling",
    "subtype": "desktop_app",
    "observation_kind": "app",
    "product_key": "product:0b6c2f3e-8a0e-4a53-9d1a-2f6f2b1f7c11",
    "name": "Example AI",
    "canonical_name": "Example AI",
    "vendor": "Example AI Ltd",
    "observed_publisher": null,
    "identifier": "com.example.ai",
    "browser": null,
    "platforms": ["macos"],
    "versions": ["1.4.0", "1.5.1"],
    "version_count": 2,
    "device_count": 7,
    "devices": ["7d0c...", "8e1d..."],
    "devices_truncated": false,
    "user_count": null,
    "first_seen": "2026-08-01T09:00:00Z",
    "last_seen": "2026-09-23T11:40:00Z",
    "approval_state": "unreviewed",
    "approval_target": {"type":"application","platform":"macos","identifier":"com.example.ai",
                         "team_id":null,"browser":null,"extension_id":null,"name":null,
                         "tap":null,"identity_kind":null,"source":null},
    "match_basis": ["macos_bundle_id"],
    "last_used_at": "2026-09-22T10:30:00Z",
    "metered_installation_count": 7,
    "unmetered_installation_count": 0,
    "stale_metering_installation_count": 0,
    "unknown_metering_installation_count": 0,
    "metering_state": "metered"
  }, {
    "category": "ai_tooling",
    "subtype": "browser_extension",
    "observation_kind": "browser_extension",
    "product_key": "ext:chrome:abcdefghijklmnopabcdefghijklmnop",
    "name": "Example AI Helper",
    "canonical_name": null,
    "vendor": null,
    "observed_publisher": null,
    "identifier": "abcdefghijklmnopabcdefghijklmnop",
    "browser": "chrome",
    "platforms": ["macos", "windows"],
    "versions": ["2.0"],
    "version_count": 1,
    "device_count": 3,
    "devices": ["7d0c...", "9f2e..."],
    "devices_truncated": false,
    "user_count": 4,
    "first_seen": "2026-09-02T10:00:00Z",
    "last_seen": "2026-09-23T11:40:00Z",
    "approval_state": "unapproved",
    "approval_target": {"type":"browser_extension","platform":null,"identifier":null,
                         "team_id":null,"browser":"chrome","extension_id":"abcdefghijklmnopabcdefghijklmnop",
                         "name":null,"tap":null,"identity_kind":null,"source":null},
    "match_basis": ["browser_extension"],
    "last_used_at": null,
    "metered_installation_count": 0,
    "unmetered_installation_count": 0,
    "stale_metering_installation_count": 0,
    "unknown_metering_installation_count": 0,
    "metering_state": "not_applicable"
  }]
}
```

- **Grouping.** An app groups by its normalised product (`product_key`
  `product:<uuid>`) when it resolves to one through a reviewed identity alias,
  otherwise by its observed identity on one platform (`app:<platform>:<fingerprint>`).
  A browser extension groups by browser and store ID (`ext:<browser>:<id>`),
  matching `GET /v1/portal/extensions`. `product_key` is opaque and stable;
  do not parse it. A product tagged into two subtypes appears once per subtype.
- **Presence.** Only installations currently present count
  (`software_installations.removed_at` unset). Browser extension rows are
  never deleted when an extension goes away. On a device whose agent sends
  `browser_extensions_status` (PAT-2055), an extension stops counting only
  once a complete or not_present, uncapped report for its device, or for its
  own user and browser, arrived after its `last_seen`; a partial, capped or
  failed report never hides it. On a device that has never sent that block,
  the older rule applies unchanged: an extension counts only while its
  `last_seen` is within 30 days of its device's own last report. Either way a
  device that has stopped reporting keeps its last known extensions, as its
  installations do, and hiding an extension here never retires its tag.
  (`GET /v1/portal/extensions` still counts every stored row.)
- **`device_count`** is distinct devices. **`user_count`** is the number of
  distinct OS user account names the extension was reported under. It is
  `null` for apps, because app inventory carries no per-user evidence; `null`
  never means zero. `devices` is the sorted membership list, bounded to 100;
  `devices_truncated` says that `device_count` is larger than that list.
  Top-level `distinct_device_total` is the exact union across all matching
  products before pagination, not a sum that double-counts devices.
- **`approval_target`** is either the exact item accepted by
  `PUT /v1/portal/software-approvals`, or `null`. It is null when a group has
  no decision-safe identity or contains more than one target; the API never
  guesses a target from a mixed group.
- **`first_seen` / `last_seen`** are the earliest first observation and the
  latest observation across the group.
- **Metering.** These fields apply to `desktop_app` rows only. A usage row is
  accepted only when the currently-present tagged installation's latest
  observation has the same device-local observed identifier and version as a
  current `device_apps` row. Display names, category names and product names
  are never used as a bridge. `last_used_at` is the maximum among fresh,
  `metered` (`devices.metering_status="ok"`) exact rows, so it is nullable.
  On a fully metered group a null value means no launch was recorded; on any
  other state it remains unknown and must not be read as never used.
  `metering_state` is `metered` only when every current installation is fresh
  and metered; `partial` when at least one is metered but coverage is not
  complete; `stale` when any otherwise exact usage evidence is older than 30
  days; `unmetered` when every installation reported unavailable metering; or
  `unknown` when an exact current usage record is absent. The four counts make
  that coverage explicit. Browser extensions and non-app observations use
  `not_applicable`, not an invented usage result.
- **`approval_state`** for apps uses the same resolver as the drift and
  posture surfaces over `tenant_app_policies`: `mandatory`, `approved`,
  `unapproved`, `unmanaged`, or `unreviewed` when no policy applies. For
  browser extensions it is `tenant_extension_policies`: `approved`,
  `unapproved`, `ignored` or `unreviewed`, with a browser-specific policy
  winning over `any`. `mixed` means the group's installations resolve to
  different states.
- **`match_basis`** lists what attached the tag: a rule identifier type
  (`macos_bundle_id`, `macos_team_id`, `windows_authenticode`,
  `browser_extension`, `ide_extension`, `package`, `mcp_server`, `kind`) or
  `software_product` for a tag on a normalised product identity. A
  `macos_team_id` rule always names one bundle ID as well, so it is a
  product-level match, not a vendor-wide one. `kind` (PAT-2094) is a
  kind-level rule: it matches every observation of one named observation
  kind, not one identifier value. Deliberately narrow and currently one
  rule for one kind -- every `mcp_server` observation is AI tooling by
  definition, because an MCP server is what gives an AI tool access to
  local files and systems, so no per-server-name rule can reliably catch
  it. `internal/categorytag.kindRuleKinds` is the code-level gate that
  keeps this from becoming a general "tag everything of kind X" mechanism.
- **`vendor`** and **`canonical_name`** come only from the curated product
  identity and are `null` without one. `observed_publisher` is what the
  endpoint reported and is not verified.
- **`estate_too_large`**: above 50,000 source rows the request fails closed
  with `total: 0`, empty `products` and `estate_too_large: true`, rather than
  returning a partial aggregate. It is logged server side.
- Only published rules appear; a rule still backfilling its publish does
  not. Retired rules never match. A tag whose rule is retired or edited away
  is kept as retired history and never appears here. A payload that omits a
  field such as `team_id` or `signed_by` does not remove a product; only a
  different value, or authoritative removal, does.
- Tagged observation kinds (`observation_kind`): `app`, `browser_extension`,
  and since PAT-2021 `ide_extension` (rule type `ide_extension`, qualifier
  the marketplace: `vscode_marketplace` for VS Code and Insiders, `open_vsx`
  for Cursor and Windsurf, `jetbrains_marketplace`), `package` (rule type
  `package`, qualifier `npm` or `pip`; pip covers pip user-site and pipx) and
  `mcp_server` (rule type `mcp_server`). `product_key` is
  `<observation_kind>:<platform>:<fingerprint>` without a product identity.
  Approval state for `ide_extension`, `package` and `mcp_server` is always
  `unreviewed` until PAT-2031: an app policy is never applied to them.
  Homebrew formulae and casks (PAT-2094) are tagged the same way: rule type
  `package`, qualifier `brew_formula` or `brew_cask`, `observation_kind`
  `package`. They were ingested onto this same `software_installations` seam
  from PAT-2013 (`internal/extractor/homebrew_inventory.go`) but were not
  wired to the matcher until PAT-2094; an empty subtype before that ticket
  meant "not tagged yet", not "none found" -- that gap is now closed on the
  platform side. Whether Homebrew data is live on the wire from the
  collector is a separate, agent-side flag (PAT-2021/2032); if it is still
  held off the wire, formula and cask rules simply have nothing to match
  yet, the same as any other rule with no matching observations, and start
  tagging the moment a device reports Homebrew data. Local models are never
  tagged.

## AI Tooling (PAT-2021)

Read-only views for the AI Tooling tab (PAT-2000) over the four agent blocks
`ide_extensions`, `package_managers`, `local_models` and `mcp_servers`
(PAT-2017 to PAT-2020, Windows and macOS). Tenant scope comes only from the
verified portal identity; no tenant ID is accepted. Which of these items are
AI tools is `GET /v1/portal/tagged-products` (category `ai_tooling`); these
endpoints count everything collected.

**Absence requires authority.** Each block has its own `collection_status`
per device: `complete`, `partial`, `not_present`, `failed`, or
`not_reported` (the device never sent the block). A `failed` or
`not_reported` block has `null` counts, never `0`: "could not read" is never
shown as "none". A `partial` block has `lower_bound: true`. Package sources,
model runtimes and MCP clients are units with their own status; a unit whose
newest status is `failed` has a `null` per-unit count and its last known
items are not counted anywhere. A partial report never removes an item; only
a `complete` or `not_present` unit does.

### GET /v1/portal/ai-tooling/summary

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "device_count": 40,
  "devices_with_tooling": 34,
  "collection_status": {
    "ide_extensions":   {"complete": 30, "partial": 2, "not_present": 5, "failed": 1, "not_reported": 2},
    "package_managers": {"complete": 28, "partial": 4, "not_present": 6, "failed": 0, "not_reported": 2},
    "local_models":     {"complete": 36, "partial": 0, "not_present": 0, "failed": 2, "not_reported": 2},
    "mcp_servers":      {"complete": 33, "partial": 1, "not_present": 4, "failed": 0, "not_reported": 2}
  },
  "ide_extensions": {"installed": 612, "distinct": 140, "devices": 32},
  "packages": {
    "npm_global": {"installed": 210, "distinct": 60, "devices": 25},
    "pip_user":   {"installed": 480, "distinct": 190, "devices": 12},
    "pipx":       {"installed": 35, "distinct": 30, "devices": 6}
  },
  "local_models": {
    "models": {"installed": 18, "distinct": 9, "devices": 7},
    "runtime_installations": {"installed": 9, "distinct": 2, "devices": 8},
    "total_bytes": 96000000000,
    "lower_bound_devices": 0
  },
  "mcp_servers": {"installed": 44, "distinct": 12, "devices": 15},
  "mcp_servers_by_client": {"claude_desktop": {"installed": 20, "distinct": 8, "devices": 11}},
  "vulnerability_products": [{"subject_kind":"package","ecosystem":"npm","identity":"example-package",
    "source":"npm","version":"1.2.3","state":"assessed","reason":null,"finding_count":1,
    "highest_severity":"HIGH","device_count":3,"advisory_sources":["osv"]}]
}
```

`installed` counts items per device per user (one extension in two users'
profiles is two), `distinct` counts identities (extension id and
marketplace; npm or PEP 503 package name; model `name:tag` and runtime;
MCP server name and client), `devices` counts devices with at least one.
Only devices whose block is `complete`, `partial` or `not_present` are
counted. `local_models.total_bytes` sums each counted device's newest
reported store total, blobs shared between models counted once as the agent
reports them; `lower_bound_devices` of those were `partial`.
`devices_with_tooling` is the exact distinct device count with at least one
current, authority-valid item. Failed and not-reported blocks contribute no
items and are unknown, not clean zeroes.

`vulnerability_products` is grouped by exact identity and version. npm and
PyPI are distinct ecosystems. MCP rows inherit a package assessment only when
`package_status=extracted` and the same device has an exact current package
version; unresolved MCP is `not_assessed`. Model files never appear. IDE
extensions and local runtimes require a published staff-curated exact CPE
mapping. `state=assessed` means the exact current version was checked
successfully, including `finding_count:0`; `pending` covers changed, queued,
stale or failed refreshes; `not_assessed` covers unsupported/unmapped input.
Both non-assessed states have null `finding_count` and `highest_severity`.
An assessed result older than the named 26-hour advisory freshness window is
presented as `pending` with reason `advisory_refresh_stale`, null counts and no
advisory sources until a successful refresh completes.
`advisory_sources` is `osv` or `nvd`; a GHSA/PYSEC/OSV identifier is never
presented as a CVE unless the authoritative record supplies a CVE alias.

### GET /v1/portal/ai-tooling/devices

Every tenant device, paged (`limit` default and maximum 500, `offset`),
ordered by hostname. `total` is the device count.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "total": 40, "limit": 500, "offset": 0,
  "devices": [{
    "device_id": "7d0c...",
    "hostname": "alice-mbp",
    "platform": "macos",
    "ide_extensions": {"collection_status": "complete", "units": {}, "reported_at": "2026-09-23T08:00:00Z",
                       "lower_bound": false, "item_count": 14, "items_by_unit": {}},
    "package_managers": {"collection_status": "partial",
                         "units": {"npm_global": "complete", "pip_user": "failed", "pipx": "not_present"},
                         "reported_at": "2026-09-23T08:00:00Z", "lower_bound": true, "item_count": 9,
                         "items_by_unit": {"npm_global": 9, "pip_user": null, "pipx": 0}},
    "local_models": {"collection_status": "failed", "units": {}, "reported_at": "2026-09-23T08:00:00Z",
                     "lower_bound": false, "item_count": null, "items_by_unit": {},
                     "runtime_installation_count": null, "total_bytes": null},
    "mcp_servers": {"collection_status": "not_reported", "units": {}, "reported_at": null,
                    "lower_bound": false, "item_count": null, "items_by_unit": {}},
    "vulnerability_products": [{"subject_kind":"local_runtime","ecosystem":null,"identity":"ollama",
      "source":"ollama","version":"0.1.20","state":"pending","reason":"inventory_changed",
      "finding_count":null,"highest_severity":null,"device_count":1,"advisory_sources":[]}]
  }]
}
```

`item_count` is extensions, packages, models or MCP servers. For
`local_models`, `runtime_installation_count` is the Ollama, LM Studio and
llama.cpp installations found and `total_bytes` the newest report's store
total (`null` unless the block is `complete`, `partial` or `not_present`).
Each device's `vulnerability_products` uses the same exact-version state and
nullability rules as the summary. The endpoint accepts no tenant parameter.

### GET /v1/portal/ai-tooling/devices/{deviceID}/items

Current allowlisted evidence for one tenant-owned device. Another tenant's or
an unknown device is `404`. JSON is paged with `limit` 1 to 500 (default 100)
and non-negative `offset`; `total` remains exact. `?format=csv` returns the
same builder's complete device projection and does not accept pagination.
Above 50,000 current items on that device the request fails closed with
`422 estate_too_large`.

Each item carries an opaque `item_id`, device/host/platform, block and unit,
entry kind, collection status and `lower_bound`, the named identity/source,
display name, version/publisher, observed time, policy state, an exact
`approval_target` where one exists, and type-specific allowlisted facts. Its
`assessments` are joined only through the exact current-entry key and include
state, nullable finding count/severity, advisory source/id/CVE alias and
freshness provenance. A version replacement or authoritative removal retires
the old join immediately. `partial` is a lower bound; failed/not reported is
unknown; pending, unsupported, stale or absent assessment is never presented
as clean.

In addition to the four collected developer-tooling blocks, this projection
includes every currently-present `ai_tooling/desktop_app` and
`ai_tooling/browser_extension` tag for the device. Desktop apps use the
normal installation presence lifecycle; browser extensions use the same
authoritative extension-presence rule as `GET /v1/portal/tagged-products`, so
a partial, capped or failed extension report never removes one. These rows
carry `block` `desktop_apps` or `browser_extensions`, `collection_status`
`current`, a stable opaque item ID derived from the tagged row, and the exact
server-owned application or browser-extension approval target. Desktop-app
rows additionally carry nullable `last_used_at` and `metering_state` with the
same exact-identity, freshness and unknown semantics above; browser-extension
rows say `not_applicable`. CSV is this same complete projection and includes
model `size_bytes` plus MCP `transport`, `runner`, `package` and `host` where
they are allowlisted.

Raw observation attributes and payloads are not exposed. In particular the
response and exports never include prompts, chat/output/files, credentials,
environment values, MCP arguments, paths, or raw URL query strings.

## Homebrew (PAT-2013)

Read-only macOS Homebrew views for the portal Homebrew tab (PAT-1999). Every
endpoint is tenant-scoped from the verified portal identity only and accepts
no tenant ID. Paged endpoints use the normal convention (`limit` clamped to
`1..500`, default `500`; `offset` default `0`) and echo `limit`, `offset` and
an exact `total`. `search`, where accepted, is at most 256 characters after
trimming and matches name/token or tap. A bad boolean flag or `kind` is `400`.

**What "current" means.** A device's current Homebrew list is every formula
keg, cask and tap listed since its newest `complete` or `not_present` report,
each shown from the newest report that listed it (PAT-2032). A `partial`
report only adds or refreshes entries and never removes one, because it may
have listed a formula without reading every keg; a `complete` or
`not_present` report removes everything it did not list; a `failed` report
changes nothing but the device status. A Mac that only ever reports `partial`
therefore shows every keg seen since its last complete report. So `not_present` ("this Mac has no Homebrew")
and `failed` ("we could not read it") stay distinct, and a device that has
never sent the block is `not_reported`.

**Identity.** Every formula, cask and tap carries
`identity: {kind, name, tap}` (`kind` is `homebrew_formula`, `homebrew_cask`
or `homebrew_tap`; `name` and `tap` are normalised; `tap` is `""` when the
receipt did not say). This is package-namespace identity, not a normalised
product. `third_party_tap` / `third_party` is true for any tap outside the
`homebrew/` organisation; an unknown tap is never claimed third party.

**Approval state (PAT-2058).** Formulae and casks join the software approval
model: the same resolver, the same `software_approval_decisions` audit table
and the same write endpoint (`PUT /v1/portal/software-approvals`) as
applications and browser extensions — no parallel approval store. Taps are
not approvable (PAT-2013's `homebrew_tap` identity kind is package-namespace
evidence, not a product). The drift report
(`GET /v1/portal/software/drift`) reads the same resolver, so an Unapproved
or Unreviewed Homebrew package shows there the way an application does; the
new-software report (`GET /v1/portal/software/new`) stays application-only
by design (it documents Homebrew as having its own views, above).
A cask with a live app-bundle link inherits the linked application's policy;
that app policy has precedence even if an old direct cask policy row exists.
Such a cask cannot be changed through the Homebrew item shape (`409`
`linked_app_policy`), so it is never decided twice. The Homebrew
device-detail endpoint below (`GET /v1/portal/homebrew/devices/{deviceID}`)
does **not** carry `approval_state`: it is a per-device evidence drill-down,
not the product-level approval surface.

**Marking a Homebrew package Unapproved raises no alert or notification.**
Applications and browser extensions set Unapproved through this same
endpoint can raise the `software.unapproved` email/webhook (PAT-2009) and
the tracked alert (PAT-2097); a Homebrew formula or cask never does, on
first write or later on ingest. The portal should not offer or imply an
alert for a Homebrew decision (no "notify" copy, no alert-count badge tied
to a Homebrew product). The decision is still fully audited
(`software_approval_decisions`, `GET /v1/portal/software-approvals/history`)
and still feeds the drift report and `unreviewed_count`/`unapproved_count`
above — only the alerting side is excluded. Mechanically:
`software_unapproved_episodes.policy_kind` only admits
`application`/`browser_extension` (migration 0183), so a Homebrew decision
is audited and feeds drift but never opens or resolves an alert episode.
Identity: a normalised (lower-cased, whitespace-collapsed) `name` (the
formula name or cask token) plus an optional `tap`, matching
`identity.name`/`identity.tap` above. `tap` omitted, empty, or the
package's own default tap (`homebrew/core` for a formula, `homebrew/cask`
for a cask) are all the same identity (`softwaregov.NormalizeHomebrewTap`);
any other tap is a distinct, tap-qualified identity, because a same-named
package in a third-party tap is a different package.

### GET /v1/portal/homebrew/summary

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "macos_device_count": 2,
  "devices_with_homebrew": 1,
  "device_status": {"complete": 1, "partial": 0, "not_present": 0, "failed": 1, "not_reported": 0},
  "formula_count": 3,
  "formula_on_request_count": 2,
  "formula_installation_count": 3,
  "cask_count": 1,
  "cask_installation_count": 1,
  "linked_cask_installation_count": 1,
  "tap_count": 1,
  "third_party_tap_count": 1,
  "estate_software_installation_count": 7,
  "unreviewed_count": 2, "unapproved_count": 1
}
```

`devices_with_homebrew` counts `complete` and `partial` devices. `failed` is
counted separately because a failed read does not prove Homebrew is there.
`tap_count` excludes `homebrew/core` and `homebrew/cask`.
`estate_software_installation_count` is every active application and Homebrew
package installation (taps excluded). A cask counts once, as its app, only
when its link is `reported_path` (the app was found inside that cask's own
Caskroom directory). `linked_cask_installation_count` also includes
`default_appdir` links, which are a name-based guess at `/Applications/<name>`
(PAT-2032): they are shown, but never hide the cask from the estate total.
`unreviewed_count`/`unapproved_count` (PAT-2058) count distinct current
formulae and casks together (not installations, not taps) resolved to those
two states.

### GET /v1/portal/homebrew/formulae

Query: `include_dependencies` (`true`/`false`, default `false`), `search`,
`limit`, `offset`. By default an entry installed only as a dependency is
hidden; an entry whose receipt did not say is shown. Sorted by `device_count`
descending, then name, then tap.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "total": 2, "limit": 500, "offset": 0, "include_dependencies": false,
  "formulae": [{
    "identity": {"kind": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"},
    "name": "openssl@3", "tap": "homebrew/core", "third_party_tap": false,
    "versions": ["3.5.2"], "device_count": 1, "installation_count": 1,
    "on_request_device_count": 1, "dependency_device_count": 0,
    "homepage": "https://openssl-library.org",
    "source_url": "https://github.com/openssl/openssl/releases/download/openssl-3.5.2/openssl-3.5.2.tar.gz",
    "first_seen_at": "2026-09-01T10:00:00Z", "evidence_at": "2026-09-23T11:00:00Z",
    "approval_state": "unreviewed", "product_key": "homebrew:formula:openssl@3"
  }]
}
```

`installation_count` counts kegs, so two versions on one Mac count twice.
`approval_state`/`product_key` (PAT-2058) are never null: a formula's own
(name, tap) is always a confirmed identity, unlike an application's
display-name case. `product_key` is exactly what
`PUT /v1/portal/software-approvals` computes for this identity and can be
passed straight to a write item's `name`/`tap` (or matched against
`results[].product_key` / `GET /v1/portal/software-approvals/history`).

### GET /v1/portal/homebrew/casks

Query: `search`, `limit`, `offset`.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "total": 1, "limit": 500, "offset": 0,
  "casks": [{
    "identity": {"kind": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"},
    "token": "firefox", "tap": "homebrew/cask", "third_party_tap": false,
    "versions": ["143.0"], "unknown_version_installation_count": 0,
    "device_count": 1, "installation_count": 1, "linked_app_device_count": 1,
    "app_names": ["Firefox.app"],
    "first_seen_at": "2026-09-10T08:00:00Z", "evidence_at": "2026-09-23T11:00:00Z",
    "approval_state": "unreviewed", "product_key": "homebrew:cask:firefox"
  }]
}
```

`approval_state`/`product_key` (PAT-2058): same rules as
`GET /v1/portal/homebrew/formulae` above.

`linked_app_device_count` is how many of those Macs link the cask to an
application bundle already in inventory, on either basis (see the per-device
`linked_apps` and their `link_basis`).

### GET /v1/portal/homebrew/taps

Query: `include_core` (`true`/`false`, default `false`), `limit`, `offset`.
Third-party taps sort first.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "total": 1, "limit": 500, "offset": 0, "include_core": false,
  "taps": [{
    "identity": {"kind": "homebrew_tap", "name": "acme/tools", "tap": ""},
    "name": "acme/tools", "third_party": true,
    "remote_urls": ["https://github.com/acme/homebrew-tools"],
    "device_count": 1, "first_seen_at": "2026-09-01T10:00:00Z", "evidence_at": "2026-09-23T11:00:00Z"
  }]
}
```

### GET /v1/portal/homebrew/devices

Every device that has reported a `homebrew` block, plus every macOS device
that has not (`collection_status: "not_reported"`). Sorted by hostname.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "total": 1, "limit": 500, "offset": 0,
  "devices": [{
    "device_id": "d0477a25-8856-4ba6-97fc-987f322f5a4d", "hostname": "mac-01",
    "collection_status": "complete", "truncated": false, "truncation_reason": null,
    "reported_at": "2026-09-23T11:00:00Z", "authority_at": "2026-09-23T11:00:00Z",
    "prefixes": [{"path": "/opt/homebrew", "owner": "alice", "owner_uid": 501,
                  "collection_status": "complete", "formulae": 3, "casks": 1, "taps": 2}],
    "issues": [],
    "formula_count": 3, "cask_count": 1, "tap_count": 2
  }]
}
```

### GET /v1/portal/homebrew/devices/{deviceID}

Query: `kind` (`formula`, `cask` or `tap`; omitted = all), `limit`,
`offset`. Another tenant's device, or a malformed id, is `404`. Returns
`state` (the device object above) and one page of `entries`, sorted formulae,
casks, taps, then prefix, name, version. Fields that do not apply to an
entry's kind are `null`.

```json
{
  "generated_at": "2026-09-23T12:00:00Z",
  "state": {"device_id": "...", "collection_status": "complete", "...": "..."},
  "total": 1, "kind": "cask", "limit": 500, "offset": 0,
  "entries": [{
    "kind": "cask",
    "identity": {"kind": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"},
    "prefix": "/opt/homebrew", "name": "firefox", "version": "143.0",
    "tap": "homebrew/cask", "third_party_tap": false,
    "installed_on_request": true, "installed_as_dependency": null,
    "installed_at": "2026-09-10T08:00:00Z", "runtime_dependencies": null,
    "homepage": null, "source_url": null, "opt_linked": null,
    "receipt_status": "read", "formula_file_status": null,
    "versions_on_disk": ["143.0"],
    "apps": [{"name": "Firefox.app", "path": null, "exists": null}],
    "linked_apps": [{"path": "/Applications/Firefox.app", "link_basis": "default_appdir", "app_name": "Firefox"}],
    "directory": null, "remote_url": null, "config_status": null,
    "first_seen_at": "2026-09-10T08:00:00Z", "evidence_at": "2026-09-23T11:00:00Z"
  }]
}
```

## GET /v1/portal/applications

The tenant's applications with a policy state (PAT-1727): every configured
`tenant_app_policies` row — `approved`, `unapproved`, and any other
persisted policy value — **plus** every installed application matching none
of them (`"undecided"`). This is the superset `GET /v1/portal/unapproved-apps`
above cannot provide: that endpoint only ever emits `unapproved` rows, so
today the portal has no way to show an approved application or an
undiscussed one. **`GET /v1/portal/unapproved-apps` is unchanged** and stays
live; this is a new, additive endpoint, not a replacement.

`type` is always `"application"` on every row, so the portal can render this
list in the same single table as `GET /v1/portal/extensions` (`type`
`"extension"`, by convention — the extensions endpoint does not itself carry
the field, since it has no sibling to disambiguate from yet).

**PAT-1799 scope note.** This pass adds `version_count` and the
`team_id`/`signed_by`/`notarized` signing fields (documented below). It does
**not** add a `lifecycle_state` field (from `software_products.lifecycle_state`,
PAT-1461) or a CVE-findings reference (count/severity/reference into
`GET /v1/portal/findings`) — both were scoped out of this change to avoid
rushing the identity-matching and evidence work they need to be correct; see
the follow-up ticket this change's author recommended. It also does **not**

**PAT-1728 scope note.** This pass adds `latest_known_version` and
`devices_behind_count` (documented below), populated only on policy rows
whose `policy_state` is `"approved"` or `"mandatory"` — the portal's
"Approved" group, which is what asked for a per-product behind-count.
`"unapproved"`/`"unmanaged"` policy rows and every `"undecided"` row always
carry `null` for both fields; this is a deliberate scope boundary, not a
gap to be read as "not computed yet" — undecided rows are grouped by
`device_apps.identifier`/name directly (a different grouping key from the
`tenant_app_policies` identity this comparison keys on), so extending it
there is a second, differently-shaped piece of work, not a mechanical
widening of this one.
change pagination to the `?limit`/`?offset` convention `GET /v1/portal/findings`
uses: this endpoint's undecided half is built on the same abuse-resistance
cap (`portalApplicationsMaxUndecidedRows`, hardened through several PAT-933
review rounds — see that constant's doc comment) that bounds
`GET /v1/portal/extensions`, and turning that fixed cap into a
client-controlled `offset` would let a caller force the query to scan
arbitrarily deep into attacker-influenced `device_apps` volume — reopening
exactly the cost problem those rounds closed. Retrofitting real pagination
here needs a deliberate redesign of that boundary, not a mechanical copy of
`?limit`/`?offset`.

```json
{
  "generated_at": "2026-09-13T17:00:00Z",
  "total": 3,
  "truncated": false,
  "estate_too_large": false,
  "applications": [
    {
      "type": "application",
      "name": "BitTorrentClient",
      "identifier": "",
      "policy_team_id": null,
      "product_key": null,
      "platform": "any",
      "policy_state": "unapproved",
      "enforcement_tier": "app_management",
      "device_count": 2,
      "evidence_basis": "identifier_match",
      "identifier_matched_devices": 2,
      "name_matched_devices": 0,
      "removal_state": "not_available",
      "version_count": 1,
      "team_id": null,
      "signed_by": null,
      "notarized": null,
      "latest_known_version": null,
      "devices_behind_count": null,
      "decided_by": null,
      "decided_at": "2026-08-01T10:00:00Z",
      "justification": "Torrent client, bandwidth and licensing risk"
    },
    {
      "type": "application",
      "name": "MysteryApp",
      "identifier": "com.example.mysteryapp",
      "policy_team_id": null,
      "product_key": null,
      "platform": "macos",
      "policy_state": "undecided",
      "enforcement_tier": "",
      "device_count": 5,
      "evidence_basis": "identifier_match",
      "identifier_matched_devices": 0,
      "name_matched_devices": 0,
      "removal_state": "not_available",
      "version_count": 2,
      "team_id": "ABCDE12345",
      "signed_by": "Developer ID Application: Example Inc",
      "notarized": true,
      "latest_known_version": null,
      "devices_behind_count": null,
      "decided_by": null,
      "decided_at": null,
      "justification": null
    },
    {
      "type": "application",
      "name": "Slack",
      "identifier": "com.tinyspeck.slackmacgap",
      "policy_team_id": "7QQ2SVXP7X",
      "product_key": "application:macos:com.tinyspeck.slackmacgap:7QQ2SVXP7X",
      "platform": "macos",
      "policy_state": "approved",
      "enforcement_tier": "report",
      "device_count": 40,
      "evidence_basis": "identifier_match",
      "identifier_matched_devices": 40,
      "name_matched_devices": 0,
      "removal_state": "not_available",
      "version_count": 3,
      "team_id": "7QQ2SVXP7X",
      "signed_by": "Developer ID Application: Slack Technologies, Inc.",
      "notarized": true,
      "latest_known_version": "4.40.100",
      "devices_behind_count": 6,
      "decided_by": null,
      "decided_at": "2026-10-02T09:00:00Z",
      "justification": null
    }
  ]
}
```

- **Two kinds of row, told apart by `policy_state`:**
  - **Policy rows** — one per `tenant_app_policies` row configured for the
    tenant, with the exact same device-matching `FetchAppPolicyDriftReport`
    already computes for `GET /v1/portal/unapproved-apps` (no separate
    matcher). `policy_state` is the persisted `tenant_app_policies.policy`
    value: `"mandatory"`, `"approved"`, `"unapproved"` or `"unmanaged"`.
    `enforcement_tier` carries the retired internal tier vocabulary — same
    warning as on `GET /v1/portal/unapproved-apps`: never render it to
    customers, and it says nothing about removal state.
  - **Undecided rows** — one per installed application (from `device_apps`)
    that matches **no** `tenant_app_policies` row at all, under the
    identical matching rule (name / `bundle_id` / `team_id`,
    platform-scoped). `policy_state` is `"undecided"`, `enforcement_tier` is
    `""` (there is no policy row to carry one). **An application matching an
    approved (or any other) policy never also appears as `"undecided"`** —
    the two halves of this endpoint partition the tenant's applications, they
    don't overlap. `"undecided"` is a distinct, deliberate value: it is not
    a synonym for `"approved"`, and the portal must never collapse the two
    into a single "not flagged" bucket, the same discipline
    `GET /v1/portal/extensions` already applies to `"unreviewed"`.
- `identifier` — populated on an undecided row when it was grouped by a real
  `device_apps.identifier` (see `evidence_basis` below), and (PAT-2104) on a
  policy row when that row can be round-tripped through
  `PUT /v1/portal/software-approvals` — see `policy_team_id`/`product_key`
  below for exactly which policy rows qualify. `""` on every other row: an
  undecided row grouped by name only, or a policy row the write schema
  cannot address.
- `policy_team_id` / `product_key` (PAT-2104, policy rows only) — the
  identity fields `PUT /v1/portal/software-approvals` needs to change this
  exact row again, so a customer can re-address something they previously
  approved (including to unapprove it) without the portal inventing or
  separately looking up an identity. `policy_team_id` is this row's own
  `tenant_app_policies.team_id` (macOS only; always `null` on Windows, per
  PAT-2007's rule that a Windows item carries no `team_id`). **This is a
  different field from `team_id` below**: `team_id` is signing evidence
  observed on matched devices and can be non-null even on a bundle-only
  policy that carries no `team_id` of its own — sending `team_id` back on a
  write could target the wrong row or fabricate a new one whenever the two
  diverge, which is exactly why this is a separate field. `product_key` is
  exactly the key PAT-2007's write path computes for this identity
  (`application:<platform>:<lowercased identifier>[:<team_id>]`), so a
  client already holding a `product_key` from a write response
  (`PUT /v1/portal/software-approvals`'s `results[].product_key`, or
  `GET /v1/portal/software-approvals/history`) can match it against a row
  read here. Both fields are `null` together whenever the row is
  unaddressable: a name-only policy (no `bundle_id`), a `winget_id`-keyed
  policy, an `"any"`-platform policy (the write schema has no `platform=any`
  item), or a stored `team_id` that does not have the write schema's
  required shape (10 character Apple Team ID) — a malformed `team_id` cannot
  be echoed back without failing the write's own validation, so the whole
  row is treated as unaddressable rather than half-represented. Never
  populated on an undecided row: an undecided row is not yet a governance
  decision, so there is no `tenant_app_policies` row for a write to target.
- `platform` — `"macos"`, `"windows"`, or (policy rows only) `"any"` when the
  operator scoped the policy to both. An undecided row is always grouped
  from a real device's OS, so it is always `"macos"` or `"windows"`, never
  `"any"`.
- `evidence_basis` — governs slightly different things depending on the row:
  - **Policy rows**: identical semantics to `GET /v1/portal/unapproved-apps`
    above — `"identifier_match"`, `"name_match_only"` or `"unknown"` (no
    device matched at all), with the same weakest-instance rule.
  - **Undecided rows**: `"identifier_match"` when the row was grouped by a
    real `device_apps.identifier`, `"name_match_only"` when it fell back to
    grouping by `lower(name)`. `device_apps.identifier` is written `NOT
    NULL` and non-empty is enforced at ingestion (a row with no resolved
    identifier is dropped before it reaches the table), so in practice
    almost every undecided row is `"identifier_match"`; `"name_match_only"`
    only occurs for a row written before that invariant existed. Never
    `"unknown"` — an undecided row always has at least one matching device
    by construction.
- `removal_state` — always `"not_available"` on every row, policy and
  undecided alike. Same meaning and same warning as
  `GET /v1/portal/unapproved-apps`: PAT-1598's campaign records carry no
  delivery pathway and do not feed this endpoint; never render this as
  `"not requested"`.
- `version_count` (PAT-1799) — the exact distinct-version count across the
  devices behind `device_count`, for both policy and undecided rows —
  "N devices on M versions". `0` when `device_count` is `0`.
- `team_id` / `signed_by` / `notarized` (PAT-1799) — macOS codesign signing
  state (`device_apps.team_id` / `.signer` / `.notarized`), aggregated
  across the row's matched devices. **`null` means genuinely unknown, never
  a false "unsigned" or "not notarized" verdict.** Deliberately derived
  from macOS-matched devices only: the current Windows collector never
  reports these fields at all, and `device_apps.notarized` in particular
  can hold a literal `false` for a Windows row that carried no real signal
  — a Windows-only row (and the Windows-matched share of an `"any"`-scoped
  policy row) always reads `null` on all three fields, regardless of what
  is stored underneath. When a row's matched devices disagree on
  `notarized` (a boolean, unlike `team_id`/`signed_by` which are simply the
  observed value), `true` wins over `false` — a single confirmed-notarized
  instance is reported rather than averaged away. This is identity/signing
  evidence, distinct from `evidence_basis` (which is about how the row was
  matched to a policy or grouped, not what the binary's signature says).
- `latest_known_version` / `devices_behind_count` (PAT-1728) — only ever
  non-null on a policy row with `policy_state` `"approved"` or
  `"mandatory"`; `null` on every `"unapproved"`/`"unmanaged"` policy row and
  every `"undecided"` row, always. `latest_known_version` is
  `app_catalog_entries.latest_version` for this product, matched via the
  same platform + verified_signer/name identity rule
  `GET /admin/tenants/{tenantID}/needs-attention`'s `catalog_out_of_date`
  comparison already established — `null` when no catalog entry matches
  (**not** `0`/`""` — there is no trustworthy latest version to compare
  against). `devices_behind_count` is the count of this row's matched
  devices running something older than `latest_known_version`, using real
  semantic version comparison (numeric components, left-to-right — `"9.x"`
  correctly sorts below `"10.x"`), never string comparison. Its nullability
  always matches `latest_known_version`'s: `0` is a real, confident "every
  matched device is current" answer and must stay distinguishable from
  `null` ("no catalog evidence for this product") — never conflate the two.
- **`decided_by` / `decided_at` / `justification` (PAT-1800)** — provenance
  for `policy_state`: who decided it, when, and why. All three `null` when
  there is genuinely no decision record — never fabricated. Source differs
  by row kind:
  - **Policy rows**: `decided_at` is `tenant_app_policies.updated_at`
    (`NOT NULL`, so always populated — creation counts as "last decided"
    for a row nobody has edited since). `justification` is
    `tenant_app_policies.notes`, `null` when empty. `decided_by` is
    **always `null`**: `tenant_app_policies` has no actor column at all,
    unlike `tenant_extension_policies.approved_by` on the extensions
    endpoint above — there is genuinely nobody recorded as having made
    this decision.
  - **Undecided rows**: looked up against `tenant_new_apps` (the new-app
    discovery/triage queue, `GET/PUT /admin/tenants/{id}/new-apps`) by the
    same `team_id` > `identifier` > `name` precedence this endpoint's own
    undecided-matching already uses, only when that `tenant_new_apps` row
    has a recorded decision (`decision IS NOT NULL`). This is a distinct
    triage action, not a promotion to governance policy — `policy_state`
    stays `"undecided"` regardless of whether `decided_by`/`decided_at` are
    populated. `justification` is always `null` here: `tenant_new_apps` has
    no free-text field to source it from. **Known gap**: this match does
    not replicate the extractor's Windows `winget:`-prefixed identity
    branch (`identifier_kind = 'winget'`), so a Windows undecided row whose
    `tenant_new_apps` entry was filed under a `winget:` key currently shows
    `null` provenance even though a real decision exists — a false
    negative, never a false positive (never attributed to the wrong app).
    Flagged as a follow-up, not rushed into this change.
- **Undecided-application abuse-resistance caps**, mirroring
  `GET /v1/portal/extensions`'s pattern exactly. Policy rows are **not**
  subject to any of these caps — their cardinality is bounded by how many
  policies an operator has configured, not by customer-controlled telemetry
  volume.
  - At most **500 undecided rows** per response, ordered by `device_count`
    descending, then name. `total` is the exact pre-cap count (policy row
    count + the exact undecided group count); `truncated` is `true` when
    undecided rows were cut.
  - `name` and `identifier` are truncated (SQL `LEFT()`, output projection
    only — grouping and matching always operate on the full untruncated
    value) at 256 and 128 characters respectively, the same lengths
    `GET /v1/portal/extensions` uses for its own name/ID fields.
  - **Fail-closed exception.** Before grouping, a bounded existence probe
    checks the tenant's raw (ungrouped) `device_apps` row count against an
    internal 100,000-row threshold. `device_apps` rows **are** pruned per
    device on every inventory upload (unlike
    `device_browser_extensions`, which never deletes), so this table does
    not share the extensions endpoint's unbounded-lifetime-growth problem —
    but a large legitimate estate (many devices x many installed apps) can
    still organically approach the threshold, so the same defence-in-depth
    guard applies. Above the threshold, the response returns `200` with
    `estate_too_large: true`, `truncated: true`, and the undecided section
    empty — **policy rows are still returned**, since their query path never
    touches the oversized `device_apps` aggregation. `estate_too_large` is
    the only field that distinguishes this from an ordinary tenant with zero
    undecided applications; it is logged server-side (tenant ID + observed
    row count) when it fires.
- **Ordering**: `policy_state` `"unapproved"` first, then `"undecided"`,
  then `"approved"`, then the remaining persisted policy values, then by
  `device_count` descending, then name — the same "the page's point sorts
  first" convention `GET /v1/portal/extensions` uses for `approval_state`.

## Portal roles and software approval writes (PAT-2007)

### Roles

Every portal identity has a role, `owner`, `admin` or `viewer`, read from
`portal_users.role` (migration 0181; `owner` added by 0229, PAT-1883). A new
mapping is `viewer` unless the operator sets `role`; rows that existed before
0181 were backfilled to `admin`. An identity resolved through
`tenant_email_domains` has no `portal_users` row and is always `viewer`.

| Role | May |
|---|---|
| `owner` | Everything an admin may, and manage who has access: invite people, revoke invitations, change a member's role, disable and enable a member (`/v1/portal/access`) |
| `admin` | Read everything; make the portal's writes (approval state, device decisions, schedules, enrolment credentials, Jamf setup and so on); see who has access |
| `viewer` | Read everything except what is marked admin only; generate reports that are not admin only |

**Wherever this document says "admin" or "admin only", an owner is included.**
The refusal for those routes is still `403 admin_role_required`. A route that
only an owner may use says "owner only" and refuses anyone else with
`403 owner_role_required`.

A tenant created by self-service sign-up has exactly one owner, the person
who created it. A tenant an operator created has none until the operator
designates one (`POST /admin/portal-users` with `"role": "owner"`); its admins
keep working as before. The operator can do that only while
`SELF_SERVICE_SIGNUP_ENABLED` is on: with it off the route answers `400` to
`"role": "owner"` and changes nothing, because the customer portal does not
yet treat an owner as admin-level and promoting an existing admin would take
their write screens away. An owner row that already exists is honoured
whatever the flag says. Ownership cannot be transferred or granted through
the portal.

A consumer must treat a role it does not recognise as `viewer`.

### GET /v1/portal/me

```json
{"email": "someone@example.com", "tenant_id": "<uuid>", "role": "admin"}
```

`role` is `owner`, `admin` or `viewer`. For deciding whether to show write
controls. The server re-checks the role on every write; hiding a control is
not the control. For the read-only service identity (PAT-2257) the response is
`{"email": "", "tenant_id": "<uuid>", "role": "service_readonly"}`.

### PUT /v1/portal/software-approvals

Admin only. Request (strict: unknown keys, case or Unicode-fold variants of a
key, duplicate keys and trailing content are all `400`):

```json
{
  "state": "approved | unapproved | ignored | unreviewed",
  "reason": "optional, at most 1000 characters",
  "items": [
    {"type": "application", "platform": "macos", "identifier": "com.example.App", "team_id": "ABCDE12345"},
    {"type": "application", "platform": "windows", "identifier": "Example.Tool"},
    {"type": "browser_extension", "browser": "chrome", "extension_id": "abcdefghijklmnopabcdefghijklmnop"},
    {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"},
    {"type": "homebrew_cask", "name": "firefox"},
    {"type": "observation", "identity_kind": "npm_package", "name": "@scope/tool", "source": "registry.example"}
  ]
}
```

- 1 to 500 items; each product at most once.
- Application: `platform` is `macos` or `windows`; `identifier` is the
  identifier the portal already shows (`/v1/portal/applications`
  `identifier`, `/v1/portal/software` identifier); `team_id` is macOS only.
- Browser extension: `browser` is `chrome`, `edge`, `firefox`, `safari` or
  `any`.
- Homebrew formula or cask (PAT-2058): `name` is required (the formula name
  or cask token, exactly as `GET /v1/portal/homebrew/formulae|casks`
  `identity.name`/`token` show it); `tap` is optional. `tap` omitted, `""`,
  or the package's own default tap (`homebrew/core` for a formula,
  `homebrew/cask` for a cask) address the same identity. No `platform`,
  `identifier`, `team_id`, `browser` or `extension_id` on this item shape.
- Observation (PAT-2031): `identity_kind` is exactly one of
  `ide_extension`, `npm_package`, `pip_package`, `local_model`,
  `local_model_runtime` or `mcp_server`; `name` is required and `source` is
  optional. All three form an exact, tenant-local identity. Unidentified or
  unnamed kinds are never policy targets. The tenant must have observed that
  exact identity or the write is `422 unconfirmed_identity`.
- An application needs confirmed identity. An item with no identifier is
  refused `422 name_only`; an identifier that is not a macOS bundle ID with
  its Team ID and has no curated product alias is refused
  `422 unconfirmed_identity`. A supplied `team_id` must match what this
  tenant's inventory has observed for that bundle ID, otherwise
  `422 unconfirmed_identity`. Rows the portal lists with
  `evidence_basis: "name_match_only"` are always name-only and should show no
  controls. Most Windows applications need a curated alias before they can
  be marked. A Homebrew item is never refused `name_only` (its `name` is
  already a confirmed package identity, PAT-2013); it is refused
  `422 unconfirmed_identity` when this tenant's own inventory has never
  reported that exact (name, tap) pair.
- `409 operator_managed`: an operator `mandatory` row would resolve for the
  application (the resolver's matching, not just an exact-key row). Applies
  to applications only -- Homebrew has no `mandatory` vocabulary.
  PAT-2091: an approval accepted before the app was first reported (so its
  name was not yet known) never outranks an operator `mandatory` row once
  the app appears: the product then shows `mandatory`, and later writes for
  it are refused with this code.
- `409 linked_app_policy`: a Homebrew cask has a live linked application
  bundle; change the application's policy instead.
- `409 app_control_managed`: on an App Control tenant, a Chrome, Edge,
  Firefox or `any` extension being set `unapproved`, or any state change to
  an extension the operator has blocked there (any operator-set
  `unapproved` row for it, `any` included). PAT-2089: every row this
  endpoint writes is the customer's (`source = 'portal'`) and never feeds
  the signed extension blocklist, so an extension marked `unapproved` while
  App Control was off is not enforced if App Control is switched on later,
  and the customer can still change it then. Safari is always allowed: it never
  reaches the agent blocklist. Applies to browser extensions only.
- `403 admin_role_required`: the caller is a viewer.
- Homebrew items never open or resolve an unapproved-alert episode
  (PAT-2009/2097 deliberately excludes Homebrew -- see the Homebrew section
  above); `resolved_alerts` on a Homebrew result is always `0`.
- All or nothing: one refused item and nothing is written. Refusal body:
  `{"error","message","items":[{"index","code","message"}]}`, where `index`
  is the item's position in the request.

`200` response:

```json
{
  "batch_id": "<uuid>",
  "state": "unapproved",
  "changed_count": 2,
  "warning_count": 1,
  "results": [
    {"index": 0, "type": "application", "product_key": "application:macos:com.acme.edr:ACMEEDR123",
     "previous_state": "approved", "new_state": "unapproved", "changed": true,
     "protected_warning": true, "protected": {"category": "edr", "vendor": "Acme", "product_name": "Acme EDR"}},
    {"index": 1, "type": "browser_extension", "product_key": "browser_extension:chrome:abcdefghijklmnopabcdefghijklmnop",
     "previous_state": "unreviewed", "new_state": "unapproved", "changed": true,
     "protected_warning": false, "protected": null},
    {"index": 2, "type": "homebrew_formula", "product_key": "homebrew:formula:openssl@3",
     "previous_state": "unreviewed", "new_state": "unapproved", "changed": true,
     "protected_warning": false, "protected": null, "resolved_alerts": 0}
  ]
}
```

`changed: false` means the product was already in that state; no history row
is written for it. `protected_warning` flags a protected product (PAT-1801)
set to `unapproved`; the write still succeeded, so show the warning after
the fact or confirm before sending. PAT-2088: the operator's own
`PUT /admin/tenants/{id}/app-policies` applies the same rule (warn and
allow), so the portal and the operator console no longer disagree about
whether a protected product can be Unapproved.

`resolved_alerts` is exact when the response is sent: the alerts are
resolved in the same transaction as the decision. Marking a product
`unapproved` is different since PAT-2095: the response does not wait for the
marked unapproved alert. The decision commits with its episode, and
Patched's background runner raises the alert (and its tracked alerts, and
the email) straight after, normally within seconds; a bulk mark on a large
estate can take longer. So a `GET /v1/portal/software-alerts` sent
immediately after a mark may not list the new alerts yet, and nothing in the
`200` response counts them.

Unapproved never removes, blocks or uninstalls anything. On an application
it does surface on the end user's device as the existing `unapproved_present`
notice in the macOS menu bar app and Windows tray.

**Windows publisher key (PAT-2121).** When a Windows application is set to
`approved`, the server derives the product's Authenticode publisher key from
this tenant's own stored evidence (each installation's latest observation)
and records it on the policy row. It is recorded only when there is at least
one installation and every one is Authenticode `valid`, chains to a
`microsoft` or `public` root, and yields the same key; with no evidence, an
`enterprise` root, an older agent or installations that disagree, the
approval is still written and records no key. Any other state clears it.
The key is never part of the request: `publisher_key` is not a field, so
sending it (at the top level or in an item, in any spelling) is a `400
invalid_request` like any other unknown key. Nothing in the response
changes. A key lets another trusted product from the same publisher read
`low` on the overview's new software block (see above).

### GET /v1/portal/software-approvals/history

Query: optional product filter with the same fields as a write item (`type`,
`platform`, `identifier`, `team_id`, `browser`, `extension_id`); `limit`
1 to 500 (default 100); `offset`. Unknown parameters are `400`. Newest first.

```json
{
  "product_key": "application:macos:com.example.app:ABCDE12345",
  "total": 4, "limit": 100, "offset": 0, "returned": 4,
  "decisions": [
    {"id": 12, "batch_id": "<uuid>", "product_type": "application",
     "product_key": "application:macos:com.example.app:ABCDE12345",
     "platform": "macos", "identifier": "com.example.App", "team_id": "ABCDE12345", "browser": null,
     "previous_state": "ignored", "new_state": "unreviewed", "reason": null,
     "actor_email": "admin@example.com", "protected_warning": false,
     "decided_at": "2026-09-24T10:00:00Z"}
  ]
}
```

`product_key` is `null` for the whole-tenant history. `previous_state` is the
product's own decision before the change (`unreviewed` when it had none).

### GET /v1/portal/software-approvals/history/export

Same filter, no paging. `format=json` (default; `{"generated_at",
"product_key","total","decisions"}`) or `format=csv` (header `decided_at,
actor_email,product_type,product_key,platform,identifier,team_id,browser,
previous_state,new_state,reason,protected_warning,batch_id,id`). Sent as an
attachment with `X-Patched-Export-Rows`. Over 50,000 decisions:
`413 export_too_large`.

## Device retirement and the customer device list (PAT-2135)

Customer self-service replacements for the /devices page's "Tell us it's
gone" and "Send us a device list" links: the customer records the decision,
nobody at Patched acts on their behalf. Same auth, roles and error shape as
the software approval writes above: tenant from the portal identity only;
writes are `admin` only (`403 admin_role_required`, `{"error","message"}`
body, checked in the write transaction); reads are open to every role;
request bodies are strict JSON (unknown, case-variant or duplicate keys and
trailing content are `400 invalid_request`). A device outside the caller's
tenant is `404 not_found`, the same as one that does not exist. Nothing the
operator admin API does is recorded as a customer decision: the operator's
device dispositions (PAT-1825) and device uploads (PAT-1595) are separate
records that these endpoints neither read nor write.

### PUT /v1/portal/devices/{deviceID}/retirement

Admin only. `{"retired": true | false, "reason": "optional, at most 500
characters"}`. `retired` is required. The reason is trimmed; line breaks and
tabs are allowed, other control characters are `400`.

`200`:

```json
{"device_id": "<uuid>", "retired": true, "changed": true,
 "retirement": {"retired_at": "2026-09-25T10:00:00Z", "retired_by": "admin@example.com",
                "reason": "Written off after theft", "reported_after_retirement": false}}
```

- Setting the state the device is already in is a no-op: `200`,
  `changed: false`, nothing recorded (`retirement` shows the existing one).
- Every change is one append-only row (who, when, why). Unretiring
  (`retired: false`) records a new row; the retirement is never edited or
  deleted, and `retirement` becomes `null`.
- Writes for one device are serialised, so two concurrent retires record
  one decision.
- Retiring does not remove the device from the roster, does not change its
  findings and does not act on the device. A retired device that reports
  again stays retired, with `reported_after_retirement: true`.

Where a retired device is counted differently: `/overview`
`devices_retired` and `oldest_successful_ingest`; the software governance
`coverage` block (`/software/new`, `/software/drift`, the overview's
`new_software.coverage`, the new software notification) and the software governance report
PDF; the portal report PDF's "Devices not reporting" section and device
roster ("(retired)"); and the stale endpoints report, which lists retired
devices in their own section instead of as stale.

### GET /v1/portal/devices/{deviceID}/retirement/history

Every role. `limit` 1 to 500 (default 100), `offset`; other parameters are
`400`. Newest first.

```json
{"device_id": "<uuid>", "retirement": null,
 "total": 2, "limit": 100, "offset": 0, "returned": 2,
 "decisions": [
   {"id": 8, "action": "unretire", "reason": "Found it", "actor_email": "admin@example.com",
    "decided_at": "2026-09-26T09:00:00Z"},
   {"id": 5, "action": "retire", "reason": null, "actor_email": "admin@example.com",
    "decided_at": "2026-09-25T10:00:00Z"}
 ]}
```

### PUT /v1/portal/device-list

Admin only. The portal parses the customer's CSV and sends JSON; the
platform validates and stores it. Replaces the tenant's current list
wholesale; earlier uploads are kept as history.

```json
{"filename": "estate.csv",
 "entries": [{"hostname": "DESKTOP-ROBWIN", "serial": null},
             {"hostname": "alice-mbp", "serial": "C02XL0GTJGH5"},
             {"serial": "PF3ABCDE"}]}
```

- `entries`: 1 to 10,000. Each needs a `hostname` unless it has a `serial`;
  both are trimmed, at most 255 characters, valid UTF-8, no control
  characters (tab, CR and LF included). An empty `serial` is no serial.
  Entries that normalise to the same hostname and serial collapse into one.
- `filename`: optional, same field rules; empty is `null`.
- Body at most 2 MiB (`413 body_too_large`).
- Errors (`400`): `invalid_request` (malformed body, `entries` missing),
  `empty_list` (clearing is `DELETE`, so an empty upload is never taken as
  "clear"), `too_many_entries`, `invalid_filename`, and `invalid_entry` for
  the first bad row: `{"error": "invalid_entry", "message":
  "entries[12]: hostname contains control characters", "items": [{"index":
  12, "code": "invalid_hostname | invalid_serial | missing_identifier",
  "message": "..."}]}`. Nothing is stored on any error.

`200`: `{"list": {"uploaded_at", "uploaded_by", "filename", "entry_count"},
"received_count": 3, "duplicates_collapsed": 0}` (`entry_count` is after
duplicates collapse).

### DELETE /v1/portal/device-list

Admin only. Clears the list. Recorded, not erased: the history keeps the
previous list and who cleared it. `200` `{"changed": true, "cleared":
{"cleared_at", "cleared_by"}}`; with no current list, `{"changed": false,
"cleared": null}`.

### DELETE /v1/portal/device-list/entries/{entryID} (PAT-2271)

Admin only. Removes exactly one entry from the tenant's *current* list
(the latest upload, when it is not cleared) and records the deletion —
same role requirement, per-tenant write lock and CSRF/auth pattern
(the `portalauth` middleware on the whole `/v1/portal` group) as the bulk
`DELETE` above, audited the same way: an append-only
`device_list_entry_deletions` row naming the entry, its position, hostname,
serial, the actor and the time. `200 {"deleted": true, "entry_id": 42}`.
`entryID` is `entry_id` from a `GET` response's `matched` or
`on_list_never_seen` row (below) — stable across reads of the same upload,
never reused across uploads. `404 not_found` for an unknown `entry_id`, one
from another tenant, one from a superseded (replaced) upload, or when there
is no current list at all (never uploaded, or cleared) — all
indistinguishable from an entry that never existed. Non-admin roles are
refused exactly like the bulk clear (`403 admin_role_required`).

### GET /v1/portal/device-list

Every role. The current list reconciled against the devices Patched has
seen.

```json
{
  "generated_at": "2026-09-25T12:00:00Z",
  "list": {"uploaded_at": "2026-09-25T10:00:00Z", "uploaded_by": "admin@example.com",
           "filename": "estate.csv", "entry_count": 3},
  "cleared": null,
  "match_basis": "serial_then_hostname",
  "matched_count": 2,
  "matched_retired_count": 0,
  "matched": [
    {"entry_id": 101, "index": 0, "hostname": "alice-mbp", "serial": "C02XL0GTJGH5",
     "device": {"device_id": "<uuid>", "hostname": "alice-mbp", "serial": "C02XL0GTJGH5", "retired": false}},
    {"entry_id": 102, "index": 1, "hostname": "DESKTOP-ROBWIN", "serial": null,
     "device": {"device_id": "<uuid>", "hostname": "desktop-robwin", "serial": null, "retired": true}}
  ],
  "on_list_never_seen": [{"entry_id": 103, "index": 2, "hostname": null, "serial": "PF3ABCDE"}],
  "on_list_never_seen_total": 1,
  "seen_not_on_list": [{"device_id": "<uuid>", "hostname": "build-07", "serial": "C02ZZZ"}],
  "seen_not_on_list_total": 1,
  "limit": 500,
  "truncated": false,
  "on_list_never_seen_truncated": false,
  "seen_not_on_list_truncated": false
}
```

- `list` is `null` before any upload and after a clear; `cleared` then says
  who cleared it (or is `null` too). With no list, all three arrays are
  empty and the counts are `0`.
- Matching, per entry and device:
  - Serials are trimmed and upper cased (`devices.serial`, the serial the
    device detail's `identity.serial` shows). A placeholder serial counts as
    no serial, on both sides: empty, `To be filled by O.E.M.`, `Default
    string`, `System Serial Number`, `None`, `N/A`, `Not Specified`, `Not
    Applicable`, `0`, `123456789`, any single character repeated (all zeros
    included), or under 4 characters after trimming (case-insensitive). An
    entry whose only identifier is a placeholder serial is refused as
    `missing_identifier`.
  - When both carry a real serial, they match only if the serials are
    equal; the hostname is not consulted.
  - Otherwise they match on hostname: trimmed, lower case, trailing dots
    removed, then a trailing `.local` removed. So a Windows NetBIOS name in
    any case matches (`DESKTOP-ROBWIN`, `desktop-robwin`), as does
    `mac-01.local` for `mac-01`.
  - Last, an entry and a device both still unmatched, where exactly one of
    the two hostnames contains a dot, match on the first DNS label
    (`pc01.corp.example.com` and `pc01`), but only when that label belongs
    to exactly one unmatched entry and exactly one unmatched device. A
    collision (two devices `pc01.a.example.com` and `pc01.b.example.com`
    against `pc01`) leaves every party unmatched. Two fully qualified names
    never match this way (`pc01.a.example.com` is not `pc01.b.example.com`),
    and two different real serials still rule a pair out. `match_basis`
    stays `serial_then_hostname`.
- `matched` (PAT-2271): one row per entry that matched a device, always
  exactly `matched_count` long — unlike the two arrays below, it is never
  capped or truncated. Each row is the entry (same shape as
  `on_list_never_seen`, plus `entry_id`) plus the `device` it matched
  (`device_id`, `hostname`, `serial`, and `retired`). When an entry's
  candidates span more than one device, a live device is reported over a
  retired one, matching the live/retired split `matched_retired_count`
  already makes; otherwise the first candidate. A device appears here with
  `retired: true` exactly when it counted toward
  `matched_retired_count`.
- `on_list_never_seen`: entries matching no device, in upload order, `index`
  being the entry's position in the upload. Patched does not treat this as
  proof the device is missing, only as a device it has not seen.
- `seen_not_on_list`: devices no entry matches, sorted by hostname. Retired
  devices are left out; an entry matching a retired device counts as
  matched (`matched_retired_count` says how many matched only retired
  devices).
- `entry_id` (PAT-2271): every `matched` and `on_list_never_seen` row
  carries the stable id of the uploaded entry behind it (`device_list_entries.id`),
  for `DELETE /v1/portal/device-list/entries/{entryID}` above. It is stable
  across repeated reads of the same upload and never reused; a fresh upload
  gives every entry a new id. `seen_not_on_list` rows have no underlying
  entry to delete — target those by `device_id` through the device
  endpoints instead.
- `on_list_never_seen` and `seen_not_on_list` are each capped at 500 rows;
  the `_total` fields give the full count and `truncated` (or the
  per-array flag) says when a cap applied. `matched` is never capped (see
  above).

## Software governance reporting (PAT-2009)

Three reads over the same tenant-scoped data, each available as JSON
(default) or `?format=csv`. Unknown query parameters are refused with 400, so
a typo never silently changes the window. Product rows carry the PAT-2007
`product_key` and item fields (`type`, `platform`, `identifier`, `team_id`, or
`browser`, `extension_id`), so a row can be passed straight back to
`PUT /v1/portal/software-approvals`.

Presence comes from the current inventory (`device_apps`,
`device_browser_extensions`, and -- for drift and approved, PAT-2058 --
current Homebrew formulae/casks, `homebrew_current_entries`). Approval state
is resolved per device with the same resolver as the drift, posture and
finding-lifecycle surfaces, so a product never reads Unapproved here and
Approved elsewhere. States are PAT-2007's: `approved`, `unapproved`,
`unreviewed`, `ignored`, `mandatory` (Homebrew never resolves to
`mandatory`: PAT-2058 has no such vocabulary for it).
A product resolving to different states on different devices counts once, at
its worst state (unapproved, then unreviewed, mandatory, approved, ignored).
`GET /v1/portal/software/new` stays application-only (below); drift and
approved include Homebrew.

Every response carries `coverage`:

```json
{ "devices_total": 12, "devices_reporting": 10, "devices_stale": 1,
  "devices_retired": 1, "devices_without_inventory": 0,
  "oldest_device_last_seen": "2026-09-01T09:00:00Z",
  "stale_after_days": 14, "complete": false }
```

`complete` is false whenever a device is stale (no report for 14 days) or has
reported no applications. A device the customer has retired (PAT-2135) is
counted in `devices_retired` instead: it is not stale, not without
inventory and does not set `oldest_device_last_seen`, so it never holds
`complete` false. `devices_total` = `devices_reporting` + `devices_stale` +
`devices_retired`. `complete` is false when every device is retired. The portal must not present "nothing new" or
"nothing unapproved" as an estate-wide fact when `complete` is false. Each
device in a list also carries its own `last_seen` and `stale`.

A tenant whose current inventory exceeds the load cap (250,000 rows) gets
422 `{"error":"estate_too_large"}`, never a partial answer.

### GET /v1/portal/software/new

Products first seen on the tenant within a window. "First seen" is the
earliest `software_installations.first_seen_at` for the product across every
device, including installations since removed, so software that was
installed, removed and installed again is not new. Application identity
kinds only; Homebrew and developer tooling have their own views.

Query: `since` (optional), RFC 3339 or `YYYY-MM-DD` (midnight UTC). Without
it the window starts at the tenant's last review: the most recent approval
decision any customer user recorded (`software_approval_decisions`).

```json
{
  "generated_at": "2026-09-24T12:00:00Z",
  "since": "2026-09-20T10:15:00Z",
  "since_basis": "last_review",
  "until": "2026-09-24T12:00:00Z",
  "last_review_at": "2026-09-20T10:15:00Z",
  "coverage": { "...": "as above" },
  "total": 1,
  "truncated": false,
  "products": [
    {
      "name": "New Tool", "platform": "windows", "identifier": "vendor.newtool",
      "identity_basis": "identifier", "product_key": "application:windows:vendor.newtool",
      "approval_state": "unreviewed", "first_seen_at": "2026-09-23T08:00:00Z",
      "device_count": 1,
      "first_device": { "device_id": "…", "hostname": "win-01",
                        "first_seen_at": "2026-09-23T08:00:00Z", "still_installed": true }
    }
  ]
}
```

- `since_basis`: `query` (the caller's date), `last_review`, or `no_review`
  (no decision was ever recorded, `since` is `null`, and every product the
  estate has reported is listed). The window is `since` exclusive to `until`
  inclusive.
- `identity_basis`: `identifier`, or `name_only` when the endpoint reported no
  identifier. A name-only product has `product_key: null` and cannot be given
  an approval decision (PAT-2007 refuses it).
- `device_count` is devices with the product installed now; `first_device`
  is where it was first seen, even if since removed (`still_installed`).
- Newest first, at most 1000 products; `truncated` says when that bound.
  PAT-2093 put urgency on the overview's `new_software` block instead (see
  "New software by urgency"); this endpoint is unchanged.

CSV columns: `first_seen_at, name, platform, identifier, team_id,
identity_basis, product_key, approval_state, device_count,
first_device_hostname, first_device_id, first_device_still_installed, since,
since_basis`.

### GET /v1/portal/software/drift

Installed products that are Unapproved or Unreviewed, the 26-week trend, the
devices with the most Unapproved software, and the Unapproved-present list.

```json
{
  "generated_at": "2026-09-24T12:00:00Z",
  "coverage": { "...": "as above" },
  "counts": { "installed_products": 42, "unapproved": 2, "unreviewed": 17, "approved": 20,
              "ignored": 3, "mandatory": 0, "unapproved_devices": 3 },
  "products": [
    { "type": "application", "product_key": "…", "name": "Bad App", "platform": "macos",
      "identifier": "com.example.bad", "team_id": "ABCDE12345", "approval_state": "unapproved",
      "device_count": 2, "stale_device_count": 1, "observed_since": "2026-09-01T09:00:00Z" },
    { "type": "homebrew_formula", "product_key": "homebrew:formula:openssl@3", "name": "openssl@3",
      "platform": "macos", "identifier": "openssl@3", "tap": "", "approval_state": "unapproved",
      "device_count": 1, "stale_device_count": 0, "observed_since": "2026-09-10T08:00:00Z" }
  ],
  "products_total": 19,
  "products_truncated": false,
  "trend": [
    { "week_start": "2026-10-06", "recorded": false, "live": false, "unapproved_products": null,
      "unreviewed_products": null, "unapproved_devices": null, "installed_products": null, "devices_stale": null },
    { "week_start": "2026-09-21", "recorded": true, "live": true, "unapproved_products": 2,
      "unreviewed_products": 17, "unapproved_devices": 3, "installed_products": 42, "devices_stale": 1 }
  ],
  "top_devices": [
    { "device_id": "…", "hostname": "mac-01", "platform": "macos", "unapproved_product_count": 2,
      "unapproved_products": ["Bad App", "Worse App"], "last_seen": "…", "stale": false }
  ],
  "unapproved_present": [
    { "type": "application", "product_key": "…", "name": "Bad App", "platform": "macos",
      "identifier": "com.example.bad", "team_id": "ABCDE12345",
      "policy_kind": "application", "policy_id": 42,
      "device_count": 2, "stale_device_count": 1,
      "devices": [ { "device_id": "…", "hostname": "mac-01", "platform": "macos",
                     "observed_since": "…", "last_seen": "…", "stale": false } ],
      "marked_by": "admin@customer.example", "marked_via": "portal",
      "marked_at": "2026-09-20T10:15:00Z", "marked_at_basis": "decision",
      "present_since": "2026-09-01T09:00:00Z", "since": "2026-09-20T10:15:00Z" }
  ]
}
```

- `products` lists Unapproved first, then by device count, at most 2000
  (`products_truncated`). The CSV is uncapped.
- `trend` is always 26 points, oldest first, weeks starting Monday (UTC). The
  current week is computed live (`live: true`). Earlier weeks come from
  captures Patched records daily from PAT-2009 onwards; a week with no
  capture has `recorded: false` and `null` counts. It is unknown, not zero.
  Old weeks are never re-derived from today's decisions, which would rewrite
  history each time a product is approved.
- `top_devices`: at most 10, by distinct Unapproved products, with up to five
  product names.
- `unapproved_present`: every Unapproved product on at least one device.
  `marked_via` is `portal` (a customer admin, `marked_by` is their email),
  `operator` (the Patched admin API, `marked_by` null) or `unknown` (no
  recorded decision: `marked_at` is then the policy row's last update,
  `marked_at_basis: "policy_last_updated"`). `present_since` is the earliest
  `observed_since` across its devices; `since` is the later of `marked_at` and
  `present_since`.

CSV: one row per Unapproved or Unreviewed product: `approval_state, name,
type, platform, identifier, team_id, browser, extension_id, product_key,
device_count, stale_device_count, observed_since, unapproved_since,
marked_by, marked_via` (the last three only on Unapproved rows).

### GET /v1/portal/software/approved

Every Approved application, browser extension and (PAT-2058) Homebrew
formula/cask policy, with who approved it and when.

```json
{
  "generated_at": "…",
  "total": 3,
  "products": [
    { "type": "application", "policy_id": 26, "product_key": "application:macos:com.example.good:ABCDE12345",
      "name": "Good App", "platform": "macos", "identifier": "com.example.good", "team_id": "ABCDE12345",
      "approved_by": "admin@customer.example", "approved_via": "portal",
      "approved_at": "2026-09-20T10:15:00Z", "approved_at_basis": "decision", "justification": null },
    { "type": "application", "policy_id": 28, "product_key": null, "name": "Licensed Tool",
      "platform": "any", "match_name": "Licensed Tool", "approved_by": null, "approved_via": "operator",
      "approved_at": "2026-08-01T09:00:00Z", "approved_at_basis": "policy_last_updated", "justification": "licensed" },
    { "type": "homebrew_cask", "policy_id": 5, "product_key": "homebrew:cask:firefox",
      "name": "firefox", "platform": "macos", "identifier": "firefox",
      "approved_by": "admin@customer.example", "approved_via": "portal",
      "approved_at": "2026-09-23T09:00:00Z", "approved_at_basis": "decision", "justification": null }
  ]
}
```

Homebrew rows carry the same `approved_by`/`approved_via`/`approved_at`
rules as applications above; `tenant_homebrew_policies` has no actor column
either, so an operator-set Homebrew approval (there is no operator write
path for it today, but the shape is ready) would show `approved_by: null`
the same way.

- `approved_via: "portal"` when the latest PAT-2007 decision for the product
  key set it Approved; `approved_by` and `approved_at` are that decision.
- Otherwise `approved_via: "operator"`: the operator admin API records no
  actor for applications, so `approved_by` is `null` (for an extension it is
  the row's own `approved_by` when set), and `approved_at` is the policy
  row's last update, which may be later than the original approval.
- Operator rows keyed by name, Winget ID or Team ID alone have
  `product_key: null` and show the match in `match_name`, `winget_id` or
  `team_id`.
- Every tenant starts with the Patched agent pre-approved (PAT-1318); those
  rows appear here too.

CSV columns: `name, type, platform, identifier, team_id, winget_id,
match_name, browser, extension_id, product_key, approved_by, approved_via,
approved_at, approved_at_basis, justification, policy_id, declaration_id,
source, identity_state, observation_state, observed_installation_count,
effective_approval_state, publisher, min_version, review_date,
outside_constraint_count, unknown_version_count`. Text cells a
spreadsheet would read as a formula are prefixed with `'`.

Declared software (PAT-2393, "Software declarations" below) appears in this
list whether or not anything is installed:

- Every row carries `source` (`portal` or `operator`, the same value as
  `approved_via`) and the three counts (`0` for a row with no declaration).
- A declaration that is not yet matched to a product is its own row:
  `policy_id: 0`, `product_key: null`, no identifier, `identity_state:
  "unmatched"`, `observation_state: "not_observed"`,
  `observed_installation_count: 0`, `approved_at_basis: "declaration"`, with
  `approved_by`, `approved_at` and `justification` from the declaration. It
  matches no installation and approves nothing.
- A matched declaration is not a second row. Its policy row is the single
  authority and keeps its own `approved_by`, `approved_at`, `justification`
  and `min_version`; it gains `declaration_id`, `publisher`, `review_date`,
  `identity_state`, `observation_state`, `effective_approval_state` and the
  counts. If the policy is later set to anything but Approved, or removed, the
  row leaves this list; the declaration and its history remain readable.

### Software declarations (PAT-2393)

A tenant admin can record software as approved before any endpoint reports
it. A declaration is governance intent. It is not an observation and not
evidence that the software is installed, trusted or compliant, and it never
suppresses or changes a vulnerability finding or an installation count. It
lives apart from observed installations and from the legacy deployment
catalogue.

Reads are open to every portal role, including the read-only service identity.
Writes are admin only: the role and the tenant's live state are re-read from
the database inside the write transaction, so a still-valid token cannot keep
a role or tenant it has lost (`403 admin_role_required`). The tenant always
comes from the verified identity. Unknown query parameters and unknown,
duplicate or case-variant body keys are `400`, so a request cannot name a
tenant, actor, publisher key, Team ID, count or state. A declaration id that
belongs to another tenant answers exactly as one that does not exist: `404`.

| Route | Roles | Purpose |
| --- | --- | --- |
| `GET /v1/portal/software-products?platform=&query=` | all | Curated products a declaration can be matched to |
| `GET /v1/portal/software-declarations` | all | `{"declarations": [...], "total": n}`, oldest first |
| `POST /v1/portal/software-declarations` | admin | Create; `201` with the declaration |
| `GET /v1/portal/software-declarations/{id}` | all | One declaration |
| `POST /v1/portal/software-declarations/{id}/resolve` | admin | Match to a curated identity; `200` with the declaration |
| `GET /v1/portal/software-declarations/{id}/history` | all | `{"decisions": [...], "total": n}`, oldest first |

`GET /v1/portal/software-products`: `platform` is required (`macos` or
`windows`), `query` is an optional case-insensitive substring of the product
or vendor name (at most 128 characters). Returns at most 50 `products`
(`alias_id`, `product_id`, `canonical_name`, `vendor_name`, `platform`,
`identity_kind`, `identity_value_normalized`, `companion_value_normalized`),
`total` and `has_more`. Only identities a declaration can be resolved to are
listed: an active product, a reviewed alias of exact or high confidence that
Patched has not since withdrawn, and
either a macOS bundle ID with its Team ID or a Windows identifier with its
registry publisher. A display name is never an identity.

Create body:

```json
{ "name": "Example Editor", "publisher": "Example Ltd", "platform": "macos",
  "justification": "Approved for the design team",
  "alias_id": "<uuid, optional>", "min_version": "2.0", "review_date": "2027-01-31" }
```

`name` and `publisher` are 1 to 256 characters, `justification` 1 to 1000, none
with control characters. `platform` is `macos` or `windows`. `min_version` is
optional and numeric dotted (`^[0-9]{1,9}(\.[0-9]{1,9}){0,7}$`). `review_date`
is an optional real calendar date, `YYYY-MM-DD`; it is governance metadata and
changes no state. A tenant holds at most 1000 declarations (`409
declaration_limit`).

- Without `alias_id` the declaration is manual: `identity_state: "unmatched"`.
  It creates no policy row, matches nothing by name and approves nothing. A
  second manual declaration with the same platform, name and publisher
  (ignoring case and surrounding space) is `409 duplicate_declaration`; the
  same name with a different publisher is a separate declaration.
- With `alias_id` on macOS, the curated bundle ID and Team ID are an exact
  identity, so the declaration is matched at once: an ordinary Approved row is
  written to the existing policy store with `source: "portal"` and the
  declared `min_version`, and the approval decision history records it.
- With `alias_id` on Windows the declaration stays unmatched. A registry or
  display publisher is not signer proof, so it needs the explicit resolve step
  and observed Authenticode evidence.
- `alias_id` must be an active, reviewed, exact or high confidence identity on
  the same platform, otherwise `422 unverified_identity`. One declaration per
  tenant per curated identity: a second is `409 duplicate_declaration`. If the
  identity already has an authored policy row, or an operator mandatory row
  resolves for it, the request is `409 existing_policy` and nothing changes.

Resolve body: `{"alias_id": "<uuid>", "justification": "…"}`.

- `409 already_resolved` if the declaration is already matched, `422
  unverified_identity` if the alias is not a resolvable identity on the
  declaration's platform, `409` if another declaration or policy holds it.
- Windows additionally needs evidence, or `422 unverified_signing_identity`:
  at least one current installation of the identifier, and every current
  installation of it must be the selected curated identity, validly signed,
  chaining to a Microsoft or public root, with one and the same signer. That
  Authenticode publisher key is derived from the tenant's own observations
  and pinned on the declaration. Unsigned, missing, mismatched or conflicting
  evidence refuses the resolution; it is not approved and then suspended.
- Concurrent writes on one tenant are serialised, so two resolves of one
  declaration, or two declarations racing for one identity, produce exactly
  one success and `409` for the rest.

Declaration object:

```json
{ "id": "<uuid>", "name": "Example Editor", "publisher": "Example Ltd", "platform": "windows",
  "justification": "Approved for the design team", "min_version": "2.0", "review_date": "2027-01-31",
  "selected_alias_id": "<uuid>|null", "resolved_alias_id": "<uuid>|null", "policy_id": 41,
  "identifier": "example.editor", "identity_kind": "windows_native_publisher", "identity_companion": "example ltd",
  "created_by": "admin@customer.example", "created_at": "…", "resolved_at": "…|null",
  "approval_state": "approved", "identity_state": "matched", "observation_state": "observed",
  "effective_approval_state": "active", "source": "portal",
  "observed_installation_count": 3, "outside_constraint_count": 1, "unknown_version_count": 0 }
```

- `identity_state`: `matched` once resolved to a curated identity that is
  still active and reviewed, otherwise `unmatched`. If Patched withdraws the
  curated identity after a declaration resolved to it, the declaration reads
  `unmatched` again and its approval has no effect; the declaration, its
  policy row and its history are kept, and it is `matched` again, with no
  action needed, if the identity is reinstated.
- `approval_state`: the linked policy row's state once matched (`approved`,
  `unapproved`, `ignored`, `mandatory`), so an operator's later change shows
  here; `unreviewed` if that policy row has been removed; `approved` (declared
  intent only) while unmatched. `min_version` likewise follows the policy row
  once linked.
- `effective_approval_state`: `unmatched`, `active`, or `suspended`. A matched
  Windows approval is `suspended`, and every policy reader treats the product
  as if the approval were absent, while the tenant has no current installation
  backing the pinned publisher or any current installation of the identifier
  is unsigned, differently signed or a different identity. Nothing is deleted
  and it becomes `active` again when the evidence does.
- `observation_state` is `observed` when `observed_installation_count` is
  above zero. Only current installations that are verifiably the resolved
  identity are counted: the same display name, another publisher, another Team
  ID or another platform never counts. Removing the last installation returns
  the declaration to `not_observed` and leaves the approval and its history in
  place. An installation is removed only by a report with authority to prove
  absence; a partial or unavailable report changes nothing.
- With a `min_version`, `outside_constraint_count` is the counted
  installations below it and `unknown_version_count` those whose version is
  missing or not numeric dotted. Neither is ever read as inside the constraint.

History rows are `{"action": "created"|"resolved", "actor_email",
"justification", "decided_at", "declaration"}`, where `declaration` is the
declaration as stored at that moment. The history is append-only and is
written in the same transaction as the change it records. Inventory never
writes to it.

### Software notifications (PAT-2009)

`GET /v1/portal/software-notifications`, readable by every portal role.
`PUT /v1/portal/software-notifications`, portal admin only (403
`admin_role_required` otherwise), body is either or both of
`{"unapproved_alerts_enabled": bool, "new_software_enabled": bool,
"ai_tooling_notifications_enabled": bool}` with the PAT-2021 strict key walk
(unknown, duplicate or case-variant keys are 400).

```json
{
  "unapproved_alerts_enabled": true,
  "new_software_enabled": false,
  "ai_tooling_notifications_enabled": false,
  "is_default": true,
  "updated_at": null,
  "updated_by": null,
  "unapproved_alert": {
    "event": "software.unapproved_detected",
    "email_recipient": { "email": "it@customer.example", "configured": true },
    "webhook_endpoints": 1,
    "email_schedule": "marked: immediately; newly observed: daily digest",
    "digest_hour_utc": 7,
    "webhook_subscribe_to": "software.unapproved_detected"
  },
  "new_software": { "event": "software.first_seen", "channels": 0, "digest_hour_utc": 7 },
  "ai_tooling": { "event": "ai_tooling.first_seen", "channels": 0, "digest_hour_utc": 7 }
}
```

- Defaults: the unapproved software alert is **on**, the new software
  notification and AI tooling notification are **off** (owner ruling,
  2026-09-24). `is_default` is true until someone saves the settings.
- `email_recipient` is the tenant's contact email (`tenants.contact_email`),
  set by the operator at provisioning. `configured: false` means there is no
  usable address: the webhook still fires, the email is recorded as
  `no_recipient`. The portal should say so rather than imply alerts are
  emailed.
- `webhook_endpoints` counts enabled outbound webhooks subscribed to
  `software.unapproved_detected`; `new_software.channels` counts enabled
  notification channels subscribed to `software.first_seen`. Zero means the
  event has nowhere to go on that route.
- `ai_tooling.first_seen` is an independent opt-in daily event over named,
  decision-safe AI tooling identities. Its cursor is independent from
  `software.first_seen`, so toggling it cannot advance or reset general
  software delivery. Every preference change is append-only audited with the
  verified portal email or `operator` actor.

### The unapproved software alert, `software.unapproved_detected`

Raised for a tenant with the alert on when:

1. **marked**: a customer admin marks a product Unapproved with
   `PUT /v1/portal/software-approvals`, or the operator sets it with the admin
   API, and it is installed on at least one device. One alert (and one webhook
   delivery per endpoint) per product, listing every device. The email is
   sent immediately and is one email per request: a bulk mark of 200 products
   sends one email listing the first 20 and saying how many more are in the
   portal. The episode is recorded in the same transaction as the decision,
   and Patched's background runner raises the alert straight after the
   commit, normally within seconds (PAT-2095; the write request does not wait
   for it). A raise that fails is retried at the runner's next minute tick,
   so the alert is delayed, never lost. A device that reports the product
   before the alert is raised is listed in it, not alerted separately.
2. **observed**: an Unapproved product is newly observed on a device during
   extraction of a report whose evidence time is current. One alert per
   (product, device) per unapproved episode, emailed in a daily digest at
   07:00 UTC covering alerts raised before that time (including a tenant's
   first digest; an alert raised at 10:00 goes out the next morning).

Deploying this feature alerts nothing that already existed: migration 0183
records every device already carrying an Unapproved product as known
(`suppressed_baseline`), so only a new (product, device) pair or a new
Unapproved marking alerts afterwards.

An episode is one transition of the product's policy into Unapproved.
Devices the marked alert listed are not alerted again by ingest, and a device
reporting every 15 minutes is alerted once. Approving, ignoring or clearing
the product and then marking it Unapproved again starts a new episode and
alerts again. Approved, Ignored, Unreviewed and Mandatory products never
alert. Patched never removes the software; the alert says so.

Delivery: the PAT-134 outbound webhook (every enabled `tenant_webhooks`
endpoint subscribed to the event, signed exactly as `vulnerability.discovered`
is) and email to the tenant contact. Never to Patched staff. The webhook body:

```json
{
  "event_type": "software.unapproved_detected",
  "tenant_id": "<uuid>",
  "timestamp": "2026-09-24T14:05:02Z",
  "data": {
    "alert_id": 7,
    "trigger": "marked",
    "policy": { "kind": "application", "id": 42 },
    "marked_by": "admin@customer.example",
    "marked_via": "portal",
    "marked_at": "2026-09-24T14:05:00Z",
    "detected_at": "2026-09-24T14:05:02Z",
    "device_count": 2,
    "devices_truncated": false,
    "products": [
      { "type": "application", "product_key": "application:macos:org.torproject.torbrowser:MADPSAYN6T",
        "name": "Tor Browser", "platform": "macos", "identifier": "org.torproject.torbrowser",
        "team_id": "MADPSAYN6T", "device_count": 2,
        "devices": [ { "device_id": "…", "hostname": "mac-01", "platform": "macos",
                       "observed_since": "…", "last_seen": "…", "stale": false } ] }
    ]
  }
}
```

`trigger: "observed"` has one product and one device. `marked_via` is
`portal`, `operator` or `unknown` as on the drift endpoint. `alert_id` is
stable for the alert and serves as the receiver's dedupe key; a marked alert
lists at most 500 devices (`devices_truncated`, with `device_count` exact).
The payload never carries a secret, token or credential.

### Unapproved software alerts: lifecycle (PAT-2097)

Every (episode, device) pair an alert covered is a **tracked alert** with a status: `open`, `acknowledged` or `resolved`. A marked alert
on 40 devices is 40 tracked alerts. Pairs recorded as already present when
0183 ran (`trigger: "baseline"`) are tracked too, although they were never
announced. Nothing resolves on a timer.

- **Acknowledge** (a person has seen it). Portal admin, or the operator.
  Changes nothing on any device and resolves nothing.
- **Resolved**, with `resolved_reason`:
  - `superseded`: the alert no longer describes an active case. Either the
    product is still installed but a different policy row, or none, now
    decides its state (a more specific Approved row was added, or the
    display name or identifier the policy matched changed). Or a
    newer Unapproved decision on the same policy started a new episode,
    which carries its own alert. A still-installed product is never
    resolved `not_observed`.
  - `approved`, `ignored`, `policy_removed`: the product's policy moved to
    Approved (or operator Mandatory), Ignored, or was cleared (Unreviewed or
    deleted). Resolved in the same transaction as the decision; the
    `PUT /v1/portal/software-approvals` result carries `resolved_alerts` per
    item.
  - `not_observed`: an authoritative report proved the product gone from
    that device. For an application only a report with
    `collection_status.apps: "complete"` (schema v3) counts. A partial,
    unavailable, inconsistent or legacy report, or one with no status,
    resolves nothing, even when the product has left the inventory. A
    per-user install stays present while its user is missing from the
    report or reported partial. For a browser extension, a complete uncapped
    `browser_extensions_status` report after the extension was last listed.
- **Re-opened**: an alert resolved `not_observed`, or resolved `superseded`
  because another policy row governed the product, re-opens when the
  product is reported on the device again under its own policy, that policy
  is still Unapproved and the alert's episode is still the latest. It goes back to `open` (the same `id`, not a new
  alert), `reopened_count` increments, any acknowledgement is cleared. A
  re-open sends **no email and no webhook** of its own; it is listed once in
  the tenant's next daily digest under "Found again". If the product was
  marked Unapproved again by a new decision, that is a new episode and a new
  alert instead. Alerts resolved `approved`, `ignored` or `policy_removed`,
  or `superseded` by a newer episode, never re-open.

`GET /v1/portal/software-alerts`, every portal role. Query: `status`
(comma-separated `open`, `acknowledged`, `resolved`; default all),
`product_key` (exact, as elsewhere), `device_id` (UUID), `limit` (1 to 500,
default 100), `offset`. Unknown parameters are 400. Order: open, then
acknowledged, then resolved; most recently changed first within each.
`counts` apply the product and device filters but not `status`; `total`
applies all three.

```json
{
  "total": 3, "limit": 100, "offset": 0, "returned": 3,
  "counts": { "open": 2, "acknowledged": 1, "resolved": 0 },
  "alerts": [
    {
      "id": 812,
      "status": "open",
      "trigger": "observed",
      "product": { "type": "application", "product_key": "application:macos:org.torproject.torbrowser:MADPSAYN6T",
                   "name": "Tor Browser", "platform": "macos", "identifier": "org.torproject.torbrowser",
                   "team_id": "MADPSAYN6T" },
      "policy": { "kind": "application", "id": 42 },
      "device": { "device_id": "…", "hostname": "mac-01", "platform": "macos", "last_seen": "2026-09-24T13:50:00Z" },
      "notification_id": 7,
      "raised_at": "2026-09-24T14:05:02Z",
      "status_changed_at": "2026-09-24T14:05:02Z",
      "acknowledged_at": null,
      "acknowledged_by": null,
      "resolved_at": null,
      "resolved_reason": null,
      "reopened_count": 0,
      "last_reopened_at": null
    }
  ]
}
```

- `id` is the tracked alert, used in the URLs below. `notification_id` is
  the outbound alert that reported the pair, the webhook payload's
  `alert_id`; several tracked alerts share one when a marked alert listed
  several devices. `null` for `baseline`.
- `trigger`: `marked`, `observed` or `baseline`.
- `product` is the product as observed. For a `baseline` alert the device
  has not reported since 0184, it is built from the policy row and may lack
  `product_key`, in which case a `product_key` filter does not match it
  until the device next reports.
- `acknowledged_by` is the admin's email, or `"operator"`.
- `device.last_seen` is `null` only if the device row has gone.

`GET /v1/portal/software-alerts/{id}`, every portal role: the same object
plus `history`, oldest first. Another tenant's id, or no such id, is 404
`not_found`.

```json
{
  "id": 812, "status": "acknowledged", "…": "…",
  "history": [
    { "id": 1, "from": null, "to": "open", "actor_kind": "system", "actor": null, "reason": null, "note": null, "at": "…" },
    { "id": 9, "from": "open", "to": "acknowledged", "actor_kind": "portal_user", "actor": "admin@customer.example",
      "reason": null, "note": "Raised with the service desk", "at": "…" }
  ]
}
```

`actor_kind` is `portal_user` (with `actor` the verified email), `operator`
or `system` (policy change seen at ingest, authoritative absence, re-open;
`actor` null). `reason` is set on every transition to `resolved`.

`POST /v1/portal/software-alerts/{id}/acknowledge`, portal **admin only**:
403 `admin_role_required` for a viewer, checked before anything else. Body
optional: `{"note": "..."}`, at most 1000 characters, newlines allowed, other
control characters and unknown keys 400. Response 200: `changed` plus the
detail object above. Idempotent: acknowledging an acknowledged alert returns
200 with `changed: false` and records nothing (a second note is not stored).
A resolved alert is 409 `alert_resolved`. Another tenant's id is 404.

## SAM reports (PAT-2146)

Pre-staged software asset management reports. Each is a saved definition over
the existing read data (the response names it in `definition`), states the
`basis` it rests on, says plainly what it did not count, and never presents an
estimate as an audit or compliance position. Tenant-scoped from the verified
identity only; every portal role can read them; unknown query parameters are
refused with 400.

### GET /v1/portal/reports/software/unsupported (PAT-2147)

Every installed application and every device's operating system, with its
support state against the vendor's published end of support:

| `state` | Meaning |
|---|---|
| `unsupported` | The cycle's end of support date is today or earlier (or the source marks it ended and gives no date). |
| `ending_within_90_days` | End of support is 1 to 90 days away. |
| `supported` | End of support is more than 90 days away, or the source marks the cycle maintained with no end date announced. |
| `unknown` | Patched could not determine support. Never read as supported. `unknown_reason` says why. |

`unknown_reason` values (with `unknown_reason_text` in plain English):
`no_published_mapping` (no staff-published link from this product to a
lifecycle entry; includes every name-only product), `lifecycle_not_fetched`,
`lifecycle_stale` ("lifecycle data older than 7 days"),
`version_not_reported`, `version_not_matched` ("version not matched to a
support cycle"), `edition_unknown` (Windows: the edition was not reported and
the Enterprise/Education and Home/Pro cycles have different dates),
`edition_not_covered` (Windows Server, which is a separate lifecycle product),
`no_end_of_support_data`, `no_release_data` (a rolling-release product whose
cycle has no usable release date).

Rolling-release products (Chrome and Firefox, PAT-2171) are judged by release
order, not by the source's end of support date, because that date is only the
next release, two to four weeks out. The latest released major is `supported`;
the previous major is `supported` while the latest is under 21 days old and
`unsupported` after; older majors are `unsupported`. These rows never read
`ending_within_90_days`, carry a `note` saying so and, when `supported`, no
`days_to_eol` or `eol_date`. Firefox ESR keeps the source's own dates. The
source has no Chrome Extended Stable cycle, so an Extended Stable install reads
`unsupported` once it is two or more majors behind.

Lifecycle data comes from endoflife.date, refreshed daily and used for at most
7 days. Only mappings staff have published affect this report; a proposed
mapping changes nothing. Every mapped row carries its `source` and
`last_checked_at` (when that product's data was last fetched successfully).

Query: `state`, `kind` (`application` | `operating_system`), `platform`
(`macos` | `windows`), `limit` (1 to 500, default 100), `offset`, `format`
(`json` | `csv`).

```json
{
  "definition": { "id": "sam.unsupported-software", "version": 1, "title": "Unsupported software",
                  "ending_window_days": 90, "lifecycle_cache_ttl_days": 7, "stale_after_days": 14,
                  "lifecycle_source": "endoflife.date" },
  "generated_at": "2026-09-25T12:00:00Z",
  "summary": {
    "installation_count": 11,
    "states": {
      "unsupported":           { "installation_count": 3, "device_count": 2 },
      "ending_within_90_days": { "installation_count": 1, "device_count": 1 },
      "unknown":               { "installation_count": 6, "device_count": 3 },
      "supported":             { "installation_count": 1, "device_count": 1 }
    },
    "unknown_by_reason": { "no_published_mapping": 4, "lifecycle_stale": 1, "edition_unknown": 1 }
  },
  "basis": {
    "generated_at": "2026-09-25T12:00:00Z",
    "evidence_newest_at": "2026-09-25T11:00:00Z", "evidence_oldest_at": "2026-09-05T11:00:00Z",
    "devices_total": 4, "devices_assessed": 4, "devices_reporting": 3, "devices_stale": 1,
    "devices_without_inventory": 0, "stale_after_days": 14,
    "lifecycle_source": "endoflife.date",
    "lifecycle_checked_oldest_at": "2026-09-17T01:02:00Z", "lifecycle_checked_newest_at": "2026-09-25T01:02:00Z",
    "retired_devices_excluded": true, "devices_retired": 0,
    "not_counted": [
      { "reason": "retired_devices", "description": "devices your organisation has retired", "count": 0 },
      { "reason": "unrecognised_platform", "description": "devices reporting an operating system other than macOS or Windows", "count": 0 },
      { "reason": "developer_tooling", "description": "IDE extensions, language packages, local models and MCP servers are not assessed by this report", "count": 1 },
      { "reason": "homebrew_taps", "description": "Homebrew taps are package sources, not installed software", "count": 0 }
    ],
    "complete": false,
    "statement": "An estimate from the software and operating system versions your devices reported, compared with public end of support dates from endoflife.date. It is not an audit or a compliance position. Unknown means Patched could not determine support; it never means supported.",
    "notes": ["…"]
  },
  "cyber_essentials": { "…": "see below" },
  "total": 11, "limit": 100, "offset": 0,
  "products": [
    {
      "product_key": "os:windows", "kind": "operating_system", "name": "Windows", "platform": "windows",
      "version": "10.0.19045", "edition": "Microsoft Windows 10 Pro",
      "state": "unsupported", "cycle": "10-22h2", "eol_date": "2025-10-14", "days_to_eol": -346,
      "device_count": 1, "stale_device_count": 0, "installation_count": 1,
      "source": { "name": "endoflife.date", "slug": "windows", "url": "https://endoflife.date/windows" },
      "last_checked_at": "2026-09-25T01:02:00Z",
      "unknown_reason": null, "unknown_reason_text": null,
      "note": "paid extended security updates are available until 2028-10-10; enrolment is not evidenced"
    },
    {
      "product_key": "app:3f1c…", "kind": "application", "name": "Proposed App", "platform": "windows",
      "version": "1.0", "state": "unknown", "cycle": null, "eol_date": null, "days_to_eol": null,
      "device_count": 1, "stale_device_count": 0, "installation_count": 1,
      "source": null, "last_checked_at": null,
      "unknown_reason": "no_published_mapping",
      "unknown_reason_text": "no published lifecycle mapping for this product", "note": null
    }
  ]
}
```

- A product row groups installations by product, version and outcome (and
  Windows edition), so one product at two versions is two rows. Rows are
  ordered unsupported, ending, unknown, supported, then soonest end of
  support. `product_key` is `os:macos`, `os:windows`, or `app:` plus the
  installation identity fingerprint; pass it to `/devices` to drill down.
- `days_to_eol` is negative once passed, null when the source gives no date.
- `devices_stale` devices (no report for 14 days) are still counted, with
  `stale_device_count` per row and `device_stale` per installation.
  `complete` is false whenever a device is stale, has reported no software,
  runs an unrecognised OS, or any row is `unknown`. When `complete` is false
  the portal must not present the Unsupported count as the whole estate's.
- A device the customer has retired (PAT-2135, the shared
  `internal/deviceretirement` rule) is left out of every row, the drill-down,
  the summary and `devices_assessed`; `devices_total` still includes it, and
  `devices_retired` and the `retired_devices` not-counted entry report how
  many were excluded.
- Windows: the build number picks the feature release and the WMI caption
  (`os_caption`) picks the edition. Windows 10 22H2 past its end of support
  reads `unsupported` with a `note` that paid Extended Security Updates exist
  and are not evidenced; Patched cannot see ESU enrolment.
- 422 `{"error":"estate_too_large"}` over 250,000 current installations,
  never a partial answer.

`cyber_essentials` is the evidence shape the Cyber Essentials readiness view
(PAT-1927) consumes; Go callers use `lifecycle.FetchCyberEssentialsEvidence`.
It is evidence only, never a pass or fail:

```json
{
  "requirement": "security_update_management",
  "evidence_kind": "unsupported_software",
  "position": "evidence_only",
  "statement": "Cyber Essentials requires in-scope software to be licensed and supported. …",
  "evidence_at": "2026-09-25T12:00:00Z",
  "devices_assessed": 4,
  "devices_with_unsupported_software": 2,
  "devices_with_unknown_support": 3,
  "unsupported_installation_count": 3,
  "complete": false,
  "devices": [
    { "device_id": "…", "hostname": "mac-01", "device_last_seen": "…", "device_stale": false,
      "unsupported": [ { "kind": "operating_system", "product_key": "os:macos", "name": "macOS",
                         "version": "13.6.1", "cycle": "13", "eol_date": "2025-09-15",
                         "source": { "…": "as above" }, "last_checked_at": "…", "note": null } ] }
  ]
}
```

`devices_with_unknown_support` is there so a readiness view can say how much
of the estate the evidence does not cover; an absence of Unsupported devices
is not evidence of compliance while it is non-zero.

CSV (`?format=csv`) is every matching installation row, unpaged (the
`limit`/`offset` are ignored): `device_id, hostname, device_last_seen,
device_stale, kind, product_key, name, platform, version, edition, state,
cycle, eol_date, days_to_eol, source, source_url, last_checked_at,
unknown_reason, note, generated_at`. Any text cell starting with `=`, `+`,
`-`, `@`, tab or carriage return is prefixed with `'` (spreadsheet formula
injection). `X-Patched-Export-Rows` carries the row count.

### GET /v1/portal/reports/software/unsupported/devices (PAT-2147)

The per-installation drill-down: one row per device and application, plus
one per device for its operating system. Same query as above plus
`device_id` and `product_key` filters; `{definition, generated_at, basis,
total, limit, offset, rows}`. A row is a product row's fields without the
counts, plus `device_id`, `hostname`, `device_last_seen` and `device_stale`.
Filtering on another tenant's device id returns no rows. `?format=csv` is the
same CSV as above, filtered.

### GET /v1/portal/reports/software/remote-access (PAT-2148)

Every remote access tool and RMM agent on the estate, by device and (PAT-2075,
where a per-user install is reported) by user, with the tenant's existing
software-approval state. Detection is `internal/categorytag`'s own match
rules, evaluated directly against live installations and browser extensions,
never a materialised-tag read, so this report is never a backfill cycle
behind `/v1/portal/tagged-products`.

`category` is `remote_access` or `rmm_agent` (migration `0197`'s taxonomy).
RMM agents (an MSP's own remote monitoring and management tooling: NinjaOne,
Datto RMM, N-able, Kaseya VSA, ConnectWise Automate, Atera, Syncro) are a
separate category from `remote_access` so an MSP's own tooling is never
presented as an unsanctioned remote-access finding, in the summary or in the
row ordering.

`approval_state` is the tenant's own existing decision (PAT-2007/PAT-2058),
never a parallel remote-access allow list: `approved` (sanctioned),
`unapproved` (flagged), `unreviewed` (flagged as not reviewed), `ignored`
(shown as ignored, neither flagged nor sanctioned). A product with no
`tenant_app_policies` / `tenant_extension_policies` / `tenant_homebrew_policies`
row reads `unreviewed`. Unsanctioned products (`unapproved`, then
`unreviewed`, then `ignored`) sort ahead of `approved` ones, in both the
product list and the device drill-down.

Query: `category` (`remote_access` | `rmm_agent`), `kind` (`app` |
`browser_extension` | `package`; `package` covers a Homebrew formula or
cask), `state` (an approval state), `platform` (`macos` | `windows`), `limit`
(1 to 500, default 100), `offset`, `format` (`json` | `csv`). Unknown
parameters are `400`.

```json
{
  "definition": { "id": "sam.remote-access", "version": 1, "title": "Remote access tools" },
  "generated_at": "2026-09-26T12:00:00Z",
  "summary": {
    "remote_access": {
      "unapproved": { "tool_count": 1, "installation_count": 1, "device_count": 1 },
      "unreviewed": { "tool_count": 1, "installation_count": 1, "device_count": 1 },
      "ignored":    { "tool_count": 1, "installation_count": 1, "device_count": 1 },
      "approved":   { "tool_count": 1, "installation_count": 1, "device_count": 1 }
    },
    "rmm_agents": {
      "unapproved": { "tool_count": 1, "installation_count": 1, "device_count": 1 },
      "unreviewed": { "tool_count": 0, "installation_count": 0, "device_count": 0 },
      "ignored":    { "tool_count": 0, "installation_count": 0, "device_count": 0 },
      "approved":   { "tool_count": 0, "installation_count": 0, "device_count": 0 }
    },
    "remote_access_tool_count": 4, "remote_access_installation_count": 4,
    "rmm_agent_tool_count": 1, "rmm_agent_installation_count": 1
  },
  "basis": {
    "generated_at": "2026-09-26T12:00:00Z",
    "evidence_newest_at": "2026-09-26T11:00:00Z", "evidence_oldest_at": "2026-09-20T11:00:00Z",
    "devices_total": 7, "devices_assessed": 6, "devices_reporting": 6, "devices_stale": 0,
    "devices_without_inventory": 0, "stale_after_days": 14,
    "retired_devices_excluded": true, "devices_retired": 1,
    "not_counted": [
      { "reason": "retired_devices", "description": "devices your organisation has retired", "count": 1 },
      { "reason": "unrecognised_platform", "description": "devices reporting an operating system other than macOS or Windows", "count": 0 }
    ],
    "complete": true,
    "statement": "Every remote access tool and RMM agent Patched's category rules recognise, by device and user where a per-user install is reported, with your tenant's existing software approval state. Detection covers only the tools this catalogue recognises: a device reporting none of them is not evidence that no remote access tool is installed, only that none of the catalogued ones were found. It is not an audit or a compliance position.",
    "notes": ["…"]
  },
  "total": 4, "limit": 100, "offset": 0,
  "products": [
    {
      "product_key": "remote_access:app:com.philandro.anydesk", "category": "remote_access", "kind": "app",
      "name": "AnyDesk", "platform": "macos", "identifier": "com.philandro.anydesk",
      "approval_state": "unapproved", "device_count": 1, "stale_device_count": 0, "installation_count": 1,
      "users": ["alice"], "machine_wide_count": 0, "last_seen": "2026-09-26T11:00:00Z"
### GET /v1/portal/reports/software/version-sprawl (PAT-2150)

Version sprawl per product: how many distinct versions of a product are live
across the estate, the oldest and the newest of them, the latest the vendor
has released (where Patched holds a trusted source for it), how many devices
are more than one major version behind, and the CVE count on the oldest live
version. Scope is installed applications only (the same identity kinds and
not-counted boundary as the unsupported-software report above); operating
systems are not a "product" for sprawl purposes.

**Version comparison rule** (`definition.major_version_rule`, also in
`basis.notes`): a version's major is the leading run of digits before the
first separator (`.`, `-`, `_`, `+` or space), optionally prefixed `v`:
`"154.0.8037.58"` -> `154`, `"8.0.402.6"` -> `8`, `"v3.12.4"` -> `3`. A
version that does not start that way, or is empty (a Homebrew HEAD build,
`"latest"`, or no version reported), has no major: it is not a comparable
point on a version line, so it is excluded from the distinct-version count,
can never be reported as the oldest or the newest, and its device is counted
in `devices_not_comparable` rather than as behind or current.
`devices_more_than_one_major_behind` compares each device's major against the
**newest live major version of the same product across the estate** — not
the vendor's latest release, which is a separate, independently sourced
figure carried in `latest_released`.

**Latest released** (`definition.latest_source_precedence`) is taken only
from a source Patched already trusts, tried in this order, and never from the
newest version merely seen on the estate:

1. `endoflife.date` — a staff-published lifecycle mapping (the same
   `lifecycle_mappings` PAT-2147 uses), not older than 7 days
   (`definition.lifecycle_cache_ttl_days`): the `latest_version` of whichever
   cycle is newest (by release date, or by version where no release date is
   given).
2. `curated_catalogue` — `app_catalog_entries` (PAT-472/PAT-1728), shown to a
   reader as "Patched reference list". An entry is matched to a product only
   on an exact product name (PAT-2509): the product's display name must equal
   the entry's name, ignoring case and surrounding spaces, and, where the entry
   has a verified signer, the product's Team ID must also be that signer. A
   name that merely contains the other does not match ("Microsoft Teams
   classic" is not "Microsoft Teams" and has its own version line; "zoom.us"
   against a "Zoom" entry is a guess), a product with no Team ID evidence never
   matches a signed entry, and a helper or sub-app (an updater, a crash
   reporter, a plugin host) never matches. A vendor's Team ID signs many
   products, so a Team ID that agrees without a product name that agrees gives
   nothing. This is stricter than the name-contains-name rule `GET /v1/posture`
   and the tenant apps view apply: a version claim made to a customer needs the
   same product, so a partial match reads not known. If more than one entry has
   exactly the product's name and they give different versions, the report does
   not pick one. The entry must have been verified within the last 7 days
   (`definition.catalogue_max_age_days`, measured from the entry's
   `verified_at`); an older entry is not a reference. This applies uniformly
   across identity kinds, so a Homebrew formula or cask whose reported name
   equals a catalogue entry's name resolves through it too — Patched holds no
   separate "latest available Homebrew version" feed (PAT-2013 is inventory
   evidence only, never an upstream-version source), so the catalogue is the
   one trusted path a Homebrew product has today.
3. `vendor_feed` — reserved for a future per-vendor release feed. No such
   feed exists yet, so this source is never produced.

The first source that answers is the one used. Its figure is then checked
against the estate: if it is lower than the newest comparable version of the
same product running on the estate, it is stale by evidence and withheld
(`cvematch.CompareVersionsStrict`; a pair that cannot be ordered with
certainty is also withheld). A second source is not consulted to overrule the
first. Where none of this can produce a figure, `latest_released` and
`latest_released_source` are both `null` — never a guess.

`latest_released_source` carries `name` (the machine field, unchanged:
`endoflife.date` or `curated_catalogue`), `slug` and `url` (endoflife.date
only, otherwise empty), and, added by PAT-2509, `label` (the plain wording to
display: `endoflife.date` or `Patched reference list`) and `checked_at`
(RFC 3339, UTC: when the source was last refreshed, the endoflife.date fetch
time or the catalogue entry's `verified_at`). Display `label`, not `name`.

**CVE count on the oldest live version** (`cve_count_on_oldest_version`,
`cve_not_assessed_on_oldest_version`) is only ever evidence Patched already
holds: a matched finding (`device_cve_findings`) on a device running the
product's oldest live version. Whether the product is assessable at all is
decided the same way the CVE matcher itself decides it —
`cvematch.MappingsFor` / `HomebrewMappingsFor` against `app_cpe_mappings` — so
a product with no CPE mapping reads `cve_not_assessed_on_oldest_version: true`
with `cve_count_on_oldest_version: null`, never `0`. A product that is mapped
but has no matched finding on its oldest version reads a real `0`.

Query: `platform` (`macos` | `windows`), `limit` (1 to 500, default 100),
`offset`, `format` (`json` | `csv`).

`?format=csv` is one row per product, unpaged, with the header
`product_key, name, platform, distinct_versions, oldest_version,
newest_version, latest_released, latest_released_source,
devices_more_than_one_major_behind, devices_not_comparable,
cve_count_oldest_version, device_count, stale_device_count, generated_at,
latest_released_checked_at`. The last column was added by PAT-2509 and the
others keep their names and order. `latest_released_source` holds the plain
label, never the machine name `curated_catalogue`, so it now reads `Patched
reference list` for a catalogue figure and `endoflife.date` for the other
source; `latest_released_checked_at` is the RFC 3339 UTC time the source was
last refreshed. Both are empty on a row with no reference.

```json
{
  "definition": { "id": "sam.version-sprawl", "version": 2, "title": "Version sprawl",
                  "stale_after_days": 14, "lifecycle_cache_ttl_days": 7, "catalogue_max_age_days": 7,
                  "major_version_rule": "…", "latest_source_precedence": ["endoflife.date", "curated_catalogue", "vendor_feed"] },
  "generated_at": "2026-09-26T12:00:00Z",
  "basis": {
    "generated_at": "2026-09-26T12:00:00Z",
    "devices_total": 6, "devices_assessed": 5, "devices_stale": 1, "stale_after_days": 14,
    "retired_devices_excluded": true, "devices_retired": 1,
    "not_counted": [
      { "reason": "retired_devices", "description": "devices your organisation has retired", "count": 1 },
      { "reason": "unrecognised_platform", "description": "devices reporting an operating system other than macOS or Windows", "count": 0 },
      { "reason": "developer_tooling", "description": "IDE extensions, language packages, local models and MCP servers are not assessed by this report", "count": 0 },
      { "reason": "homebrew_taps", "description": "Homebrew taps are package sources, not installed software", "count": 0 }
    ],
    "complete": false,
    "statement": "…",
    "notes": ["…"]
  },
  "total": 1, "limit": 100, "offset": 0,
  "products": [
    {
      "product_key": "app:3f1c…", "name": "ManyVersionApp", "platform": "macos",
      "distinct_versions": 3, "oldest_version": "8.0.0", "newest_version": "10.0.0",
      "latest_released": "10.4.0",
      "latest_released_source": { "name": "endoflife.date", "slug": "manyversionapp", "url": "https://endoflife.date/manyversionapp",
                                 "label": "endoflife.date", "checked_at": "2026-09-26T03:00:00Z" },
      "devices_more_than_one_major_behind": 2, "devices_not_comparable": 1,
      "cve_count_on_oldest_version": 3, "cve_not_assessed_on_oldest_version": false,
      "device_count": 5, "stale_device_count": 1,
      "versions": [
        { "version": "10.0.0", "device_count": 1, "stale_device_count": 0 },
        { "version": "9.5.0", "device_count": 1, "stale_device_count": 0 },
        { "version": "8.0.0", "device_count": 2, "stale_device_count": 1 }
      ]
    }
  ]
}
```

- A product row groups installations by product and outcome; `product_key`
  is `<category>:<kind>:<identifier>`, pass it to `/devices` to drill down.
  `kind` is `app` (a regular application, and a Homebrew formula matched by a
  future rule), `package` (a Homebrew cask, PAT-2148's own reuse of
  `internal/categorytag`'s package/cask identity), or `browser_extension`.
- `users` lists the distinct accounts a per-user install (PAT-2075) or a
  per-user browser extension resolves to for this product; `machine_wide_count`
  is how many of the product's matching rows carry no per-user scope (a
  machine-wide install, or one this tenant's agent version does not report
  per user). A product can have both: two devices, one machine-wide and one
  per-user for two accounts.
- A device the customer has retired (PAT-2135, the shared
  `internal/deviceretirement` rule) is left out of every row, the
  drill-down, the summary and `devices_assessed`; `devices_total` still
  includes it, and `devices_retired` and the `retired_devices` not-counted
  entry report how many were excluded.
- `complete` is false whenever a device is stale, has reported no software,
  or runs an unrecognised OS. Detection itself is always catalogue-limited
  (the `statement` says so plainly) independent of `complete`: a `true`
  value means every in-scope device was fully assessed against the current
  rule set, never that the estate carries no remote access tooling beyond
  what is listed.
- 422 `{"error":"estate_too_large"}` over 250,000 current installations,
  never a partial answer.

### GET /v1/portal/reports/software/remote-access/devices (PAT-2148)

The per-installation (and per-user) drill-down: one row per device and
product, or one row per device, product and user where a per-user install or
per-user browser extension is reported. Same query as above plus `device_id`
and `product_key` filters; `{definition, generated_at, basis, total, limit,
offset, rows}`. A row is a product row's fields without the counts, plus
`device_id`, `hostname`, `device_last_seen`, `device_stale`, `user` (the
account, or `null`) and `machine_wide` (true when `user` is `null` because
the install has no per-user scope, as opposed to one this tenant simply
hasn't reported per user yet -- both read `user: null`). Filtering on another
tenant's device id returns no rows. `?format=csv` is the same CSV as above,
unpaged, with the header `device_id, hostname, device_last_seen,
device_stale, category, kind, product_key, name, platform, identifier,
version, approval_state, user, last_seen, generated_at`; `user` reads
`machine-wide` for a machine-wide row. Any text cell starting with `=`, `+`,
`-`, `@`, tab or carriage return is prefixed with `'` (spreadsheet formula
injection). `X-Patched-Export-Rows` carries the row count.
- Sorted by `distinct_versions` descending, then
  `devices_more_than_one_major_behind` descending, then name.
- `product_key` is `app:` plus the installation identity fingerprint, the
  same key the unsupported-software report's product rows use.
- `versions` is the per-product version breakdown (every live version with
  its device counts); it is not paginated separately.
- A device the customer has retired (PAT-2135) is left out of every figure;
  `devices_total` still includes it, and `devices_retired` plus the
  `retired_devices` not-counted entry report how many were excluded.
- 422 `{"error":"estate_too_large"}` over 250,000 current installations,
  never a partial answer.

CSV (`?format=csv`) is every matching product row, unpaged, one row per
product (not the per-version breakdown): `product_key, name, platform,
distinct_versions, oldest_version, newest_version, latest_released,
latest_released_source, devices_more_than_one_major_behind,
devices_not_comparable, cve_count_oldest_version, device_count,
stale_device_count, generated_at`. `cve_count_oldest_version` reads
`not_assessed` rather than being left blank. Formula-injection neutralised
the same way as the unsupported report's CSV. `X-Patched-Export-Rows` carries
the row count.

### GET /v1/portal/reports/software/publishers (PAT-2152)

Every currently installed application, grouped by the publisher its code
signing evidence proves: the macOS Team ID, or the Windows Authenticode
signer pinned to its signing root (PAT-2121's `AuthenticodePublisherKey`).
Never the display name, registry Publisher string or any other
installer-claimed metadata: when signing evidence is missing (no codesign or
Authenticode result, or an agent too old to report it) or does not establish
a single pinned identity, the publisher reads `unverified`. Reuses
PAT-2093's own trust classifier (`internal/softwaregov`'s
`classifyMacTrust` / `classifyWindowsTrust`, gathered by the same
`loadTrustFacts` the overview's `new_software.trust` block reads) so a
product can never read one trust state on the overview and a different one
here.

Four groups, most attention-worthy first:

| `group` | Meaning |
|---|---|
| `unsigned_or_adhoc` | The collector reported the install unsigned (macOS `signing_status` `unsigned`, Windows `signature_state` `unsigned`), or ad hoc signed (macOS only: signed with no identity at all). |
| `invalid` | A signature that does not validate against the code (macOS `invalid`, Windows `invalid`), or one that validates but whose certificate chain does not anchor to Apple (macOS `untrusted`, PAT-2117). |
| `unverified` | No signing evidence at all, or a signature that validates but whose publisher cannot be independently pinned: installations disagree, carry no single Team ID, or (Windows) chain to an enterprise root or carry no root evidence at all (an agent older than updater #668). The raw registry Publisher string is never shown here even though PAT-2093's own overview reads it labelled unverified. |
| `verified` | Every installation agrees on one Team ID (macOS) or one Authenticode publisher key -- signer plus root pin (Windows) -- or is Apple's own platform signing. `trusted` says whether this tenant has approved a product under that exact publisher identity (PAT-2121): its own decision, never a judgement on the vendor. |

Query: `group` (one of the four above), `platform` (`macos` | `windows`),
`publisher_key`, `limit` (1 to 500, default 100), `offset`, `format`
(`json` | `csv`). Unknown parameters are `400`.

```json
{
  "definition": { "id": "sam.software-publishers", "version": 1, "title": "Software publishers" },
  "generated_at": "2026-09-26T12:00:00Z",
  "summary": {
    "publisher_count": 2, "trusted_publisher_count": 1, "untrusted_publisher_count": 1,
    "unsigned_installation_count": 1, "invalid_installation_count": 1,
    "unverified_installation_count": 1, "installation_count": 5
  },
  "basis": { "…": "same shape as PAT-2147/PAT-2148: devices_total, devices_assessed, devices_stale, retired_devices_excluded, devices_retired, not_counted, complete, statement, notes" },
  "total": 4, "limit": 100, "offset": 0,
  "publishers": [
    { "publisher_key": "", "group": "unsigned_or_adhoc", "platform": "macos", "identity_basis": "none",
      "publisher": null, "trusted": false, "signing": "unsigned", "signer_class": null, "notarisation": "not_applicable",
      "product_count": 1, "device_count": 1, "stale_device_count": 0, "installation_count": 1 },
    { "publisher_key": "team:ABCDE12345", "group": "verified", "platform": "macos", "identity_basis": "team_id",
      "publisher": "ABCDE12345", "trusted": true, "signing": "signed", "signer_class": "developer_id",
      "notarisation": "confirmed", "product_count": 3, "device_count": 2, "stale_device_count": 0, "installation_count": 4 }
  ]
}
```

- A `publisher` row groups every current installation under one publisher
  identity; the three call-out groups instead bundle one platform's worth of
  installations that could not be attributed to a publisher (`publisher_key`
  and `publisher` are `null`). `publisher_key` is `team:<TEAMID>` (macOS),
  `apple` (macOS platform signing) or the Authenticode publisher key itself
  (Windows, already prefixed `authenticode:`) -- pass it to `/devices` or as
  the `publisher_key` filter to drill down.
- `trusted` is always `false` on a call-out row. A publisher with more than
  one product shows `product_count` above 1: more than one product can share
  a publisher.
- A device the customer has retired (PAT-2135, the shared
  `internal/deviceretirement` rule) is left out of every row, the
  drill-down, the summary and `devices_assessed`; `devices_total` still
  includes it, and `devices_retired` and the `retired_devices` not-counted
  entry report how many were excluded.
- 422 `{"error":"estate_too_large"}` over 250,000 current installations,
  never a partial answer.

CSV (`?format=csv`) is every matching installation row from the `/devices`
drill-down below, unpaged. `X-Patched-Export-Rows` carries the row count.

### GET /v1/portal/reports/software/publishers/devices (PAT-2152)

The per-installation drill-down: one row per device and application. Same
query as above plus `device_id` and `product_key` filters;
`{definition, generated_at, basis, total, limit, offset, rows}`. A row
carries `device_id`, `hostname`, `device_last_seen`, `device_stale`, the same
`publisher_key`, `group`, `platform`, `identity_basis`, `publisher`,
`trusted`, `signing`, `signer_class` and `notarisation` fields as a publisher
row, plus `product_key`, `name`, `identifier` and `version` for that one
installation. Filtering on another tenant's device id returns no rows.
`?format=csv` is the same CSV, unpaged, with the header `device_id, hostname,
device_last_seen, device_stale, group, platform, publisher_key,
identity_basis, publisher, trusted, signing, signer_class, notarisation,
product_key, name, identifier, version, generated_at`. Any text cell starting
with `=`, `+`, `-`, `@`, tab or carriage return is prefixed with `'`
(spreadsheet formula injection). `X-Patched-Export-Rows` carries the row
count.

### GET /v1/portal/reports/software/duplicate-tools (PAT-2151)

Within a curated set of categories where an estate commonly runs several
competing products doing the same job -- PDF editors, screen recorders, VPN
clients, password managers, file sync clients, video conferencing, remote
access tools (`remote_access`, reused from PAT-2148 rather than a second
copy) and note-taking apps -- the distinct products present, their install
counts and users, so consolidation opportunities are visible without needing
price data. Detection is `internal/categorytag`'s own match rules, evaluated
directly against live installations and browser extensions, the same pattern
PAT-2147/PAT-2148 use, grouped by each rule's `product_key` (migration
`0198`) rather than by raw identifier: one product's macOS bundle, Windows
winget package and Homebrew cask are three different identifiers but one
product.

Flag rule: a category is flagged when three or more distinct products are
present in the tenant's own estate. **The ticket's other rule -- two or more
PAID products in a category -- is not implemented.** It needs licence or
price data that does not exist yet (PAT-2143's price catalogue); this report
evaluates only the three-or-more-products rule and says so in
`basis.paid_products_rule_pending` (always `true` today). A product with no
category tag never appears in a duplicate group.

Query: `category` (one of the eight category keys), `product_key`, `limit`
(1 to 200, default 50), `offset`, `format` (`json` | `csv`). Unknown
parameters are `400`.

```json
{
  "definition": { "id": "sam.duplicate-tools", "version": 1, "title": "Duplicate tools by category" },
  "generated_at": "2026-09-26T12:00:00Z",
  "summary": {
    "categories_assessed": 8, "categories_with_products": 2,
    "categories_flagged": 1, "product_count": 4, "installation_count": 5
  },
  "basis": {
    "generated_at": "2026-09-26T12:00:00Z",
    "evidence_newest_at": "2026-09-26T11:00:00Z", "evidence_oldest_at": "2026-09-20T11:00:00Z",
    "devices_total": 7, "devices_assessed": 6, "devices_reporting": 6, "devices_stale": 0,
    "devices_without_inventory": 0, "stale_after_days": 14,
    "retired_devices_excluded": true, "devices_retired": 1,
    "not_counted": ["…"],
    "paid_products_rule_pending": true,
    "complete": true,
    "statement": "Categories where Patched's curated category rules recognise three or more distinct products installed across your estate, which makes each one a consolidation candidate. …",
    "notes": ["…"]
  },
  "total": 1, "limit": 50, "offset": 0,
  "categories": [
    {
      "category": "password_manager", "display_name": "Password managers", "flagged": true, "product_count": 3,
      "products": [
        {
          "product_key": "password_manager:onepassword", "category": "password_manager", "name": "1Password",
          "kinds": ["app"], "platforms": ["macos", "windows"], "identifiers": ["agilebits.1password", "com.1password.1password"],
          "approval_state": "unreviewed", "device_count": 2, "stale_device_count": 0, "installation_count": 2,
          "users": [], "machine_wide_count": 2, "last_seen": "2026-09-26T11:00:00Z"
        }
      ]
    }
  ]
}
```

- A category row is included only when at least one product is present in
  the estate; a category with zero matched products is left out entirely
  (never a zero-`product_count` row).
- A product row groups every rule (any category-eligible identifier type
  or platform) sharing the seed migration's `product_key` -- `platforms` and
  `identifiers` are therefore plural, unlike PAT-2147/PAT-2148's single-
  identifier product rows, because collapsing a product's platforms into one
  row is this report's whole point.
- `approval_state` is the least favourable state across the product's rows
  (`unapproved`, then `unreviewed`, then `ignored`, then `approved`), the
  same precedence PAT-2148 sorts by: a product approved on one platform and
  unreviewed on another reads `unreviewed`, never silently `approved`. Per-
  installation state is available from `GET /v1/portal/software/drift` and
  this report's own CSV export.
- `?format=csv` is the per-device (and per-user) row export, unpaged, with
  the header `device_id, hostname, device_last_seen, device_stale, category,
  product_key, name, platform, kind, identifier, version, approval_state,
  user, last_seen, generated_at`; `user` reads `machine-wide` for a
  machine-wide row. Any text cell starting with `=`, `+`, `-`, `@`, tab or
  carriage return is prefixed with `'` (spreadsheet formula injection).
- A device the customer has retired is left out of every figure, the same
  `internal/deviceretirement` rule PAT-2147/PAT-2148 apply.
- Detection is catalogue-limited independent of `complete`: a category is
  only as complete as its curated identities, so a category showing fewer
  than three products (or none) is not evidence that fewer are actually
  installed.
- 422 `{"error":"estate_too_large"}` over 250,000 current installations,
  never a partial answer.

## GET /v1/portal/local-admins (PAT-2215)

Standing local-administrator roster (PAT-1974's `local_admin_accounts`,
PAT-1988/1992's built-in-Administrator `account_state`), tenant-scoped.
**Admin role only** — account names are personal data, so a `viewer`
identity gets `403 admin_role_required` (`writeApprovalError`'s body shape,
the same as every write route in this package) rather than being served the
roster. This is the one read-only route on this surface that gates on role
at all; every other admin check here gates a write.

Reuses `report.FetchLocalAdminReport` — the exact query behind the
`local-admin` report-catalogue PDF above — rather than a second query.

```json
{
  "generated_at": "2026-09-29T10:00:00Z",
  "threshold": 2,
  "over_limit_devices": 3,
  "distinct_accounts": 11,
  "unreadable_devices": 1,
  "devices": [
    {
      "device_id": "7f3c5e2a-…",
      "hostname": "DC-1",
      "platform": "windows",
      "reported_admin_count": 3,
      "assessed_admin_count": 2,
      "pass": true,
      "membership_readable": true,
      "collection_status": "complete",
      "builtin_admin_state": "disabled",
      "builtin_admin_note": "The built-in Administrator account is disabled, so it is not counted as a standing admin.",
      "principals": [
        {"name": "CONTOSO\\Domain Admins", "principal_type": "group", "builtin": false, "account_state": null},
        {"name": "DC-1\\Administrator", "principal_type": "user", "builtin": true, "account_state": "disabled"}
      ]
    }
  ]
}
```

- `threshold` is the `lte 2` value both `cis_macos_5_8_local_admin_count`
  and `cis_win_5_8_local_admin_count` share (migrations 0005, 0160); it is
  not re-derived from `compliance_rules` per request.
- `reported_admin_count`/`assessed_admin_count`/`pass` are all `null`
  together for a device with no usable `local_admin_count` signal —
  `report.LocalAdminDevice.Risk == "unknown"` — never `0` or `false`, which
  would claim a clean device this platform has no evidence for.
  `assessed_admin_count` is the reported count less any disabled Windows
  built-in Administrator (PAT-1992); `pass` is `true` only when
  `Risk == "compliant"`.
- `membership_readable` is `false` when `local_admins.collection_status` is
  `"unavailable"` or was never reported (`collection_status` is then `""`
  in the response's own JSON, an honest "not yet known" rather than a
  guessed status string). It is independent of
  `reported_admin_count`/`pass`: the scalar count and the named roster come
  from separate collector paths and can degrade independently — a device
  can have a real count with an unreadable roster, or vice versa.
- `principal_type` is one of `local_admin_accounts`' own three values:
  `user` (an individual account, local or directory-sourced), `group` (a
  directory-sourced group principal such as Domain Admins — never itself a
  person, and its own membership is opaque to the device), or `unresolved`
  (a SID the device could not resolve to a name or kind — counted, never
  guessed at). `builtin`/`account_state` are PAT-1992's own fields; a `null`
  `account_state` means never reported (older agent, a non-built-in entry,
  or macOS, which carries no built-in entry to judge).
- `distinct_accounts` counts distinct `(principal_type, name)` pairs across
  the whole estate; the same principal on two devices counts once.
- `over_limit_devices` counts devices with a known `pass == false`; a
  device with `pass == null` is excluded from both the numerator and the
  denominator implied by this figure.
- No CSV export from this route itself; the portal's own
  `/local-admins.csv` builds its CSV server-side from this same JSON, the
  same shape as `/ai-tooling.csv` and `/devices.csv`.

## POST /v1/portal/exports/table-pdf (PAT-2405)

Renders a table the portal sends as a branded PDF. The portal builds its CSV
list exports itself from the JSON routes above and has no PDF renderer; it
posts the same column headers and cells here and returns the PDF, so the PDF
and the CSV of a list show the same rows. The route reads only the tenant's
name (and, for `local-admins`, the caller's role) and stores nothing.

Same `portalauth` middleware as every `/v1/portal` route. The tenant name
printed comes only from the verified portal identity. The body cannot name a
tenant or set the title: the platform owns one title per export key, and any
field outside this contract is refused.

Request body (JSON, at most 16 MiB):

```json
{
  "export": "devices",
  "filters": [{"label": "Platform", "value": "macOS"}],
  "columns": ["Hostname", "Platform"],
  "rows": [["mac-01", "macOS"]],
  "total_rows": 12345
}
```

| Field | Rule |
| --- | --- |
| `export` | Required. One of the keys below. |
| `filters` | Optional, at most 20. Printed under the title as `label: value`. |
| `columns` | Required, 1 to 40 non-blank strings, each at most 120 characters. |
| `rows` | Required, may be `[]`, at most 10,000. Each row is exactly `len(columns)` strings. |
| `total_rows` | Optional, not negative. When greater than `len(rows)` the PDF says it shows the first `len(rows)` of `total_rows` rows and that the CSV holds the full list. |

Export keys and the title each prints with:

| Key | Title |
| --- | --- |
| `devices` | Devices |
| `devices-stale` | Stale devices |
| `jamf-coverage` | Jamf coverage |
| `findings` | Findings |
| `homebrew` | Homebrew packages |
| `local-admins` | Local administrators |
| `ai-tooling` | AI tooling |
| `ai-tooling-device` | AI tooling on one device |
| `software-unsupported` | Unsupported software |
| `software-unsupported-devices` | Unsupported software: installations |
| `software-remote-access` | Remote access software |
| `software-remote-access-devices` | Remote access software: installations |
| `software-version-sprawl` | Software version sprawl |
| `software-duplicate-tools` | Duplicate tools |
| `software-publishers` | Software publishers |
| `software-publishers-devices` | Software publishers: installations |

Responses:

- `200`, `Content-Type: application/pdf`,
  `Content-Disposition: attachment; filename="<export>.pdf"`,
  `Cache-Control: private, no-store`.
- `400 invalid_request` (`writeApprovalError`'s body shape) for an unknown
  export key, an unknown field at any level, malformed JSON or anything after
  the one JSON document, missing, empty or blank `columns`, more than 40
  columns, a column name over 120 characters, missing `rows`, a row whose
  length differs from `columns`, a cell that is not a string, more than
  10,000 rows, more than 20 filters, or a negative `total_rows`.
- `403 admin_role_required` when `export` is `local-admins` and the caller is
  not an admin, the same rule and body as `GET /v1/portal/local-admins`.
  Every other key is open to every portal role, as the page data is.
- `413 body_too_large` over 16 MiB.
- `405` for any method but `POST`.
- The read-only service identity is refused `403` by the middleware, as on
  every non-GET route.

The PDF is A4 landscape with the customer report header, the title, the
tenant name, the generated time in UTC, the filters, the row count and the
table. The column header row repeats on every page and the footer reads
"Page X of Y". Column widths are fitted to the content. Cell text wraps and is
never cut: a token wider than its column breaks across lines, and a row moves
to the next page whole unless it is taller than a page. Zero rows prints "No
rows for this selection." Characters the PDF font path cannot carry
(malformed UTF-8 and anything above U+FFFF, such as emoji) print as U+FFFD
rather than being dropped; control characters print as spaces.

## Jamf Pro coverage (PAT-2145)

Which Macs the customer's Jamf Pro manages that Patched has never seen, and
which Macs Patched sees that no MDM manages. Built only from webhooks the
customer's Jamf Pro pushes to `POST /v1/webhooks/jamf/{webhookID}` (public
API, not a portal route; see `go-service/docs/API.md`) and from the agents'
own evidence. Patched never holds a Jamf API credential (PAT-1666). Intune
is out of scope here.

Every portal role reads. Writes (token create/rotate/revoke, the check-in
subscription) need role `admin`, re-read inside the write transaction, and
any other role gets `403 admin_role_required` in the software-approvals
error shape. Each write is recorded in the append-only `jamf_webhook_audit`
with the caller's verified email. The tenant comes only from the verified
portal identity.

### GET /v1/portal/mdm/jamf/setup

No query parameters (`400` otherwise).

```json
{
  "configured": true,
  "webhook_url": "https://api.patched.im/v1/webhooks/jamf/q3Xb...32 characters",
  "token": {"exists": true, "created_at": "...", "issued_at": "...", "last_rotated_at": null,
            "revoked_at": null, "plaintext_shown": "once, when created or rotated"},
  "check_in_enabled": false,
  "events": [
    {"event": "ComputerAdded", "required": true, "subscribed": true, "purpose": "a Mac enrolled in Jamf Pro"},
    {"event": "ComputerInventoryCompleted", "required": true, "subscribed": true, "purpose": "..."},
    {"event": "DeviceAddedToDEP", "required": true, "subscribed": true, "purpose": "..."},
    {"event": "ComputerCheckIn", "required": false, "subscribed": false, "purpose": "optional: ..."}
  ],
  "authentication": {"type": "Header Authentication", "content_type": "JSON",
                     "header_json": "{\"Authorization\":\"Bearer <your webhook token>\",\"X-Patched-Jamf-Instance\":\"https://<your instance>.jamfcloud.com\"}",
                     "alternative": "Basic Authentication with any username and the webhook token as the password",
                     "instance_header_note": "..."},
  "jamf_instance": {"url": null, "last_claimed": null, "mismatch": false, "mismatch_seen_at": null},
  "patched_holds": "no Jamf credential; Jamf Pro pushes webhooks to Patched"
}
```

Before setup: `configured: false`, `webhook_url: null`, `token.exists: false`.
The token is never readable here. `webhook_url` is built from
`JAMF_WEBHOOK_PUBLIC_BASE_URL`; the ID is opaque and never the tenant id.
The portal should tell the admin to create one webhook in Jamf Pro per
subscribed event (Settings > Global Management > Webhooks), all pointing at
this URL with Content Type JSON and the Header Authentication JSON above.

### PUT /v1/portal/mdm/jamf/setup (admin)

Body `{"check_in_enabled": true|false, "reset_jamf_instance": true}`,
either or both (strict: unknown or case-variant keys `400`;
`reset_jamf_instance: false` is `400`). `409 not_configured` before a token
exists. Response `{"changed": bool, "setup": <the GET shape>}`. While
check-in is off, Jamf `ComputerCheckIn` events are refused
`422 event_not_subscribed`. `reset_jamf_instance` forgets the pinned Jamf
Pro instance (after a planned move); the next event's claim is pinned.

### POST /v1/portal/mdm/jamf/token (admin)

No body, or `{}`. Creates the connector and its first token (`201`,
`"action": "token_created"`) or rotates the token (`200`, `"token_rotated"`).
On rotation the old token stops working when the request commits; the
webhook URL does not change, so the admin only replaces the token in Jamf
Pro. A new token also clears the pinned Jamf instance, so the next event's
claim is pinned afresh. `Cache-Control: no-store`.

```json
{"action": "token_created", "token": "pjwh_<43 characters>",
 "webhook_url": "https://api.patched.im/v1/webhooks/jamf/<id>",
 "note": "This token is shown once. ...", "setup": { ... }}
```

The plaintext is in this response only; Patched stores its SHA-256. A lost
token is rotated, never retrieved.

### DELETE /v1/portal/mdm/jamf/token (admin)

Revokes the token, and **deletes the Jamf device records first seen under
that token** (anything a leaked token could have fabricated); Macs first
seen under an earlier token are kept. Every Jamf event is `401` until a new
token is created, and coverage then refills from Jamf's next events, so the
portal must say so before the admin confirms. `{"action": "token_revoked",
"changed": bool, "devices_deleted": n, "note": "Revoking deleted the n Jamf
device records first seen under this token. ...", "setup": { ... }}`;
`changed: false` (and nothing deleted) when there was no active token.

### DELETE /v1/portal/mdm/jamf/devices (admin)

No body, or `{}`. Deletes every Mac Jamf has reported for the tenant. The
connector, token and webhook URL are kept, and the lists refill from Jamf's
next events. `{"action": "devices_purged", "changed": bool,
"devices_deleted": n, "setup": { ... }}`. `409 not_configured` without a
connector. Audited with the count.

### GET /v1/portal/mdm/jamf/coverage

Query: `bucket` (`gap`, `not_reported_by_jamf`, `covered`, `os_not_reported`; omitted returns all four),
`limit` (1 to 500, default 100) and `offset` (applied to each bucket
returned), `format` (`json` default, `csv`). Unknown parameters `400`.
`422 estate_too_large` above 50,000 Jamf or Patched devices.

```json
{
  "generated_at": "2026-09-26T12:00:00Z",
  "connector": {
    "status": "ok", "amber": false, "message": "Receiving Jamf events.",
    "token_active": true, "first_event_at": "...", "last_event_at": "...", "hours_since_last_event": 0,
    "events_rejected": 0, "last_rejected_at": null, "last_rejected_reason": null,
    "check_in_enabled": false, "amber_after_hours": 24,
    "jamf_instance": {"url": "https://acme.jamfcloud.com", "last_claimed": "https://acme.jamfcloud.com",
                      "mismatch": false, "mismatch_seen_at": null}
  },
  "basis": {
    "since": "2026-09-01T09:12:00Z", "statement": "From Jamf webhooks since 1 September 2026.",
    "no_backfill": "...", "no_delete_event": "...", "silent_after_days": 30,
    "match_basis": "serial_then_udid", "scope": "macOS devices only. ...", "seed": "..."
  },
  "counts": {
    "gap": 2, "gap_dep_assigned_only": 1, "gap_silent": 1,
    "not_reported_by_jamf": 5, "not_reported_by_jamf_by_mdm_state": {"other_mdm": 1, "jamf_no_event_yet": 1,
      "enrolled_mdm_unidentified": 0, "unmanaged": 2, "unknown": 1},
    "agent_reports_no_mdm": 2,
    "covered": 2, "covered_jamf_silent": 0, "jamf_devices_total": 5,
    "retired_excluded": 1, "non_mac_devices_excluded": 1, "os_not_reported": 1
  },
  "bucket": null, "limit": 100, "offset": 0,
  "gap": {"total": 2, "rows": [
    {"jamf_id": 61, "serial": "C02SILENT01", "udid": null, "device_name": "a-silent-mac", "model": "MacBookPro18,3",
     "os_version": "15.6", "jamf_state": "enrolled", "first_jamf_event_at": "...", "last_jamf_event_at": "...",
     "last_jamf_event_type": "ComputerAdded", "days_since_jamf_event": 45, "note": "not heard from Jamf in 45 days"}]},
  "not_reported_by_jamf": {"total": 5, "rows": [
    {"device_id": "uuid", "hostname": "mac-other", "serial": "C02OTHER001", "os_version": "15.6", "last_seen": "...",
     "mdm_state": "other_mdm", "mdm_vendor": "Microsoft Intune", "mdm_server_host": "i.manage.microsoft.com",
     "note": "enrolled with Microsoft Intune (i.manage.microsoft.com)"}]},
  "covered": {"total": 2, "rows": [
    {"device_id": "uuid", "hostname": "mac-both", "serial": "C02BOTH0001", "last_seen": "...", "jamf_id": 63,
     "jamf_device_name": "both-mac", "last_jamf_event_at": "...", "days_since_jamf_event": 0,
     "match_basis": "serial", "note": ""}]},
  "os_not_reported": {"total": 1, "rows": [
    {"device_id": "uuid", "hostname": null, "serial": null, "os_version": null, "last_seen": "..."}]}
}
```

`connector.status`: `not_configured` (no token ever created), `revoked`,
`awaiting_first_event` (no event yet, set up under 24 hours ago), `amber`
(no event for 24 hours or more, or the latest event claims a different Jamf
instance from the first) or `ok`. `amber` is true for `revoked` and `amber`.

Matching: serials normalised as the device list does (trimmed, upper case,
placeholders such as `To be filled by O.E.M.`, `0` or all zeros count as
none). Two real serials match only if equal. Otherwise the Jamf UDID is
compared with the device's hardware UUID (`match_basis: "udid"`).

- `gap`: Jamf has reported it, no Patched device matches. `jamf_state`
  `dep_assigned_only` means Jamf sent only `DeviceAddedToDEP` (assigned in
  Apple Business Manager, no enrolment event since).
- `not_reported_by_jamf`: a macOS device Patched sees that no Jamf event
  matches. This is not a claim the Mac is unmanaged: Jamf's silence is not
  authority (no backfill, no delete event). Only `mdm_state: "unmanaged"`,
  from the agent's own evidence, means no MDM (`agent_reports_no_mdm`).
  `mdm_state` comes from the agent's own evidence: the latest successfully
  collected applied-configuration snapshot's MDM server (PAT-1667) and the
  `mdm_enrolled` signal (legacy `mdm_enrolment` when absent).
  `other_mdm` (enrolled elsewhere, including a Jamf host when no instance
  is claimed; `mdm_vendor` named from the server host when recognised, else
  `null` with the host), `jamf_no_event_yet` (the Mac says it is enrolled
  with the Jamf Pro instance this tenant's events claim, but Jamf has sent
  nothing for it since setup),
  `enrolled_mdm_unidentified` (enrolled, server not reported), `unmanaged`
  (the agent reports no enrolment) or `unknown` (no evidence).
- `covered`: both.
- `os_not_reported`: any live Patched device whose OS is NULL, empty
  or whitespace. Its platform cannot yet be established, so it is neither
  a known non-Mac exclusion nor classified from MDM evidence. Rows use the
  same hostname then device-id ordering and pagination as the other buckets.
  This diagnostic bucket overlaps `covered` when serial or UDID matches
  a Jamf event; do not sum it with coverage classes as distinct devices.
  Retired devices remain excluded. `counts.os_not_reported` is the full
  diagnostic bucket size.

Caveats the portal must show with every count: the `basis.statement`
("From Jamf webhooks since <date>"); there is no backfill, so a Mac Jamf has
not reported since setup is in no bucket; Jamf sends no delete event, so a
quiet Mac reads "not heard from Jamf in N days" (from 30 days) and is never
called removed or unmanaged. Retired devices (PAT-2135) are excluded:
`retired_excluded` counts Jamf Macs that match only retired devices. Windows
devices are never in `not_reported_by_jamf` (`non_mac_devices_excluded`).

Seeding from before setup: a Jamf Pro computer export (Computer Name, Serial
Number) can be uploaded as the customer device list
(`PUT /v1/portal/device-list`); its "on your list, never seen" view covers
the pre-setup gap. It does not change these buckets, and there is no second
upload path.

CSV (`?format=csv`, optionally with `bucket`): every row, unpaged, header
`bucket, device_id, hostname, serial, udid, jamf_id, jamf_device_name,
model, os_version, patched_last_seen, first_jamf_event_at,
last_jamf_event_at, days_since_jamf_event, jamf_state, mdm_state,
mdm_vendor, mdm_server_host, match_basis, note, basis, generated_at`, with
`basis` on every row and formula injection neutralised.

## Reports

Portal reports are stored as immutable `report_records` rows with
`source = 'portal'` and a stable `report_type`; the portal lists and serves
only those rows. Tenant identity always comes from the verified portal auth
context. It is never accepted from a report or schedule request.

### Roles (PAT-2406, PAT-2408; ruled 2026-10-05)

Viewers can generate reports but only admins change schedules, and the Local
Admin report is admin only.

| Route | Admin | Viewer (and a domain-matched identity) | Read-only service identity |
| --- | --- | --- | --- |
| `GET /reports/catalogue` | every type; `local-admin` carries `"admin_only": true` | every type except `local-admin` | as a viewer |
| `GET /reports` | every record | every record except `local-admin` ones; `total` counts only what is shown | as a viewer |
| `POST /reports` | every type | every type except `local-admin` (`403`) | refused: read-only |
| `GET /reports/{id}` | every record | every record except a `local-admin` one (`403`) | as a viewer |
| `GET /reports/schedule`, `/schedules`, `/schedules/{reportType}` | yes | yes | yes |
| `PUT /reports/schedule`, `/schedules/{reportType}` | yes | `403` | refused: read-only |

Every refusal in this table is `403 admin_role_required` with the
`{"error","message"}` body the other admin-only routes use; nothing is written
and no file bytes are sent. Which reports are admin only is one registry flag
(`report.ReportDefinition.AdminOnly`), so the four routes cannot disagree. The
Local Admin report is restricted because it prints the standing
local-administrator roster (account names, personal data): it follows the rule
of `GET /v1/portal/local-admins` (PAT-2215) and of the `local-admins` table
export (PAT-2405). The rule applies to a stored record however it was generated,
so a viewer cannot download a Local Admin report an admin or a schedule
produced. Another tenant's record is `404` whatever its type. The role is read
at the point of use, so a demotion takes effect on the next request.

### GET /v1/portal/reports/catalogue

Returns the fourteen customer-facing tenant report definitions, including
PAT-2009's `new-software` (New Software), `software-drift` (Unapproved &
Unreviewed Software, which carries the Unapproved-present list) and
`approved-software` (Approved Software List), PAT-2205's
`ai-tooling-evidence` (AI Tooling Evidence) and PAT-2258's
`insurance-evidence` (Cyber Insurance Evidence Pack, whose JSON and CSV form
is `GET /v1/portal/insurance-evidence`). Their PDF and CSV
are generated by `POST /v1/portal/reports` like every other type (PAT-2405);
the live `/v1/portal/software/*?format=csv` reads above are separate
endpoints. Each entry has
`type`, `label`, `description`, `default_frequency`, and `subject_scope`.
An admin-only report additionally has `"admin_only": true` (PAT-2406). The
field is additive and absent on every other entry. Such an entry is sent to an
admin only: any other caller gets the catalogue without it (thirteen entries
today), so a client that predates the field never offers a viewer a report it
cannot generate.
Internal admin paths and internal-only reports are omitted. The handler has an
explicit entitlement-filter seam after the customer-facing filter, but v1 does
not filter this catalogue by tenant tier.

### GET /v1/portal/reports

History, newest first. Paginated (`limit`/`offset` as above). Records of an
admin-only report type are left out for a caller who is not an admin, and
`total` counts only the records that caller is shown (PAT-2406).

```json
{
  "total": 3,
  "reports": [
    {
      "id": "7f3c5e2a-…",
      "name": "Patch evidence",
      "report_type": "patch-status",
      "report_label": "Patch & Update Status",
      "generated_at": "2026-07-02T17:00:00Z",
      "formats": ["pdf", "csv"]
    }
  ]
}
```

`formats` lists the files the report can be downloaded as: `["pdf","csv"]`, or
`["pdf"]` for a report generated before CSV renderings existed (PAT-2405).

### POST /v1/portal/reports

Generates one customer-facing report synchronously, stored as a PDF and a CSV
rendered from the same fetched data (PAT-2405). `report_type` is the canonical
field; `type` is accepted as a rollout alias. If both are present they must be
identical. Unknown and internal-only types return `400`. Omitting both selects
`executive-summary` for compatibility with clients deployed before PAT-1847.
Unknown JSON fields are rejected.

```json
{ "report_type": "patch-status", "name": "Board pack July" }
```

The supported values are `executive-summary`, `cis-compliance`,
`patch-status`, `cve-report`, `stale-endpoints`, `encryption-posture`,
`cert-expiry`, `local-admin`, `edr-coverage`, and (PAT-2009) `new-software`,
`software-drift`, `approved-software`, `ai-tooling-evidence` and (PAT-2258)
`insurance-evidence`. Every role may generate, except that `local-admin` is
admin only (`403 admin_role_required`, nothing stored; PAT-2406). An invalid
body or type is still `400` for any role. `name` defaults to the
customer label plus `YYYY-MM-DD`, truncated to 120 characters. All fourteen types
reuse their Go report fetch and render engines; no admin HTTP handler is called.
Response `201 Created`:

```json
{
  "id": "7f3c5e2a-…",
  "name": "Board pack July",
  "report_type": "patch-status",
  "report_label": "Patch & Update Status",
  "generated_at": "2026-07-02T17:00:00Z",
  "formats": ["pdf", "csv"]
}
```

### GET /v1/portal/reports/{id}

Streams one file of the report. `format` selects it: `pdf` (the default; an
absent or empty `format` is the PDF, so existing links keep working) or `csv`
(PAT-2405). Any other value, and a repeated `format` parameter, is `400`.

| Format | Response |
| --- | --- |
| `pdf` | `200`, `application/pdf`, `attachment; filename="<name>.pdf"` |
| `csv` | `200`, `text/csv; charset=utf-8`, `attachment; filename="<name>.csv"` |

`<name>` is the report name with every character outside `A-Za-z0-9._-`
replaced by `_`. `404` for unknown, other-tenant, non-portal-source, or archived
records, in either format. A report generated before CSV renderings existed has
no CSV: `?format=csv` answers `404` with
`{"error":"csv_not_available","message":...}` and its PDF still downloads.
Role, tenant scoping and audit are exactly the PDF's: every role downloads its
own tenant's report, and the read-only service identity reads both formats of
its own tenant. The one exception is a record of an admin-only report type
(`local-admin`, PAT-2406): anyone but an admin of the tenant gets
`403 admin_role_required` in either format and no file bytes, whether an admin
or a schedule generated the record.

#### CSV shape

UTF-8, no byte-order mark, standard CSV quoting, `\n` line endings. The first
row is a header; a report with no rows is the header alone. Every cell, the
header included, is neutralised against spreadsheet formulas: a cell that starts
with `=`, `+`, `-`, `@`, tab or carriage return gets a leading `'`. An unknown
value (a count with no usable signal, a missing time) is an empty cell, never a
sentinel number. Times are RFC 3339 UTC.

Every report except the executive summary has a leading `generated_at` column.
A report whose PDF has more than one table adds a `section` column after it and
the union of the tables' columns, left empty where a section has none:
`cis-compliance` (`summary`, `control`, `device`), `stale-endpoints` (`stale`,
`retired`), `cert-expiry` (`actionable`, `platform_root`, `suspicious`),
`encryption-posture` (`device`, `finding`), `software-drift` (`product`,
`unapproved_present`, `top_device`, `trend`). The executive summary is
`metric,value` rows: the summary figures, then the findings, devices not
reporting, roster and hardware sections with the section in the metric label.
No report carries primary-user data beyond what its PDF shows; `local-admin`
carries `admin_names` exactly as its PDF does.

## Scheduled reports (PAT-703, PAT-1847)

One recurring schedule per tenant and customer-facing report type
(`portal_report_schedules`, migrations 0061 and 0148). An in-process scheduler
in `patched-api` ticks every minute,
claims due schedules (`enabled AND next_run_at <= now()`, `FOR UPDATE SKIP
LOCKED`), and generates the selected report through the same typed generation
path as `POST /v1/portal/reports`, so a scheduled report has both its PDF and its CSV. Scheduled reports land in the same
`source = 'portal'` history. Email delivery is deferred for v1: a scheduled
report is sent to nobody, it only appears in the history, where the role rules
above apply to it. Reading a schedule is open to every role; creating or
changing one is admin only (PAT-2408).

Semantics:

- `weekday` — `0=Sunday … 6=Saturday`; required iff `cadence = "weekly"`.
- `month_day` — `1–31`; required iff `cadence = "monthly"`. Days 29–31 clamp
  to the last day of shorter months (the 31st runs on Feb 28/29, Apr 30, …);
  the clamp never skips a month.
- `hour_utc` — `0–23`, always required. Runs fire at minute 0 UTC.
- `next_run_at` is **always computed server-side** and never accepted from the
  client. A slot that already ran (e.g. replayed after a restart) is skipped,
  not duplicated.
- Crash recovery is keyed by `(tenant_id, report_type, schedule_slot)`, so two
  report types may run at the same instant without suppressing each other.
- Generation failures retry after 15 minutes without moving `last_run_at`.

### GET /v1/portal/reports/schedule

Compatibility alias for the `executive-summary` schedule. `200` always;
"not configured yet" is a normal state, not a 404:

```json
{
  "configured": true,
  "report_type": "executive-summary",
  "report_label": "Executive Estate Summary",
  "cadence": "weekly",
  "weekday": 1,
  "hour_utc": 7,
  "enabled": true,
  "last_run_at": "2026-12-29T07:00:12Z",
  "next_run_at": "2026-07-06T07:00:00Z",
  "updated_at": "2026-12-25T10:14:02Z"
}
```

Unconfigured: `{"configured": false, "enabled": false}`. `month_day` appears
instead of `weekday` for monthly cadence; neither appears for daily.
`last_run_at` is `null`/absent until the first scheduled run.

### PUT /v1/portal/reports/schedule

Compatibility alias that creates or replaces the tenant's
`executive-summary` schedule. Body rules and the admin-only role rule are
identical to the typed PUT below.

### GET /v1/portal/reports/schedules

Returns `{"schedules": [...]}` containing every report schedule configured by
the authenticated tenant, ordered by `report_type`. Types with no schedule are
omitted. Another tenant's rows are never visible.

### GET /v1/portal/reports/schedules/{reportType}

Returns one customer-facing type using the same response shape as the legacy
GET. An unconfigured type returns `configured: false`. Unknown or internal-only
types return `400`.

### PUT /v1/portal/reports/schedules/{reportType}

Creates or replaces one schedule for the authenticated tenant and report type.
Admin role only (PAT-2408): any other caller gets `403 admin_role_required`
and nothing is written. The role is re-read inside the transaction that writes
the schedule, with the caller's `portal_users` row held `FOR SHARE`. Body and
type validation run first, so a malformed request is `400` for any role.
Unknown fields are rejected:

```json
{ "cadence": "weekly", "weekday": 1, "hour_utc": 7, "enabled": true }
```

| Field | Rules |
|---|---|
| `cadence` | required: `daily` \| `weekly` \| `monthly` |
| `weekday` | required iff weekly, `0–6` (0=Sunday); forbidden otherwise |
| `month_day` | required iff monthly, `1–31`; forbidden otherwise |
| `hour_utc` | required, `0–23` |
| `enabled` | required boolean |

`200` with the same shape as GET (`next_run_at` freshly computed). `400` with
a plain-text reason on any validation failure; nothing is persisted.
`last_run_at` survives settings changes, so an update cannot cause a
double-run within the same period.

## Agent enrolment token (PAT-453)

Mints a single-use, 24h agent enrolment token for the caller's own tenant —
the same `bootstrap_tokens` / `enrollment_token_audit` mechanism as the admin
mint (`POST /admin/tenants/{id}/bootstrap-tokens`), reached through a
customer-facing route instead of an operator action. The minted token
redeems exactly like any other via `POST /v1/enrol` (unauthenticated,
pre-auth device provisioning) and issues per-device bearer+HMAC credentials.

### POST /v1/portal/enrolment

Admin role only (PAT-2407): any other caller gets `403 admin_role_required`
(`{"error","message"}` body) and no token is written. That covers a
`viewer` and an identity resolved through `tenant_email_domains`, which has
no `portal_users` row and is always `viewer`. The role is re-read in the
transaction that inserts the token, the same check as
`POST /v1/portal/enrolment-keys`, and it runs before the dedicated rate
limit, so a refused call does not spend the tenant's mint budget.

Body optional; the only accepted field is `delivery_path`, and only `"mdm"`
is currently valid on this surface (unlike the admin mint, which also
accepts `"email-link"` for operator-driven delivery):

```json
{ "delivery_path": "mdm" }
```

`delivery_path` defaults to `"mdm"` when omitted. Unknown fields — including
a client-supplied `tenant_id` — are rejected outright (`400`); **the tenant
always comes from the verified portal identity, never from the request
body.**

`201 Created`:

```json
{
  "enrollment_token": "eee_EXAMPLEtokenEXAMPLEtokenEXAMPLEtoken00",
  "tenant_id": "5f9c1a2b-…",
  "token_id": "6d75459e-…",
  "expires_at": "2026-07-13T11:26:21Z"
}
```

`enrollment_token` is returned once and is not recoverable — store it
immediately (same rule as the admin mint's `bootstrap_token`/
`enrollment_token`).

Errors: `400` invalid JSON / unknown field / bad `delivery_path`, `401`/`503`
per the whole-surface auth rules above, `403 admin_role_required` if the
caller is not an admin, `409` if the caller's own tenant
carries an active (non-`"none"`) agent-decommission directive (PAT-1757:
see below), `429` per the **dedicated** rate limit below (distinct from the
general per-identity portal limit; see Environment).

**Decommissioned tenant (PAT-1757):** minting is refused with `409` for a
tenant whose `tenant_decommission` directive mode is not `"none"`:
`{"error": "...", "mode": "immediate", "set_at": "2026-09-14T…Z"}`. A freshly
minted token would let a device enrol into a tenant scheduled for agent
removal, and the new agent would receive (and act on) that directive on
its very first config poll: enrol, then immediately self-uninstall and
purge. There is no override flag; the only path past this is clearing the
directive first via `PUT /admin/tenants/{id}/decommission` with
`mode=none`. The same guard applies to the admin mint
(`POST /admin/tenants/{id}/bootstrap-tokens`, both share
`mintTenantEnrolmentToken`) and to `POST /v1/enrol` itself, which
independently refuses to redeem ANY token (including one minted before the
directive was set) against a decommissioned tenant.

**Rate limit:** a separate, per-**tenant** limiter — not the per-identity
`PORTAL_RATE_LIMIT_RPM` above, which is far too loose for a credential-
issuing mint. Default 10 mints/hour/tenant (`PORTAL_ENROL_MINTS_PER_HOUR`,
window `PORTAL_ENROL_WINDOW_MINUTES`). Every portal admin at a tenant shares
one mint budget; a 429 for one tenant never affects another.

**Audit:** every mint writes an `enrollment_token_audit` row including
`actor_email` — the caller's verified email (migration 0077). The admin
mint path has no per-user identity (admin auth is a shared token) and
always writes `actor_email = NULL`.

**Invalidate-on-regenerate, scoped by delivery_path (PAT-836):** minting a
new token supersedes the tenant's prior unconsumed token(s) of the **same**
`delivery_path` only — never tokens of the other path, and never touched by
a mint on the other path. `email-link` (single download link, one per
tenant) supersedes on remint; `mdm` (fleet enrolment — N devices legitimately
enrol concurrently against N outstanding tokens) never supersedes anything,
by design. This surface only ever mints `mdm` (see above — `delivery_path`
here accepts only `"mdm"`), so a portal re-mint never invalidates a
still-outstanding portal-issued token; the supersede behaviour is only
observable through the admin mint's `email-link` path
(`POST /admin/tenants/{id}/bootstrap-tokens?path=email-link`). A superseded
token redeems exactly like an expired or already-consumed one at
`POST /v1/enrol` — `410 Gone`, `"enrollment_token superseded by a newer
token"` — permanently unredeemable, never silently treated as
generic-invalid.

---

## Tenant enrolment keys (PAT-2250)

A reusable, revocable enrolment credential for estate rollouts through
Intune, Jamf or an RMM: one key, many devices, over weeks. It is supplied
alongside the generic signed installer, never baked into the package, and it
redeems at `POST /v1/enrol` in the **same field** as a single-use token
(`enrollment_token`, or legacy `bootstrap_token`), so the MSI
`ENROLLMENT_TOKEN` property and the macOS `enrollment.json` /
`/etc/patched/enrollment-token` paths carry it with no agent change.
Single-use tokens (above) are unchanged.

Key format: `pek_` + base64url(32 random bytes). Only SHA-256 of the key is
stored (`tenant_enrolment_keys`, migration 0211), with a four-character hint
(`key_hint`, e.g. `pek_Ab3x`) to match a leaked key to its row. The plaintext
is returned once by create and is never logged.

### POST /v1/portal/enrolment-keys

Admin role only (`403 admin_role_required` otherwise). Body, strict JSON (no
other fields; a `tenant_id` is refused with `400`):

```json
{ "label": "Intune rollout", "max_devices": 250, "expires_in_days": 30 }
```

`label` 1 to 100 characters, no control characters. `max_devices` 1 to
100000. `expires_in_days` 1 to 365, default 30. `201 Created`:

```json
{
  "key_id": "6d75459e-…",
  "label": "Intune rollout",
  "key_hint": "pek_Ab3x",
  "max_devices": 250,
  "devices_enrolled": 0,
  "status": "active",
  "expires_at": "2026-10-28T11:26:21Z",
  "created_at": "2026-09-28T11:26:21Z",
  "created_by": "admin@example.com",
  "revoked_at": null,
  "revoked_by": null,
  "enrollment_key": "pek_…",
  "warning": "This key is shown once. Store it now; Patched keeps only a hash."
}
```

Errors: `400` validation, `403` not an admin, `409` active decommission
directive (same body as the single-use mint), `429` the per-tenant
`PORTAL_ENROL_MINTS_PER_HOUR` budget, which key creation shares with
`POST /v1/portal/enrolment`.

### GET /v1/portal/enrolment-keys

Every role. `{"keys": [ … ]}`, newest first, each the object above without
`enrollment_key` or `warning`. `devices_enrolled` counts distinct devices
that have enrolled with the key. `status` is `revoked`, `expired`,
`exhausted` (`devices_enrolled >= max_devices`) or `active`, in that
precedence.

### POST /v1/portal/enrolment-keys/{keyID}/revoke

Admin role only. Body empty or `{}`. `200 {"key_id", "revoked_at",
"changed"}`; revoking an already revoked key is `changed: false`. A key that
does not exist or belongs to another tenant is `404`. Revocation stops new
enrolments immediately; devices already enrolled keep their credentials.

### Redemption at POST /v1/enrol

Each successful enrolment records a `tenant_enrolment_key_uses` row (key,
device, `hw_uuid`, time). The cap counts distinct `hw_uuid`, enforced
atomically under a row lock on the key, so concurrent enrolments at
`max_devices - 1` admit exactly one. Re-enrolling a device that already used
the key (wipe and reinstall) is admitted without taking a second slot.
A revoked, expired or exhausted key returns `410 Gone` like a consumed token
(`"enrollment_token revoked"`, `"… expired"`, `"… device limit reached"`).
The tenant always comes from the key. Trial device caps and decommission
directives apply exactly as for single-use tokens.

---

## Self-service organisation sign-up and access (PAT-1883)

A person with a verified email can create an organisation and become its
owner, and an owner can invite administrators and viewers and manage their
access, with nobody at Patched involved.

**Off by default.** Unless `SELF_SERVICE_SIGNUP_ENABLED` is set, every route
in this section answers `404` to a verified caller who uses the route's
method, with the same body as a path that was never mounted, and does
nothing. It is not otherwise identical to an unmounted route, and a consumer
should not rely on it being so:

- **A wrong method is `405`**, flag on or off (a path that was never mounted
  is `404` for every method). The routes stay in the route table and the flag
  is checked in the handler, so that a path can exist is visible to a
  verified caller who probes methods. Nothing else about it is.
- **Whatever the route group decides before a handler runs still comes
  first**, as on the rest of the surface: `503` (portal auth not configured),
  `401` (no valid JWT), `429` (the per-email request limit), and `403` for the
  read-only service identity on every sign-up route and on every write. In the
  tenant group, a person who belongs to no tenant is also `403` before the
  flag is looked at. The service identity's one permitted read here,
  `GET /v1/portal/access`, reaches the flag and is `404`.

Switching the flag off again is the rollback: no tenant, membership,
invitation or audit row is touched. The `owner` role itself does not depend on
the flag.

**Identity.** The verified Cloudflare Access email is the only identity. No
body, query parameter or header names the caller or a tenant.

**Bodies are strict**, as on the other portal writes. A body that carries any
key the route does not define is `400 invalid_request` and changes nothing.
That includes `tenant_id`, an `email` or `role` where the route takes none,
`owner_email`, `contact_email`, a case or Unicode-fold variant of a real key
(`Name`, `ROLE`), a duplicate key, and anything after the JSON object. A route
that takes no input (accept, revoke, disable, enable) accepts an empty body
(or one of white space only), `{}`, or a bare JSON `null`, none of which
carries a key, and refuses anything else the same way. So tenant membership cannot be
claimed from a request body: a body that tries is refused before any database
work on the sign-up routes, and after the owner check on the access routes. A
tenant-naming query parameter or header is not read at all and has no effect.
Bodies are limited to 4 KiB (`413`).

**Nothing here sends email.** The portal shows an invitee their invitations
when they sign in (`GET /signup/state`).

Errors use the `{"error": "<code>", "message": "<text>"}` body of the other
portal writes.

### GET /v1/portal/signup/state

Pre-membership group. What the caller can do, for their own email only.

```json
{
  "email": "someone@example.com",
  "member": false,
  "can_create_organisation": true,
  "pending_invitations": [
    {"id": "6d75459e-…", "organisation_name": "Example Ltd", "invited_by": "owner@example.com", "role": "admin", "expires_at": "2026-10-13T09:00:00Z"}
  ]
}
```

- `member`: the email resolves to a tenant, exactly as the rest of the surface
  would decide it (an enabled `portal_users` row on a live tenant, or a claimed
  email domain).
- `can_create_organisation`: the email has no `portal_users` row at all,
  enabled or not, no active tenant has claimed its domain, and the address is
  one `portal_users` can store (see `unsupported_email` below).
- `pending_invitations`: invitations addressed to this email that are pending,
  unexpired, from a tenant that is still live, and sent by someone who is
  still an enabled owner of that tenant (anything else could not be accepted).
  At most 50, newest first.
  This is the only place an organisation's name is shown to someone outside it,
  and only to a person it has invited. `organisation_name` is whatever the
  owner typed when they created the organisation. `invited_by` is the verified
  email address of the owner who sent the invitation, which they did not
  choose: a consumer should show it beside the name, so that an invitation
  nobody asked for is judged by who sent it.

### POST /v1/portal/signup/organisation

Pre-membership group. Body `{"name": "Example Ltd"}`: trimmed, 2 to 80
characters, at least two of them letters or digits, and none that a reader
cannot see. The name is shown to the people its owner invites, so it must not
be blank-looking or render in another order than it was typed. Refused anywhere
in the name: control characters; Unicode format characters (category Cf: the
zero-width space, joiners and marks, the bidirectional embeddings, overrides
and isolates, the byte order mark, the soft hyphen); line and paragraph
separators; private-use code points; and default-ignorable fillers that draw
nothing, such as the Hangul fillers. Letters and digits of any script count,
and an emoji keeps its variation selector. A name that needs a zero-width
joiner or non-joiner (some Persian and Indic spellings, and joined emoji) is
refused by this rule. Names are not unique and are never compared with another
organisation's.

`201 Created`:

```json
{"tenant_id": "<uuid>", "organisation_name": "Example Ltd", "role": "owner"}
```

One transaction creates the tenant and the caller's `portal_users` row with
role `owner`, and writes the `organisation_created` audit row. The tenant is
provisioned by the same code as `POST /admin/tenants` (initial credential,
pre-approved Patched Agent policies, compliance baseline) and is marked
`tenants.created_via = 'self_service'`. Its contact address
(`tenants.contact_email`, where alert and report mail goes) is the owner's
verified email, taken from the JWT and never from the request; a body that
carries a `contact_email` is refused like any other undefined key. The
tenant-level ingest credential is generated and discarded, never returned:
devices enrol through `POST /v1/portal/enrolment` or an enrolment key. No
trial or subscription state is set.

Single use and safe under concurrency. The `portal_users` primary key on email
is the arbiter: if the caller already has a row, or gains one while the request
runs, everything rolls back. However many requests one person sends at once,
one tenant and one owner result.

| Status | `error` | When |
|---|---|---|
| `400` | `invalid_request` | Body is not exactly `{"name": "..."}`: not one JSON object, or any other key present |
| `400` | `invalid_name` | `name` is not 2 to 80 characters, has fewer than two letters or digits, or has a control or invisible character |
| `400` | `unsupported_email` | The verified email is longer than 254 bytes, or is not in the lower-case form `portal_users` requires. Decided before anything is reserved or created |
| `409` | `already_member` | The email already has a `portal_users` row (in any tenant, enabled or disabled), or an active tenant has claimed its domain |
| `413` | `body_too_large` | Body over 4 KiB |
| `429` | `rate_limited` | A sign-up limit, with `Retry-After`; see "Limits" |

### POST /v1/portal/signup/invitations/{invitationID}/accept

Pre-membership group. No body: anything but an empty body, `{}` or `null` is
`400 invalid_request`, whether or not the invitation exists. The caller's verified
email must be the address the invitation was sent to. `200`:

```json
{"tenant_id": "<uuid>", "organisation_name": "Example Ltd", "role": "admin"}
```

One transaction locks the invitation, creates the caller's `portal_users` row
with the invited role, marks the invitation accepted and writes the
`invitation_accepted` audit row. Single use.

**An invitation is only as good as its sender's authority.** It can be
accepted only while the owner who sent it (`invited_by`) is still an enabled
owner of that tenant. If the operator has since disabled them, demoted them or
moved them to another tenant, accepting answers `410 invitation_revoked`,
with the same body as an invitation that was withdrawn, and creates nothing.
What that does and does not change:

- `GET /v1/portal/signup/state` does not offer such an invitation.
- Its stored status is not rewritten. `GET /v1/portal/access` still lists it
  as `pending` (or `expired` once past `expires_at`), with its `invited_by`.
- It still counts as the address's pending invitation, so inviting that
  address again is `409 invitation_pending` until an owner revokes it or it
  expires.
- If the sender becomes an enabled owner of the tenant again, the invitation
  can be accepted again, until it expires.
- Other owners' invitations are unaffected.

| Status | `error` | When |
|---|---|---|
| `404` | `not_found` | No such invitation, **or it is addressed to someone else**, or its tenant has been offboarded. Indistinguishable: an invitation cannot be probed by anyone but its invitee |
| `410` | `invitation_accepted`, `invitation_revoked`, `invitation_expired` | The caller's own invitation, no longer usable. `invitation_revoked` also covers an invitation whose sender is no longer an enabled owner of the tenant |
| `409` | `already_member` | The caller already has a `portal_users` row. The invitation stays pending |

### GET /v1/portal/access

Tenant group. Owner and admin. A viewer, a domain-matched identity and the
service identity get `403 admin_role_required`.

`limit` defaults to 100 and accepts 1..500; `offset` defaults to 0 and accepts
0..2147483647. Both accept decimal digits only. Empty, repeated, unknown,
malformed or out-of-range query arguments return `400 invalid_pagination`
after identity and role checks. Query arguments never select a tenant.

```json
{
  "role": "owner",
  "members_total": 1,
  "members_limit": 100,
  "members_offset": 0,
  "members_truncated": false,
  "invitations_total": 1,
  "invitations_limit": 500,
  "invitations_truncated": false,
  "members": [
    {"email": "owner@example.com", "role": "owner", "status": "active", "created_at": "…", "disabled_at": null, "disabled_by": null}
  ],
  "invitations": [
    {"id": "6d75459e-…", "email": "new@example.com", "role": "viewer", "status": "pending",
     "invited_by": "owner@example.com", "created_at": "…", "expires_at": "…",
     "accepted_at": null, "revoked_at": null, "revoked_by": null}
  ]
}
```

`role` is the caller's. `members` is one bounded page of `portal_users` rows of the tenant,
ordered by `created_at` ascending, then `email` ascending
(`status` `active` or `disabled`); people admitted only through a claimed
email domain have no row and are not listed. `disabled_by` is `null` on an
active member and `"owner"` or `"operator"` on a disabled one: who disabled
them, which decides who can enable them again (an owner only what an owner
disabled; see the member routes below). A member disabled before this was
recorded reads as `"operator"`. `invitations` is the newest 500,
in any state; `status` is `pending`, `expired`, `accepted` or `revoked`.
`expired` is computed when the row is read (a pending invitation past
`expires_at`): it is never stored and no job sweeps it. A `pending` invitation
whose `invited_by` is no longer an enabled owner of the tenant is still shown
as `pending` here but cannot be accepted (see the accept route); revoke it to
invite that address again.

Counts and both lists use one read-only, repeatable-read database snapshot.
`members_total` counts active and disabled rows, including on an empty page
beyond the last member. `members_truncated` means this response omits any
member (`len(members) < members_total`), including the last partial page at
a nonzero offset. It does not mean only that a later page exists. Invitations
are independently ordered by `created_at` descending then `id` ascending;
`invitations_total` counts every invitation and `invitations_truncated` reports
whether their fixed 500-row cap omitted any. Member pagination does not page
invitations. Consumers, including the future PAT-1884 access UI, must traverse
member pages or visibly report a partial list and must independently display
invitation incompleteness. They must never present a partial response as the
complete tenant access list. Pagination across requests assumes unchanged
membership; concurrent changes can shift offset boundaries.

### POST /v1/portal/access/invitations

Tenant group. **Owner only.** Body `{"email": "new@example.com", "role":
"admin"}`. `email` is one bare address (no display name, no list), stored
lower case. `role` is `admin` or `viewer`, never `owner`. `201 Created` with
the invitation object above. It can be accepted for
`PORTAL_INVITATION_TTL_HOURS` (default 168 hours). The per-tenant hourly
limit counts attempts from an authorised owner, including attempts refused
by the database or interrupted by a database outage.

Only the caller's own tenant is consulted. Whether the address is known to any
other tenant has no effect on the answer, so this route cannot be used to find
out. If it is, the invitee is told when they try to accept (`409
already_member`).

Inviting an address whose earlier invitation has expired withdraws the expired
one (recorded as a revocation by the inviting owner) and issues a new one with
a new id.

| Status | `error` | When |
|---|---|---|
| `400` | `invalid_request` | Body is not exactly `{"email", "role"}`: any other key, `tenant_id` included, is refused |
| `400` | `invalid_email`, `invalid_role` | `email` is not one valid address, or `role` is not `admin` or `viewer` |
| `403` | `owner_role_required` | The caller is not an owner. Decided before the body is read |
| `409` | `already_member` | The address is already a member of this tenant, enabled or disabled |
| `409` | `invitation_pending` | The address already has an unexpired pending invitation here |
| `409` | `invitation_limit_reached` | The tenant has 50 pending, unexpired invitations |
| `429` | `rate_limited` | `PORTAL_INVITATIONS_PER_HOUR` for this tenant, with `Retry-After` |

### POST /v1/portal/access/invitations/{invitationID}/revoke

Tenant group. **Owner only.** No body (`400 invalid_request` for anything but
an empty body, `{}` or `null`). `200 {"id", "status": "revoked", "revoked_at",
"changed"}`; revoking one that is already revoked is `changed: false`. A pending invitation can be revoked whether or not it has expired.
`404 not_found` for an id that does not exist or belongs to another tenant.
`409 invitation_accepted` for one that has been accepted: the person is a
member now, so disable them instead.

### PUT /v1/portal/access/members/{memberEmail}/role

Tenant group. **Owner only.** Body `{"role": "admin"}` and no other key
(`400 invalid_request`). `role` is `admin` or `viewer`; `400 invalid_role`
otherwise, including `owner`. `200 {"email", "role", "changed"}`; setting the
role a member already has is `changed: false`. A disabled member's role may
be changed, but this does not clear their disable marker or restore access;
the new role takes effect only after an authorised enable.

### POST /v1/portal/access/members/{memberEmail}/disable and /enable

Tenant group. **Owner only.** No body (`400 invalid_request` for anything but
an empty body, `{}` or `null`). `200 {"email", "disabled_at", "disabled_by",
"changed"}`. A disabled member is refused `403` on every route from the next
request, with no fallback to the tenant's email domain, and cannot create an
organisation under the same address. Enabling restores the same role.

Who disabled a member is recorded (`disabled_by`: `"owner"` here, `"operator"`
for `DELETE /admin/portal-users/{email}`), and an owner can enable only a
member an owner disabled:

- `disable` on an active member sets `disabled_by: "owner"`.
- `disable` on a member who is already disabled, by anyone, is `changed:
  false` and leaves the row as it is. It does not take over an operator's
  disable, and the answer carries the `disabled_by` that is in force.
- `enable` on a member an owner disabled clears both fields
  (`"disabled_at": null, "disabled_by": null`).
- `enable` on a member the operator disabled is `409 disabled_by_operator`
  and changes nothing. Only the operator can enable them again
  (`POST /admin/portal-users`), which clears `disabled_by` too. A member
  disabled before `disabled_by` was recorded counts as disabled by the
  operator.
- The operator's disable always records `"operator"`, also on a member an
  owner had already disabled, and keeps the first `disabled_at`.
- `enable` on an active member is `changed: false`.

For all three member routes:

- `{memberEmail}` is matched case-insensitively and may be percent-encoded.
  It is decoded exactly once, as any path segment is: `%40` is `@`, and a
  literal `%` in an address is sent as `%25` (`x%2541y@d.example` names the
  member `x%41y@d.example`, never `xAy@d.example`).
- `404 not_found` when the tenant has no `portal_users` row for that address,
  **including when the address belongs to another tenant**. Indistinguishable.
- `409 cannot_change_own_access`: an owner cannot change, disable or enable
  themselves.
- `409 cannot_change_owner`: nor another owner. Ownership transfer is not
  available.
- So no request can leave a tenant without an active owner. The server checks
  that before every commit all the same, and would answer `409 last_owner`.

### Limits

All in memory, per process: they reset when the service restarts, like every
other limit on this surface.

| Limit | Default | Applies to | Answer |
|---|---|---|---|
| Per verified email | `PORTAL_RATE_LIMIT_RPM` 120 | Every route here, shared with the rest of `/v1/portal` | `429` + `Retry-After` |
| Organisations, all callers | `SIGNUP_ORG_CREATIONS_PER_HOUR` 20 | `POST /signup/organisation` | `429 rate_limited` + `Retry-After` |
| Invitations per tenant | `PORTAL_INVITATIONS_PER_HOUR` 20 | `POST /access/invitations` | `429 rate_limited` + `Retry-After` |
| Pending invitations per tenant | 50 | `POST /access/invitations` | `409 invitation_limit_reached` |

The organisation ceiling counts organisations that were created, not requests
that tried: at most that many in any hour. A request takes a slot only when it
is about to create a tenant, and gives the slot back on every outcome except a
committed tenant. So a request that is refused first (an invalid name, an
undefined body key, a person who already belongs somewhere, an address that
cannot be stored) takes no slot, and one that gets further and then creates
nothing (the address gained a membership while the request ran, the database
failed, the caller went away) keeps none. Someone who can never succeed cannot
use up the budget every new customer shares, however often they try. A caller
who finds the ceiling full is refused before any provisioning work. While
creations are in flight `Retry-After` is a few seconds, since one of them may
yet fail; otherwise it is the time until the oldest organisation leaves the
hour.

**There is no per-client-address limit on sign-up, on purpose.** The portal
calls this API from its own server (`upstream.py`, one `requests` session,
forwarding only the Access JWT), so every sign-up reaches the platform from the
portal server's address. A per-address bucket would not tell customers apart:
it would be a second global cap under another name, and a lower one. Telling
them apart would need the portal to forward the browser's address in a header,
and the platform does not trust the portal for that, any more than it trusts it
for identity. What limits sign-up is who can pass Cloudflare Access with a
verified email, the per-email request limit, one organisation per email, and
the hourly ceiling.

### Audit

Every change writes one `portal_access_audit` row in the same transaction as
the change: `organisation_created`, `invitation_created`,
`invitation_accepted`, `invitation_revoked`, `role_changed`,
`member_disabled`, `member_enabled`, each with the acting email, the email it
was about, the roles before and after where they apply, the invitation id
where there is one, and the time. A refused or no-op request writes nothing.
Expiry is not an event: it is the invitation's `expires_at`. The ledger is
append-only and is not exposed by a portal route yet. See
`go-service/docs/SCHEMA.md` for its shape and for what a tenant purge does to
it.

---

## Admin CRUD — portal_users (internal listener only)

Email → tenant mapping management. Lives on the **internal** listener
(`:8081`, Tailscale-only) behind `ADMIN_API_TOKEN` — never public.

| Route | Behaviour |
|---|---|
| `GET /admin/portal-users[?tenant_id=<uuid>]` | `{"users": [{"email","tenant_id","tenant_name","role","created_at","disabled_at"}], "total": n}` |
| `POST /admin/portal-users` `{"email","tenant_id","role"?}` | `201` upsert. A re-POST re-enables a disabled mapping and moves tenant (idempotent onboarding). Optional `role` (`owner`, `admin` or `viewer`; PAT-2007, `owner` since PAT-1883): omitted, a new row is `viewer`, a re-POST on the same tenant keeps the role, a move to another tenant drops to `viewer`. `owner` is how an operator designates an owner for a tenant that was not created by sign-up, and is accepted only while `SELF_SERVICE_SIGNUP_ENABLED` is on: with it off, `"role": "owner"` is `400` with a message saying the role needs self-service sign-up enabled, and nothing changes (an existing owner row keeps its role, including on a re-POST that names no role). This route is not bound by the portal's owner guards, so an operator can also demote or disable an owner. Strict body: unknown, case-variant or duplicate keys are `400`. `400` bad email/UUID/role, `404` unknown tenant |
| `DELETE /admin/portal-users/{email}` | Soft-disable (`disabled_at` set; row survives for audit linkage). `200` `{"email","disabled_at"}`, `404` unknown. Records the disable as the operator's (`portal_users.disabled_by = 'operator'`, PAT-1883), also on a member an owner had disabled, so the tenant's owner cannot enable the member again; a re-POST of the address re-enables it and clears that marker |

## Environment

| Var | Meaning |
|---|---|
| `PORTAL_ACCESS_TEAM_DOMAIN` | CF Access team domain (`patchedim` or `example-team.cloudflareaccess.com`) |
| `PORTAL_ACCESS_AUD` | CF Access application AUD tag |
| `PORTAL_RATE_LIMIT_RPM` | Per-identity requests/minute (default 120) |
| `PORTAL_RATE_LIMIT_BURST` | Per-identity burst (default 30) |
| `PORTAL_ENROL_MINTS_PER_HOUR` | PAT-453: per-tenant cap on `POST /v1/portal/enrolment` mints per window (default 10) |
| `PORTAL_ENROL_WINDOW_MINUTES` | PAT-453: window the cap above applies over (default 60) |
| `JAMF_WEBHOOK_PUBLIC_BASE_URL` | PAT-2145: public origin of the Jamf webhook URL on the setup page (default `https://api.patched.im`) |
| `SELF_SERVICE_SIGNUP_ENABLED` | PAT-1883: switches on `/v1/portal/signup/*` and `/v1/portal/access*` (default `false`: all of them `404`) |
| `PORTAL_INVITATION_TTL_HOURS` | PAT-1883: how long an invitation can be accepted for (default 168) |
| `PORTAL_INVITATIONS_PER_HOUR` | PAT-1883: invitations one tenant may create per hour (default 20) |
| `SIGNUP_ORG_CREATIONS_PER_HOUR` | PAT-1883: organisations created in any hour across every caller (default 20) |

Both `PORTAL_ACCESS_*` unset → `/v1/portal/*` answers `503` (fail closed).

## Finding lifecycle event types

`GET /v1/portal/finding-lifecycle` returns each finding's latest event as
`status`; `GET /v1/portal/finding-lifecycle/history` returns every event as
`event_type` with its `source_type`, `actor` and `authoritative` flag. The
full semantics are in `go-service/docs/FINDING_LIFECYCLE.md`.

| Value | Meaning | Reads as |
|---|---|---|
| `first_observed`, `currently_observed`, `still_failing`, `recurred` | endpoint evidence shows the finding failing | open problem |
| `acknowledged`, `risk_accepted`, `guidance_issued`, `customer_applied`, `pending_verification` | operator or customer action | open, not fixed |
| `verification_unknown` | evidence stale or incomplete | not verified |
| `verified_fixed` | fresh authoritative endpoint evidence shows it passes | fixed (only when `authoritative` is true) |
| `withdrawn` (PAT-2107) | Patched retracted the finding: the CVE matcher's verdict changed while the device still reports the same software at the same version | **withdrawn: matcher correction, not a fix** |

`source_type` is `endpoint_observation`, `operator_action`, `migration` or,
for `withdrawn` only, `matcher`. A `withdrawn` row is never authoritative and
has no `observed_at` and no `verified_fixed_at`. A consumer must not render
`withdrawn` as fixed, resolved or remediated, and must treat any value it
does not recognise as neutral (never as fixed): new values can be added.


## Customer-managed certificate expiry (PAT-2389)

`GET /v1/portal/certificates` returns an array of the authenticated tenant's
agent certificate observations and uploaded public certificate metadata. Admins,
viewers and the existing read-only service identity may read it. All write routes
require a fresh database `admin` role, locked within the write transaction; an
already-issued JWT does not retain write access after demotion. Tenant identifiers
in query strings or JSON cannot change the verified tenant scope.

| Method and route | Request | Result |
|---|---|---|
| `POST /v1/portal/certificates` | JSON `label` and `certificate` (base64 of PEM or DER bytes) | `201` metadata; duplicate SHA-256 in the same tenant returns `200` with the existing id and label, without another audit row |
| `PATCH /v1/portal/certificates/{id}` | Optional `label`, optional `certificate` | `200` metadata; supplied label and replacement are atomic; replacement matching another record is `409` |
| `DELETE /v1/portal/certificates/{id}` | No body required | `204`; absent, already removed, other-tenant and agent-observation ids return `404` |

The decoded upload limit is 64 KiB; the entire JSON body limit is 96 KiB.
Exactly one X.509 public certificate is accepted. Private keys, mixed files,
multiple PEM blocks, PEM headers, leading non-whitespace text, trailing non-whitespace
PEM data, trailing DER data, invalid certificates and reversed validity dates
are rejected. Labels are trimmed, contain 1 to 200 Unicode characters and may
not contain control characters. Malformed input is `400`, size overflow `413`,
and a viewer write is `403`. Raw certificate bytes and keys are never persisted
or included in application logs.

Uploaded rows have `id`, `source: "uploaded"`, `label`, `subject_cn`, `issuer_cn`,
`fingerprint_sha256` (lowercase DER SHA-256 hex), `sha1` (legacy classification
fingerprint), `not_before` and `not_after` (UTC RFC3339), `ext_key_usage` (actual
OID strings), `basic_constraints_ca`, `is_self_signed`, `days_until_expiry`,
and `status`. They have no device or collection provenance. Self-signing requires
matching issuer/subject and a valid signature under the certificate's public key;
this is not a chain-trust verdict.

Expiry is recomputed at request time as the floor of remaining UTC seconds
based on `not_after`, in units of 24 hours. Negative days are `expired`, 0 to 7
`critical`, 8 to 30 `warning`, and over 30 `healthy`; a missing date is `unknown`.
This is an expiry status, not an assertion of certificate trust or installation.
Agent rows retain the legacy certificate fields, with portal-only additions of
`source: "agent"`, current `days_until_expiry` and `status`.

The operator `GET /admin/tenant/{tenant_id}/certs` also includes uploaded rows,
while retaining the exact existing agent response fields. Both reads accept
`device_id` (UUID, excludes uploads) and `expiring_within_days` (non-negative
integer; the existing zero value means no filter). Positive expiry filters use
the actual expiry timestamp, never the collection-time day count.

Migration `0223_manual_certificate_expiry` adds `tenant_uploaded_certificates`
and `tenant_uploaded_certificate_audit`. Each successful create/edit/replacement/
removal records the verified actor email, action, timestamp and before/after
metadata in the same transaction. Certificate removal preserves its audit;
both tables cascade when their tenant is deleted. Migration rollback locks both
tables and refuses if either contains records, including audit left after removal.
Leaving the additive tables while rolling binaries back preserves that history.
