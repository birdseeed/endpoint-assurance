# API reference — patched.im ingestion service

HTTP routes across two listeners. Both listeners bind to `127.0.0.1` and are reverse-proxied by Caddy.

PAT-2004 implements portal `GET/PUT /v1/portal/agent-releases` and internal
`POST /admin/agent-releases/{promote,evidence,observations}` plus
`POST /admin/tenants/{tenantID}/agent-releases/p0`. New stable publication must
use the fail-closed promotion gate. The authoritative request/response,
telemetry and P0 notification contract is [agent release control](../../contracts/agent-release-control.md).
Implementation does not establish deployment or real canary evidence.

## Listeners

| Listener | Bind | Caddy site | Reachable from |
|---|---|---|---|
| Public | `127.0.0.1:8080` | `api.patched.im` | Internet (via Cloudflare proxy) |
| Internal | `127.0.0.1:8081` | `api-internal.patched.im:8443` | Tailscale tailnet only |

## Auth model

**Public routes** (`POST /v1/inventory`, `POST /v1/provenance`, `POST /v1/events`, `GET /v1/agent-config`) require:

1. `Authorization: Bearer <token>` — the opaque bearer token issued by `POST /admin/tenants`. The service SHA-256-hashes the incoming token and looks up the active credential row in `tenant_credentials`. No plaintext token is ever stored.
2. `X-Patched-Signature: <hex>` — HMAC-SHA256 using the tenant's HMAC secret from the matched credential row. The current v3 canonical input binds method, stable endpoint identifier, timestamp, nonce, and the raw body (see `contracts/agent-config-schema.md`). Targetless v2 and legacy body-only forms remain temporary compatibility fallbacks; PAT-1872 telemetry observes which form accepted an inventory request without changing that acceptance order.
3. `X-Patched-Timestamp: <unix-seconds>` — Unix timestamp of the request. Rejected if outside ±300 s of server time (config: `REPLAY_SKEW_SECONDS`).
4. `X-Patched-Nonce: <opaque>` — Per-request nonce. Rejected if seen before within the skew window (stored in `seen_nonces`).

Auth chain order on `POST /v1/inventory` and `POST /v1/provenance`: bearer lookup → rate check → HMAC verify → timestamp → nonce. On `GET /v1/agent-config`: bearer+HMAC (combined authFn) → rate check → timestamp → nonce.

Any auth failure (missing header, unknown token, bad signature, stale timestamp, replay nonce) returns `401 Unauthorized` with the body `"unauthorized"`. The service deliberately returns no further detail to avoid oracle attacks.

**Rate limiting:** 60 requests/minute per tenant (burst 10) on all public routes. On exceed: `429 Too Many Requests` with a `Retry-After: <seconds>` header. Limits are in-memory and reset on service restart. Config: `RATE_LIMIT_RPM`, `RATE_LIMIT_BURST`. Alternative: the `caddy-ratelimit` module can enforce this at the proxy layer for durability across restarts.

**Internal routes** have no application-layer auth at MVP. They are protected by three layers of network restriction:
1. Bound to `127.0.0.1:8081` — only Caddy on the same box can reach them.
2. Caddy's internal site binds only to the Tailscale interface — no public ingress.
3. Tailscale ACL allows only `tag:main` → `tag:api:8443`.

Application-layer admin auth uses the shared `ADMIN_API_TOKEN` for every
`/admin/*` route, compared in constant time over fixed-width SHA-256 digests,
and is available only through the Tailscale-bound internal listener. The token
must be presented as `Authorization: Bearer <token>`: the scheme is required
(matched case-insensitively), followed by exactly one space, and the token is
compared verbatim. The token on its own, with no scheme, is refused with `401`
(PAT-2408). The
former `POST /admin/catalogue/signed` exception and its dedicated
`CATALOGUE_PUBLISHER_TOKEN` were retired with the signed catalogue (PAT-2246),
together with `GET /admin/catalogue/signed`; both paths now return `404` to an
authenticated caller.

**Admin audit attribution (PAT-1135).** Because `/admin/*` authenticates with one shared `ADMIN_API_TOKEN` and has no per-person identity, no request to it can be attributed to an individual — every caller holding the token is indistinguishable from every other. Audit tables therefore record the actor/changed_by/admin_id column as the constant `"admin_shared_token"` (the one identity the server can actually vouch for), never the caller-supplied name from the request body. That caller-supplied string is preserved separately, verbatim and explicitly untrusted, in each table's `claimed_actor` column, alongside a best-effort `source_addr`. See `internal/handlers/audit_attribution.go` and `migrations/0092_audit_attribution.sql`. Per-person identity for this surface is expected to arrive with PAT-700 (`DASHBOARD_OPERATORS`); until then, `claimed_actor` is a claim, not a verified fact.

**Subscription-tier enforcement (PAT-650).** `tenants.subscription_tier` (`report` < `patch` < `full_endpoint`, migration 0056) gates feature endpoints server-side. Requests below the required tier get `403` with body `{"error": "feature requires subscription tier: <tier>"}`:

| Endpoints | Minimum tier | Tenant resolved from |
| -- | -- | -- |
| `GET /v1/allowlist/pending-removals` | `patch` | bearer credential (agent route) |
| `/admin/tenant-app-policy/{tenantID}*` (all methods) | `patch` | `{tenantID}` URL param (target tenant) |
| `/admin/tenants/{tenantID}/allowlist*`, `allowlist-policy` | `patch` | `{tenantID}` URL param (target tenant) |
| `/admin/tenants/{tenantID}/app-control*` | `full_endpoint` | `{tenantID}` URL param (target tenant) |

Admin routes check the **target** tenant's tier, not the caller (admin callers are Tailscale-gated operators): upgrade a tenant via `PUT /admin/tenant-tier/{tenantID}` first and the gated routes unlock immediately. Tier-switch and tenant-management routes are deliberately ungated. Implementation: `internal/handlers/tier.go` (`RequireSubscriptionTier` middleware wired in `cmd/patched-api/main.go`).

---

## Public routes

### `GET` / `POST /v1/portal/feedback`

Customer portal feedback is CF Access JWT authenticated and tenant-scoped by
`portalauth`; every role (viewer, admin, owner) may submit. The feature is absent
(404 for both methods) unless `FEEDBACK_ENABLED=true`. POST is multipart with
`type` (`feature`, `design`, `support`; `bug` and `question` stay accepted for
older portals), title (5–120), description (1–5000), bug-only severity,
support-only `category` (`not_working`, `findings_or_reports`,
`account_billing`), optional PNG/JPEG screenshot (5 MiB, 12 million pixels), and `route`; build and
browser context come from `X-Portal-Build` and `User-Agent`. Route capture stores
only the path, stripping query, fragment, host and URL credentials; route, build
and browser context are capped at 512, 128 and 512 characters respectively.
A refused submission
returns 400 with `{"error":"invalid_feedback","message":"..."}`, where `message`
is customer-grade text the portal shows as is; the customer's own fields are
checked before any database work. A severity on anything but a `bug` is
refused, not ignored (PAT-2216), and so is a `category` on anything but a
`support` request, which must carry one (PAT-2347): the portal drops stale
values before forwarding, so only a caller outside the contract sends them. A successful POST
returns 201 after durable storage, not after Linear sync. Every failed Linear
delivery attempt logs `feedback sync attempt failed` (WARN) and the last one
`feedback sync failed permanently` (ERROR); a row in `sync_state='failed'` is
never retried without operator action. Limits are 10 per
portal user/hour and 50 per tenant/day; 429 includes `Retry-After`. GET returns
only the caller tenant's reference, type, door, support category (support
requests only), title, customer status and timestamps. `door` is `support` for
`support`, `bug` and `question`, and `feedback` for `feature` and `design`;
`GET ?door=feedback|support` returns only that door's items (one list per
portal door, PAT-2347), no parameter returns everything as before, and any
other value is a 400. Linear issues carry the Support or Design label when the
team has one; neither label is required.
Screenshots upload asynchronously to Linear's signed storage through hardened
HTTPS PUT. Upload failures do not create an issue until the fifth upload attempt
fails; that issue states `Screenshot upload failed` and the blob stays retained
for operator attachment. Successful upload stores the asset URL and embeds the
image above the untrusted text; the blob is cleared only after issue persistence.

### `/v1/portal/signup/*` and `/v1/portal/access*`: self-service sign-up (PAT-1883)

A person with a verified Cloudflare Access email creates an organisation and
becomes its owner; an owner invites administrators and viewers and manages
their access. No operator step. Exact shapes, status codes and limits are in
`contracts/portal-api.md`
("Self-service organisation sign-up and access"); this is the operational
summary.

**Flag:** `SELF_SERVICE_SIGNUP_ENABLED`, default `false`. While it is off
every route below answers `404` to a verified caller using the route's
method, and does nothing. That is not quite an unmounted route: the routes
stay mounted and the flag is checked in the handler, so a wrong method is
`405`, and what the route group decides first still comes first (`503`
without portal auth configured, `401` without a valid JWT, `429` over the
per-email limit, `403` for the read-only service identity on the sign-up
routes and on every write, `403` in the tenant group for someone who belongs
to no tenant). Turning it off again is the rollback and deletes nothing. The
`owner` role is recognised whether or not the flag is set.

| Route | Group | Who | Purpose |
|---|---|---|---|
| `GET /v1/portal/signup/state` | pre-membership | any verified person | Their own email: `member`, `can_create_organisation`, and the unexpired invitations addressed to them, each with the organisation's name and `invited_by` (the inviting owner's verified address) |
| `POST /v1/portal/signup/organisation` | pre-membership | a verified person with no `portal_users` row and no claimed email domain | `{"name"}` (2 to 80 characters, at least two of them letters or digits, no control or invisible characters; `400 invalid_name` otherwise). One transaction: tenant (provisioned as `POST /admin/tenants` does, `created_via = 'self_service'`, `contact_email` set to the caller's verified email so alert and report mail has a recipient), the caller's `portal_users` row as `owner`, the audit row. `409 already_member` otherwise. The tenant-level ingest credential is not returned |
| `POST /v1/portal/signup/invitations/{invitationID}/accept` | pre-membership | the invitee only | Creates their `portal_users` row with the invited role and marks the invitation accepted, single use. `404` for anyone else's invitation, `410` once used, revoked or expired, `409 already_member`. The owner who sent it must still be an enabled owner of that tenant: otherwise `410 invitation_revoked`, nothing is created, the stored status stays `pending`, and `GET /signup/state` does not offer it |
| `GET /v1/portal/access` | tenant | owner, admin | The tenant's members (each with `disabled_by`: `null`, `owner` or `operator`) and its newest 500 invitations |
| `POST /v1/portal/access/invitations` | tenant | **owner only** | `{"email", "role"}` with role `admin` or `viewer`. Checks this tenant only, so it never reveals whether an address is known elsewhere |
| `POST /v1/portal/access/invitations/{invitationID}/revoke` | tenant | **owner only** | Withdraws a pending invitation; idempotent |
| `PUT /v1/portal/access/members/{memberEmail}/role` | tenant | **owner only** | `{"role"}`, `admin` or `viewer`. Changing a disabled member's role does not enable them |
| `POST /v1/portal/access/members/{memberEmail}/disable`, `.../enable` | tenant | **owner only** | Sets or clears `portal_users.disabled_at`, recording the disable as the owner's (`disabled_by`). An owner can enable only a member an owner disabled: `409 disabled_by_operator` for one the operator disabled, and an owner's `disable` of an already disabled member changes nothing |

**Groups.** The pre-membership group (`portalauth.SignupMiddleware`) verifies
the JWT and applies the per-email limit exactly as the tenant group does, and
resolves no tenant. It mounts those three handlers and nothing else, and hands
them an applicant (an email, no tenant) which every tenant-scoped handler
refuses, so it gives no path to tenant data. Its requests are logged to
`portal_access_log` with a NULL tenant. The tenant group is the ordinary
`/v1/portal` middleware: the tenant comes from the caller's identity, and an
invitation id or member address from another tenant is `404`, the same as one
that does not exist.

**Identity.** The verified email only. Nothing in a body, query or header
names the caller or a tenant. Bodies are decoded strictly (`decodeStrictJSON`,
as on the other portal writes): any key a route does not define, `tenant_id`,
`email` and `role` included, and any case or Unicode-fold variant of a real
key, is `400 invalid_request` and changes nothing. The routes that take no
input accept an empty body, `{}` or a bare JSON `null` (what the shared
`requireEmptyOrEmptyObject` helper accepts) and nothing else.

**Roles.** Owner-only writes re-read the role inside the write transaction
(`FOR SHARE` on the caller's row) and refuse anyone else with
`403 owner_role_required` before the body is read. An owner cannot change,
disable or enable themselves or another owner, so a tenant is never left
without an active owner; the transaction checks that again before it commits.
The read-only service identity is refused on every one of these routes.

**Limits** (in memory, per process, reset on restart): the per-email portal
limit; organisations created by everyone in any hour
(`SIGNUP_ORG_CREATIONS_PER_HOUR`, default 20), which counts organisations that
were created: a slot is taken only when a tenant is about to be created and is
given back unless one is committed, so a request that creates nothing cannot
spend it; invitation attempts by an authorised owner per tenant
(`PORTAL_INVITATIONS_PER_HOUR`, default 20), including database refusals and
outages. Each answers `429` with
`Retry-After`. A tenant may hold 50 pending invitations
(`409 invitation_limit_reached`). Invitations last
`PORTAL_INVITATION_TTL_HOURS` (default 168); expiry is read from `expires_at`
at request time, with no background job.

There is no per-client-address limit on sign-up. The portal calls the platform
from its own server, so every sign-up arrives from one address and such a
limit would be a second, lower global cap. The platform does not accept a
forwarded client address from the portal.

**Audit.** Every change writes a `portal_access_audit` row in the same
transaction (see `SCHEMA.md`). No email is sent.

**Source:** `internal/handlers/portal_signup.go`,
`internal/handlers/tenant_provision.go`, `internal/portalauth/signup.go`,
`internal/portalauth/role.go`; routes in `cmd/patched-api/main.go`.

---

### `POST /public/linear-webhook`

Linear Issue status callback for portal feedback. This route has no portal or
tenant bearer authentication. It accepts only `Linear-Event: Issue` payloads
whose signed JSON says `type: Issue` and `action: update`. Other authenticated
event kinds return 200 without work. `LINEAR_WEBHOOK_SECRET` must be configured;
when absent the route returns 503 and does not parse or persist the request.

The handler reads at most 256 KiB and verifies `Linear-Signature` as the
hex-encoded HMAC SHA-256 of the exact raw body before JSON parsing, using a
constant-time comparison. The body's millisecond `webhookTimestamp` must be no
more than 60 seconds in the past or future. `Linear-Delivery` is the durable
idempotency key. A repeated delivery is a no-op; an unknown Linear issue returns
200 and is recorded as ignored. Feedback is selected only by its unique
`linear_issue_id`. The issue `updatedAt` timestamp is the ordering authority, so
an older or equal event cannot overwrite a newer observation.

Customer status mapping is exact: `Backlog` with `needs-triage` or
`claude-triaged` is `received`; other `Backlog`, `Todo` and `Blocked` are
`planned`; `RoadMap` is `on_the_roadmap`; `In Progress` and `In Review` are
`in_progress`; `Done` is `shipped`; `Canceled` is `closed_not_planned`; and
`Duplicate` is `closed_merged`. Questions map any planned outcome back to
`received`. An unknown workflow state advances the Linear observation timestamp
but leaves customer status unchanged and emits a bounded safe log.

Every actual transition is append-only audited with tenant, previous and new
status, Linear state and event time. A transition to shipped or either closed
status atomically creates one email outbox row addressed only to that feedback
row's submitter. The plain-text email contains reference, title and customer
status. Duplicate also says it was merged with an existing request; it contains
no Linear URL or internal issue identifier. Definite transient Graph failures
retry up to six attempts. An interrupted in-flight send or a sendMail transport
failure with no Graph response becomes `ambiguous` and is not automatically
retried, because Graph provides no idempotency key and a retry across that
acceptance boundary could silently duplicate mail.

### `GET /health`

Health check. Used by Caddy's `health_uri` and external uptime monitors.

**Auth:** none.

**Response `200 OK`:**
```json
{"status":"ok","version":"0.1.0"}
```

---

### `POST /v1/inventory`

Submit a device inventory snapshot. This is the endpoint the macOS agent posts to.

**Auth:** Bearer token + HMAC-SHA256 signature (see [Auth model](#auth-model)).

**Required headers:**

| Header | Example | Notes |
|---|---|---|
| `Authorization` | `Bearer eyJhbGc...` | Bearer token from tenant creation |
| `X-Patched-Signature` | `a3f9b2e1c4d5...` | Lowercase hex HMAC-SHA256 of raw body |
| `X-Patched-Timestamp` | `1749740400` | Unix seconds; must be within ±300 s of server time |
| `X-Patched-Nonce` | `f7e3a9b2c1d4...` | Opaque per-request nonce; replays rejected within the skew window |
| `Content-Type` | `application/json` | Required; body is validated as JSON |

**Body:** JSON document matching the inventory payload schema. See `docs/PAYLOAD_SCHEMA.md` and `docs/payload.schema.json`.

**Body size limit:** 6 MB. Caddy enforces this at the edge; the handler double-checks it.

**Response `200 OK`:**
```json
{
  "status": "ok",
  "request_id": "abc123",
  "raw_payload_id": 42
}
```

`raw_payload_id` is the `raw_payloads.id` of the inserted row. The extractor processes it asynchronously — a `200` response means the payload was accepted and stored, not that it has been extracted.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"read body"` | Body read failed (client disconnect mid-upload) |
| `400 Bad Request` | `"invalid payload: <detail>"` | Body is not valid JSON, or violates the `payload.schema.json` contract (PAT-227: schema validated synchronously in the handler before any DB write) |
| `401 Unauthorized` | `"unauthorized"` | Missing/wrong bearer token, HMAC signature, stale timestamp, or replay nonce |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit exceeded; check `Retry-After` header |
| `500 Internal Server Error` | `"internal error"` | Database insert failed |

**Signing a request (shell example):**
```bash
BODY=$(cat inventory.json)
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$HMAC_SECRET_HEX_DECODED" -binary | xxd -p -c 256)
curl -X POST https://api.patched.im/v1/inventory \
  -H "Authorization: Bearer $BEARER_TOKEN" \
  -H "X-Patched-Signature: $SIG" \
  -H "Content-Type: application/json" \
  --data-binary @inventory.json
```

The macOS uploader (`patched-upload.sh:79-89`) uses Python's `hmac` module with the base64-decoded HMAC secret — avoid the openssl-with-binary-key quoting trap.

---

### `POST /v1/provenance`

Submit a single provenance record — one structured audit entry per third-party app update performed by the Patched Updater on a client endpoint. Written by the `patched-update.sh` endpoint daemon.

**Auth:** Bearer token + HMAC-SHA256 signature (same as `/v1/inventory`).

**Required headers:**

| Header | Example | Notes |
|---|---|---|
| `Authorization` | `Bearer eyJhbGc...` | Same bearer token as for `/v1/inventory` |
| `X-Patched-Signature` | `a3f9b2e1c4d5...` | Lowercase hex HMAC-SHA256 of raw body |
| `X-Patched-Timestamp` | `1749740400` | Unix seconds; must be within ±300 s of server time |
| `X-Patched-Nonce` | `f7e3a9b2c1d4...` | Opaque per-request nonce; replays rejected within the skew window |
| `Content-Type` | `application/json` | Required; body must be valid JSON |

**Body:** Arbitrary JSON document representing one app update action. The `tenant_id` field is resolved from the bearer token, not the body. The JSONB body is archived verbatim in `provenance_records.body`.

**Body size limit:** 6 MB (shared with `/v1/inventory`).

**Response `200 OK`:**
```json
{
  "status": "ok",
  "request_id": "abc123",
  "provenance_id": 42
}
```

`provenance_id` is the `provenance_records.id` of the inserted row.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"read body"` | Body read failed |
| `400 Bad Request` | `"body not valid JSON"` | Body is not parseable as JSON |
| `401 Unauthorized` | `"unauthorized"` | Missing/wrong bearer token, HMAC signature, stale timestamp, or replay nonce |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit exceeded; check `Retry-After` header |
| `500 Internal Server Error` | `"internal error"` | Database insert failed |

**Source:** `internal/handlers/provenance.go` — (PAT-46).

---

### `POST /v1/events`

Submit one SIEM-style security audit event — an app-verification outcome, an install result, a posture warning, or an allowlist-tamper detection. Written by both endpoint agents' audit-event shipper (macOS `emit_audit_event()`/`drain_events_queue()` in `patched-update.sh`; Windows `AuditEventShipper.cs`), which have shipped this since PAT-499 — this handler is the platform side that was missing until PAT-1022, so every event 404s until it's deployed. See `Patched-LTD/updater`'s `docs/audit-events-contract.md` for the full agent-side contract (both agents already implement it byte-for-byte).

One event per request (unlike the batched `POST /v1/inventory/enforcement-audit`) — each agent ships fire-and-forget per event, queued to a local ring-buffer (cap 1000) on failure.

**Auth:** Bearer token + HMAC-SHA256 signature (same as `/v1/inventory` and `/v1/provenance`). Endpoint ID used in the v3 signing input is `"events"`.

**Required headers:** identical to `/v1/provenance` above.

**Body:**

```json
{
  "event_type":      "verification_failed",
  "tenant_id":       "uuid",
  "device_id":       "mac-hw-uuid-or-windows-machine-name",
  "label":           "googlechrome",
  "version":         "125.0.6422.60",
  "verified_signer": null,
  "reason":          "signer_mismatch",
  "expected":        null,
  "actual":          null,
  "platform":        "macos",
  "timestamp":       "2026-12-20T16:00:00Z"
}
```

`tenant_id` in the body is **ignored** — the tenant is resolved from the bearer token, same rule `/v1/provenance` follows, even though the agent always sends it. `event_type` must be one of `verification_passed`, `verification_failed`, `install_completed`, `install_failed`, `posture_warning`, `allowlist_tamper_detected`, `version_blocked`. `platform` must be `macos` or `windows`. `timestamp` must be RFC3339. `device_id` is required; `label`/`version`/`verified_signer`/`reason`/`expected`/`actual` are all optional and stored as SQL NULL when absent.

**Body size limit:** 6 MB (shared with `/v1/inventory`).

**Response `200 OK`:**
```json
{
  "status": "ok",
  "request_id": "abc123",
  "event_id": "9516cc19-d13a-4dbf-9d41-7f59e720e495"
}
```

`event_id` is the `audit_events.id` of the inserted row.

**Storage:** `audit_events` (`migrations/0098_audit_events.sql`), append-only — `UPDATE`/`DELETE`/`TRUNCATE` are rejected by a DB trigger even for the owning role, same guarantee PAT-1133 already gives `enforcement_audit` and friends. Retained indefinitely (contract requires ≥ 90 days; no deletion job exists, so nothing is purged early).

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"read body"` | Body read failed |
| `400 Bad Request` | `"body not valid JSON"` | Body is not parseable as JSON |
| `400 Bad Request` | `"unknown event_type \"...\""` | `event_type` is not one of the six contract values |
| `400 Bad Request` | `"device_id is required"` | `device_id` missing or blank |
| `400 Bad Request` | `"unknown platform \"...\""` | `platform` is not `macos`/`windows` |
| `400 Bad Request` | `"timestamp must be RFC3339: ..."` | `timestamp` is missing or unparseable |
| `401 Unauthorized` | `"unauthorized"` | Missing/wrong bearer token, HMAC signature, stale timestamp, or replay nonce |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit exceeded; check `Retry-After` header |
| `500 Internal Server Error` | `"internal error"` | Database insert failed |

**Source:** `internal/handlers/events.go` — added 2026-08-10 (PAT-1022).

---

### `GET /v1/agent-config`

Return the Ed25519-signed per-tenant agent configuration. Agents poll this on startup and periodically to pick up tier changes and proxy config updates.

**Auth:** Bearer token + HMAC-SHA256 over the **empty body** (same two-layer auth as `POST /v1/inventory`).

**Required headers:**

| Header | Example | Notes |
|---|---|---|
| `Authorization` | `Bearer eyJhbGc...` | Same bearer token as for `/v1/inventory` |
| `X-Patched-Signature` | `e3b0c44298fc...` | Lowercase hex HMAC-SHA256 of `""` (empty body) |
| `X-Patched-Timestamp` | `1749740400` | Unix seconds; must be within ±300 s of server time |
| `X-Patched-Nonce` | `f7e3a9b2c1d4...` | Opaque per-request nonce; replays rejected within the skew window |
| `If-None-Match` | `"3"` | Optional. Send the ETag from the last 200 response. |

**Response `200 OK`:**
```json
{
  "catalog_scope":    null,
  "config_version":   1,
  "issued_at":        "2026-12-10T12:00:00Z",
  "os_update_policy": null,
  "per_app_patch":    null,
  "proxy": {
    "auth_ref":             null,
    "bypass_when_off_corp": false,
    "host":                 null,
    "mode":                 "system",
    "pac_url":              null,
    "port":                 null,
    "type":                 null
  },
  "scan_cadence": null,
  "tenant_id":    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "tier":         "report_deploy",
  "key_id":       "d16608de1a7b17fb",
  "signature":    "base64-ed25519-signature"
}
```

**ETag:** `"<config_version>"` (quoted integer). Send in `If-None-Match` on the next poll.

**Response `304 Not Modified`:** Returned when `If-None-Match` matches the current version. Auth still runs — there is no unauthenticated fast path.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `401 Unauthorized` | `"unauthorized"` | Missing/wrong bearer token, HMAC signature, stale timestamp, or replay nonce |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit exceeded; check `Retry-After` header |
| `500 Internal Server Error` | `"internal error"` | DB read or signing failed |

**Signature verification:** See `contracts/agent-config-schema.md` for the canonical field order and verification algorithm. The agent MUST verify the Ed25519 signature before applying the config.

**Source:** `internal/handlers/agent_config.go` — (PAT-281).

---

### `GET /v1/catalogue` (retired)

Retired by PAT-2246: the signed global app catalogue (PAT-495) is no longer
served. The route answers `410 Gone` with the plain-text body
`catalogue retired`, for every request, authenticated or not. It performs no
authentication, rate limiting or database read, and emits no `ETag`.

**Source:** `internal/handlers/catalogue_signed.go`.

---

### `GET /v1/posture`

Return the device's current security posture — CIS compliance by section, evidence summary, CVE findings, available app updates from the updater catalog, and a reserved stub for app-policy (P6). This is the primary data feed for the Self Service app (U0–U4).

**Auth:** Per-device bearer token + HMAC-SHA256 over the **empty body**. The bearer token must have been issued via `POST /admin/devices/{deviceID}/credentials` — it maps to a specific device in `tenant_credentials.device_id`. A tenant-level credential returns `401` (indistinguishable from an unknown token). **A device can only read its own posture** — the device is derived from the credential, never from a client-supplied parameter.

**Required headers:**

| Header | Example | Notes |
|---|---|---|
| `Authorization` | `Bearer <device-token>` | Per-device bearer token issued via admin endpoint |
| `X-Patched-Signature` | `e3b0c44298fc...` | Lowercase hex HMAC-SHA256 of `""` (empty body) |
| `X-Patched-Timestamp` | `1749740400` | Unix seconds; must be within ±300 s of server time |
| `X-Patched-Nonce` | `f7e3a9b2c1d4...` | Opaque per-request nonce; replays rejected within the skew window |

**Response `200 OK` (abbreviated):**
```json
{
  "schema_version": 1,
  "generated_at": "2026-12-16T12:00:00Z",
  "device": {
    "id": "uuid",
    "serial": "C02XG0KGJGH7",
    "hw_uuid": "...",
    "hostname": "my-macbook",
    "arch": "arm64",
    "os": "macOS",
    "os_version": "15.4.1",
    "agent_version": "0.10.1",
    "first_seen": "2026-07-10T09:00:00Z",
    "last_seen": "2026-12-16T10:00:00Z"
  },
  "tier": "report_deploy",
  "app_count": 47,
  "compliance": {
    "platform": "macOS",
    "benchmarks": [
      {
        "benchmark": "CIS Apple macOS",
        "benchmark_version": "v3.0.0",
        "implemented": 52,
        "benchmark_total": 171,
        "passed": 49,
        "failed": 3,
        "not_applicable": 0,
        "errors": 0,
        "compliance_pct": 94.2,
        "sections": [
          {
            "section": "1",
            "passed": 5,
            "total": 5,
            "controls": [
              {
                "rule_key": "cis.1.1",
                "title": "Ensure All Apple-provided Software Is Current",
                "severity": "high",
                "status": "pass",
                "observed_value": null,
                "evaluated_at": "2026-12-16T10:00:00Z"
              }
            ]
          }
        ]
      }
    ]
  },
  "evidence": {
    "coverage_window_days": 30,
    "scans_logged": 42,
    "last_signed_report_digest": null,
    "recent_scan_times": ["2026-12-16T10:00:00Z"]
  },
  "findings": [
    {
      "cve_id": "CVE-2024-4671",
      "description": "Use after free in Visuals in Google Chrome prior to 124.0.6367.201",
      "description_source": "nvd",
      "cvss_v3_score": 9.6,
      "severity": "CRITICAL",
      "published_at": "2024-05-09T21:15:00Z",
      "app_name": "Google Chrome",
      "app_version": "124.0.6367.78",
      "match_confidence": "version_confirmed",
      "last_seen_at": "2026-12-16T08:00:00Z"
    }
  ],
  "updates": [
    {
      "app_name": "Google Chrome",
      "identifier": "com.google.Chrome",
      "current_version": "124.0.6367.78",
      "target_version": "126.0.6478.127",
      "source": "catalog",
      "linked_cve_ids": ["CVE-2024-4671"]
    }
  ],
  "app_policy": null
}
```

Full schema: `docs/posture.schema.json`.

`findings[].description_source` is additive response data: the server always
emits it alongside `description` and the schema keeps it required. Existing
updaters deserialize posture JSON with the default System.Text.Json behaviour,
which ignores unknown members, so they remain compatible until they consume the
new provenance field.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `401 Unauthorized` | `"unauthorized"` | Missing/wrong bearer token, HMAC signature, stale timestamp, replay nonce, tenant-level credential used, or device purged |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit exceeded; check `Retry-After` header |
| `500 Internal Server Error` | `"internal error"` | DB read failed |

**Security note (GitHub-Non-Author-Review):** The device is resolved entirely server-side from `tenant_credentials.device_id`. No URL, query string, or body parameter influences which device's data is returned. Tenant-level credentials and staff credentials both return `401` (same error as unknown token). A purged device also returns `401` to avoid leaking the deletion event.

**Source:** `internal/handlers/posture.go` — P1 (PAT-466); P2 CVE findings added (PAT-468); P3 update availability added (PAT-472).

---

### `GET /v1/device/identity`

Tell an agent which device its own credential belongs to (PAT-2424). An agent stores the `device_id` that `POST /v1/enrol` returns and uses it to check that a signed agent-config is addressed to it. Agent builds before Windows `0.15.1` discarded that field, so a device enrolled on one has nothing to compare with, and the signed config must never supply the value it is checked against. This endpoint is the authenticated source: the platform reads `tenant_credentials.device_id` for the presented bearer.

**Auth:** per-device bearer + HMAC-SHA256 over the **empty body**, **strict v3 only** (endpoint id `device_identity`). The targetless v2 and legacy body-only forms are refused. Same timestamp window, nonce replay check and per-tenant rate limit as the other agent endpoints. **No header, query parameter or body field influences which device is returned.**

**Required headers:** `Authorization`, `X-Patched-Signature`, `X-Patched-Timestamp`, `X-Patched-Nonce`, as for `GET /v1/posture`.

**Response `200 OK`:** exactly these two fields, the same two values `POST /v1/enrol` returned to this credential's holder. `Cache-Control: private, no-store`.
```json
{ "tenant_id": "uuid", "device_id": "uuid" }
```

**Errors:**

| Status | Body | Cause |
|---|---|---|
| `401 Unauthorized` | `"unauthorized"` | Missing, unknown, revoked or expired credential; revoked tenant; bad or non-v3 signature; stale timestamp; replayed nonce |
| `409 Conflict` | `{"error":"device_credential_required"}` | The credential is a valid **tenant-level** one (`device_id` NULL: `POST /admin/tenants`, rotation, trial provisioning) and so identifies no device. Returned only after the request has fully authenticated at tenant level; a caller without the matching secret gets the `401` above. Carries no tenant or device id. Counted in `patched_device_credential_required_total{handler="device_identity"}` |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit; check `Retry-After` |
| `500 Internal Server Error` | `"internal error"` | DB read failed |

**Side effects:** none beyond the replay nonce every signed endpoint stores in `seen_nonces`. It creates no device and does not move `last_seen`. One log line per served request (`device identity served`, with tenant, device and request id).

**Source:** `internal/handlers/device_identity.go`; `integration/device_identity_test.go`.

---

### `POST /v1/agent-logs`

Upload a gzipped JSON-lines log bundle in response to a `log_request` directive delivered in the agent's signed config (PAT-286). One bundle per `(tenant, device, request_id)` is stored; re-uploads with the same `request_id` are silently accepted (idempotent).

**Auth:** Per-device bearer + HMAC-SHA256 over the request body — same as `GET /v1/posture`. The tenant and device are derived from the credential; no client-supplied identifiers are trusted.

**Rate limiting:** Shared per-tenant limiter (same pool as `GET /v1/posture`).

**Replay protection:** `X-Patched-Timestamp` + `X-Patched-Nonce` required (same as all other authenticated public routes).

**Request headers:**

| Header | Required | Meaning |
|---|---|---|
| `Authorization` | yes | `Bearer <device-bearer-token>` |
| `X-Patched-Signature` | yes | `hex(HMAC-SHA256(body, hmac-secret))` |
| `X-Patched-Timestamp` | yes | RFC3339 UTC timestamp within ±5 min of server time |
| `X-Patched-Nonce` | yes | UUID; consumed once |
| `X-Patched-Log-Request-ID` | yes | UUID matching the `request_id` field from the `log_request` directive |

**Request body:** gzipped JSON-lines bundle. Maximum size: 10 MiB (server hard cap). The `log_request.max_bytes` directive is an additional (typically lower) constraint enforced by the agent. A per-tenant ceiling of 512 MiB total stored bytes is enforced before insert.

**Response — 200 OK:**

```jsonc
{
  "status":     "ok",
  "log_id":     42,                                    // DB row id
  "request_id": "f1e2d3c4-b5a6-7f8e-9d0c-b1a2c3d4e5f6",
  "stored":     true    // false when request_id already existed (idempotent)
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | varies | Missing/invalid `X-Patched-Log-Request-ID`, empty body |
| `401 Unauthorized` | `"unauthorized"` | Auth failure (same causes as `GET /v1/posture`) |
| `413 Request Entity Too Large` | varies | Body exceeds 10 MiB hard cap, or tenant ceiling exceeded |
| `429 Too Many Requests` | `"rate limit exceeded"` | Per-tenant rate limit; check `Retry-After` |
| `500 Internal Server Error` | `"internal error"` | DB write failed |

**Source:** `internal/handlers/agent_logs.go` — added PAT-286.

---

### `POST /v1/backup-health`

Accepts one backup-job heartbeat JSON document and writes it into `PATCHED_BACKUP_HEALTH_DIR`, the same directory `GET /admin/health`'s `readBackupJobs` scans (see that section below). Added (PAT-954) to close a gap left by PAT-387: `example-portal-host` (`tag:portal`) has zero outbound tailnet grants by design (PAT-410), so it cannot ship its heartbeat to api-01 over the scp-over-Tailscale channel `prod-backup.sh` uses. This endpoint gives it an HTTPS path over the public listener instead, reachable over the same outbound 443 portal-01 already uses to call `PLATFORM_BASE_URL` — no tailnet or ufw change needed on portal-01's side. See `api-vps-artefacts/BACKUP_DR.md` → "Dashboard backup health monitoring".

**Auth:** `Authorization: Bearer <token>` where `<token>` is `BACKUP_HEARTBEAT_TOKEN` — a dedicated credential, deliberately **not** `ADMIN_API_TOKEN` and **not** a tenant bearer token. Compared in constant time. If `BACKUP_HEARTBEAT_TOKEN` is unset the endpoint fails **closed** (`503`), matching the `ADMIN_API_TOKEN` posture.

**Rate limiting:** one dedicated in-memory token bucket shared by every caller of this endpoint (there is exactly one legitimate caller). Config: `BACKUP_HEARTBEAT_RATE_LIMIT_RPM` (default 6), `BACKUP_HEARTBEAT_RATE_LIMIT_BURST` (default 3). `429 Too Many Requests` with `Retry-After` on exceed.

**Job allowlist:** `PATCHED_BACKUP_HEALTH_DIR` is shared with other hosts' heartbeat files (e.g. prod-01's `prod-r2.json`, shipped over its own scp channel — see `GET /admin/health` below). `job` must additionally be one of `BACKUP_HEARTBEAT_ALLOWED_JOBS` (comma-separated, default `portal-r2`) — otherwise this credential could overwrite another host's file, including painting a genuinely failing job green. A well-formed `job` outside the allowlist gets `403 Forbidden`, distinct from the `400` a malformed `job` gets.

**Request body:** capped at 4 KiB via `http.MaxBytesReader` — oversized bodies are rejected mid-read (`413`), never buffered in full. Decoded strictly (`json.Decoder.DisallowUnknownFields`, trailing content after the JSON value rejected) into the exact same shape `readBackupJobs` consumes:

```json
{
  "job": "portal-r2",
  "label": "Portal+scan → R2 (portal-01)",
  "status": "ok",
  "last_success_at": "2026-12-14T03:00:12Z",
  "detail": "snapshot 20261214_030000"
}
```

| Field | Required | Constraints |
|---|---|---|
| `job` | yes | `^[a-z0-9][a-z0-9_-]{0,63}$` **and** a member of `BACKUP_HEARTBEAT_ALLOWED_JOBS` — also used verbatim as the filename (`<job>.json`); the pattern is what makes the write safe against path traversal, absolute paths, and non-`.json` names, the allowlist is what stops it overwriting another host's job |
| `status` | yes | ≤32 bytes, no control characters, none of `< > " ' &` |
| `label` | no | ≤200 bytes, no control characters, none of `< > " ' &` |
| `detail` | no | ≤500 bytes, no control characters, none of `< > " ' &` |
| `last_success_at` | no | RFC3339 timestamp or `null`; rejected if more than 5 minutes in the future or more than 1 year in the past |

Every string field is treated as untrusted input — length-capped, control-character-checked, and rejected outright if it contains `< > " ' &` — because it renders on the staff console (dashboard repo's `templates/console.html`) via raw string concatenation into `.innerHTML` with **no escaping** (`_opsRow()`, `b.detail`). This is the PAT-854 stored-XSS precedent: without the metacharacter check, a `detail` like `<img src=x onerror=...>` would execute in an authenticated staff session. The validated document is re-marshaled (not the raw request body) and written atomically (temp file in the same directory using a non-`.json`-suffixed name so a crash mid-write can never leave a stray file `readBackupJobs` would pick up, then `rename`) into `PATCHED_BACKUP_HEALTH_DIR/<job>.json`, so a reader can never observe a partial write, and a second POST for the same `job` cleanly overwrites the first. `last_success_at`'s future-timestamp bound stops a single heartbeat from reading as perpetually fresh on the dashboard's `(now - last_success_at)` staleness calculation if the job never reports again.

**Response — 200 OK:**
```json
{"status":"ok"}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | varies | Invalid/missing JSON, unknown field, `job` fails the safe-filename pattern, a string field exceeds its length cap, contains a control character or an HTML metacharacter, or `last_success_at` is out of bounds |
| `401 Unauthorized` | `"unauthorized"` | Missing/incorrect bearer token |
| `403 Forbidden` | `"job is not permitted for this credential"` | `job` is well-formed but not in `BACKUP_HEARTBEAT_ALLOWED_JOBS` |
| `413 Request Entity Too Large` | `"request body too large"` | Body exceeds the 4 KiB cap |
| `429 Too Many Requests` | `"rate limit exceeded"` | Rate limit exceeded; check `Retry-After` |
| `503 Service Unavailable` | `"backup heartbeat ingest not configured"` | `BACKUP_HEARTBEAT_TOKEN` is unset (fail closed) |

**Example:**
```bash
curl -sS https://api.patched.im/v1/backup-health \
  -H "Authorization: Bearer $BACKUP_HEARTBEAT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"job":"portal-r2","label":"Portal+scan → R2 (portal-01)","status":"ok","last_success_at":"2026-12-14T03:00:12Z","detail":"snapshot 20261214_030000"}'
```

**Note:** `portal-backup.sh` on `example-portal-host` writes `/srv/backup/health/portal-r2.json` locally first, unconditionally, then POSTs that same file here (see `api-vps-artefacts/portal-01-backup/portal-backup.sh`). If `BACKUP_HEARTBEAT_TOKEN` isn't yet provisioned in that box's `backup.env`, it skips the POST with one logged line and the backup itself is unaffected — see `api-vps-artefacts/BACKUP_DR.md` for what's still pending (token provisioning + deploying both boxes).

**Source:** `internal/handlers/backup_health_ingest.go` — added 2026-07-26 (PAT-954).

---

### `POST /v1/webhooks/jamf/{webhookID}`

PAT-2145. Jamf Pro webhook ingest: the customer's Jamf Pro pushes `ComputerAdded`, `ComputerInventoryCompleted`, `DeviceAddedToDEP` and (opt-in) `ComputerCheckIn` here, so the portal can show which Macs Jamf manages that Patched has never seen and which Macs Patched sees that no MDM manages. Patched never holds a Jamf API credential (PAT-1666). Deliberately **outside** the `/v1/portal` group: a portal identity grants nothing here.

**`{webhookID}`**: an opaque 32-character random identifier (24 random bytes, base64url), never the tenant UUID. Stable across token rotation. Minted by `POST /v1/portal/mdm/jamf/token`.

**Auth:** the tenant's webhook token, as `Authorization: Bearer <token>` (Jamf Pro "Header Authentication", JSON `{"Authorization":"Bearer <token>"}`) or as the password of HTTP Basic auth (any username). Only SHA-256 of the token is stored (`jamf_webhook_connectors.token_hash`); compared with `subtle.ConstantTimeCompare`. Unknown ID, malformed ID, revoked token, missing token and wrong token all compare against a fixed dummy hash and all answer the same `401 {"error":"unauthorized"}`, so the response never says whether a tenant or connector exists. Nothing is read from the body before authentication. Jamf Pro webhook authentication options, checked 2026-09-26 against the Jamf Pro documentation (Settings > Global Management > Webhooks): None, Basic Authentication (username and password) and Header Authentication (key/value pairs in JSON, `Content-Type`, `User-Agent`, `Accept-Encoding`, `Content-Length` and `Host` forbidden). Jamf Pro does not sign webhook bodies.

**Optional header `X-Patched-Jamf-Instance: https://<instance>.jamfcloud.com`**: Jamf Pro payloads name no server, so the setup page asks the admin to add this header to the Header Authentication JSON. Normalised to `https://host[:port]`; the first claim is pinned (`jamf_instance_url`) and a later event claiming another instance is flagged on the connector. Not `https` or malformed → `400 invalid_instance_url`.

**Rate limiting:** the tenant's bucket (`JAMF_WEBHOOK_RATE_LIMIT_RPM` 300 / `_BURST` 100, keyed by tenant) is charged only after authentication. A malformed ID or missing token is refused `401` before any database work and charges nothing shared. A failure that cost a database read (unknown ID, or a real ID with a wrong token) is charged to the global failure bucket (`JAMF_WEBHOOK_FAILED_AUTH_GLOBAL_RPM` 600 / `_BURST` 200) and, while that allows, to a per-client-IP bucket (`CF-Connecting-IP`, IPv6 keyed on its /64) and to either a shared "unknown" bucket (global sizing) or a per-ID bucket (`JAMF_WEBHOOK_FAILED_AUTH_RPM` 30 / `_BURST` 20). A connector cache holds every active connector's webhook ID and token hash, seeded before the listener serves and rebuilt every minute: a request whose token matches the cached hash always reaches the database, so no bucket blocks a correctly authenticating tenant, including straight after a restart. Any other request is refused `429` before the database read while the global, IP, unknown or per-ID bucket is exhausted, except that a cached ID still lets 6 non-matching tokens a minute (burst 2) through, which covers a token rotated by another process since the last refresh; a create, rotate or revoke in this process updates the cache immediately. A failed authentication answers `429` while the global bucket is exhausted and `401` otherwise, the same for every ID. `CF-Connecting-IP` is trusted for rate limiting only (the origin accepts Cloudflare ranges alone). Failure log lines are sampled, with `suppressed_since_last`. A revoked tenant (`tenants.revoked_at`) authenticates nothing.

**Body:** `Content-Type: application/json` (Jamf "JSON"; XML is `415`), at most 64 KiB (`413`, via `http.MaxBytesReader`). Parsed by `internal/jamfcoverage.Parse` against exact keys (never decoded into a struct: the PAT-2021 case-folding trap): unknown top-level or `webhook` keys, a wrong type on a kept field, or no event type are `400 invalid_payload`; an unknown event type is `422 unsupported_event`; no real serial, UDID or Jamf ID is `400 missing_identifier`; `ComputerCheckIn` while the tenant has not opted in is `422 event_not_subscribed`. Unknown keys inside `event` are dropped, not refused (Jamf adds event fields between releases, and they are never kept). Authenticated refusals count on the connector (`events_rejected`, `last_rejected_reason`).

**Kept (identifiers only):** serial number (normalised as `internal/devicelist` does; placeholders count as absent), UDID (upper-case UUID), Jamf ID (`jssID`), device name, model, OS version, event type and event time. **Dropped at the edge, never stored or logged:** `emailAddress`, `username` (both the computer's and the check-in's), `realName`, `phone`, `position`, `building`, `department`, `room`, `ipAddress`, `reportedIpAddress`, `macAddress`, `alternateMacAddress`, `userDirectoryID`, `managementId`, `osBuild`, the check-in `trigger`, and the DEP `assetTag`, `description`, `deviceAssignedDate` and `deviceEnrollmentProgramInstanceId`. The allowlist drops any field Jamf adds later. The raw body is never stored and no log line carries a payload value.

**Writes:** inside the write transaction the token hash is re-read `FOR SHARE` and the token checked again, so an event that authenticated just before a rotate or revoke committed writes nothing (`401`). Then one `jamf_devices` row per Mac is upserted under a per-tenant advisory lock (matched by serial, then UDID, then Jamf ID; identifiers are filled, never overwritten). When Jamf moves a UDID or Jamf ID to a Mac with a different serial (a logic board swap), the identifier is cleared from the old row (logged by row id only) and the new row takes it. At most 50,000 rows per tenant: a new Mac beyond that is `422 device_cap_reached`, recorded on the connector; known Macs still update. A `ComputerCheckIn` for a Mac Jamf reported less than an hour ago writes nothing (`202 {"status":"collapsed"}`), so check-ins give at most one update per Mac per hour. The connector's `last_event_at` is touched at most once a minute. Success is `202 {"status":"accepted"}`.

**Source:** `internal/handlers/jamf_webhook.go`, `internal/jamfcoverage/event.go` (PAT-2145).

---

### `POST /v1/trial/provision`

PAT-668, rate limited by PAT-2529. Self-serve trial provisioning: creates a trial tenant (14 days, 3 device cap) with its first credential and the T2 rule baseline, and mints a 24 hour one-use enrolment token. No bearer or HMAC: it is the pre-enrolment step, like `POST /v1/enrol`.

**Request body** (JSON, capped at 8 KiB): `email` (required, must contain `@`, lower-cased), `name` (required) and `company` (optional).

**Responses:**

| Status | Body | Meaning |
|---|---|---|
| `201 Created` | `{"tenant_id","enrollment_url","expires_at"}` | A new trial tenant was created. |
| `409 Conflict` | `{"tenant_id","enrollment_url","expires_at"}` | An active trial already exists for the email; a fresh enrolment token was minted for it. |
| `409 Conflict` | `{"error","mode","set_at"}` | The existing trial tenant has an active decommission directive; no token is minted. |
| `400 Bad Request` | plain text | Unreadable body, invalid JSON, or a missing or invalid `email` or `name`. |
| `429 Too Many Requests` | `{"error":"rate_limited","message":"rate limit exceeded"}` | Over a rate limit. Carries `Retry-After: <seconds>`. |
| `503 Service Unavailable` | plain text | The limiter is not wired (a build fault; the route never runs unlimited). |

**Rate limiting (PAT-2529):** two in-memory token buckets, checked before the body is read and before any database work, so every request counts whether or not it is valid. Per client address: `TRIAL_PROVISION_PER_IP_PER_HOUR`, default 5, keyed on `CF-Connecting-IP` (IPv6 on its /64; a request with no usable header shares one bucket with all others like it). Global, for the whole route: `TRIAL_PROVISION_GLOBAL_PER_HOUR`, default 30. Each bucket holds its full count at once and earns one token back every hour/count, so a client that spends 5 can send one more 12 minutes later. A request refused by its own client bucket does not spend the global one, and once the global bucket is empty no per-client entry is created. `CF-Connecting-IP` is trusted for rate limiting only (Cloudflare sets it and the origin accepts Cloudflare ranges alone); `X-Forwarded-For`, `X-Real-IP` and `True-Client-IP` are not read. Limits reset when the service restarts. This is a volume limit and does not verify the email address.

**Source:** `internal/handlers/trial.go`, `internal/handlers/trial_ratelimit.go`.

---

### `/v1/portal/*` — customer portal read API (PAT-693)

Authenticated, customer-scoped endpoints consumed by the `app.patched.im`
portal. Almost all are read-only; the writes are report generation and
schedules, enrolment token minting, (PAT-2007) software approval state and
(PAT-2135) device retirement and the customer device list, the last two
requiring the portal `admin` role. Wherever this section says "admin role",
an `owner` (PAT-1883) is included: an owner can do everything an admin can.
The pre-membership sign-up routes and the owner-only access routes are
described in their own section above. Full contract (exact JSON shapes) lives in
`contracts/portal-api.md` — the portal app
builds against that document; this section is the operational summary.

**Auth:** `Cf-Access-Jwt-Assertion` header (Cloudflare Access RS256 JWT).
The service validates signature (cached JWKS from the team's
`/cdn-cgi/access/certs`), `iss`, `aud`, `exp`, `nbf`, then maps the verified
`email` claim to a tenant: first an explicit `portal_users` row (migration
0059, the manual-override path), falling back to the tenant that has
registered the email's domain via `tenant_email_domains` (migration 0075,
PAT-127 — auto-binds SSO logins without a per-user row). See
`contracts/portal-api.md` for the full resolution order.
**No client-supplied tenant identifier exists anywhere on this surface.**
When `PORTAL_ACCESS_TEAM_DOMAIN` / `PORTAL_ACCESS_AUD` are unset the whole
surface answers `503` — fail closed.

| Route | Purpose |
|---|---|
| `GET /v1/portal/overview` | Tenant posture summary: device counts, CIS score + 30-day trend, open findings by severity, patch status, and (PAT-2009) `unapproved_present` / `unapproved_present_devices` (null when not assessable) with a five-item `unapproved_present_items` list, and (PAT-2097) `unapproved_alerts_open` / `unapproved_alerts_acknowledged` (tracked alerts, a different measure; see the contract), and (PAT-2093) `new_software`: products first seen in the last 14 days or since the last review, whichever is shorter, each with an `urgency` (`critical`, `high`, `not_assessed`, `medium`, `low`; Windows reaches `low` through an approved publisher key, PAT-2121), the `reasons`, `trust` and `cve` evidence behind it and the approval write identity, plus `counts` per level; top 50 by urgency then newest, `null` when it could not be computed. Rules in the contract |
| `GET /v1/portal/devices` | Device roster (paginated) with per-device CIS score, open findings, `encryption_ok`, `patch_pending` (explicit `device_os_update` verdict first; legacy `devices.pending_updates` only when no OS row exists; unknown, unrecognised or stale explicit verdicts remain unknown, PAT-2338; see `contracts/portal-api.md`), additive `evidence` provenance/section authority (`observed_at`, `received_at`, exact named section statuses, authority, freshness; see `contracts/portal-api.md`), and (PAT-2135) `retirement`: `null`, or `{retired_at, retired_by, reason, reported_after_retirement}` when the customer has retired the device. A retired device stays on the roster. (PAT-2324) `device_class` (`server`, `workstation` or `unknown`; a macOS device with no stored class reads `workstation` by OS family, a Windows device with none stays `unknown`; a stored `domain_controller` reads `server`) and `os_caption` (string or `null`); see `contracts/portal-api.md` |
| `GET /v1/portal/devices/{deviceID}` | One device: compliance signals + apps with CVE findings, plus additive per-product `cve_assessment` (PAT-2024), and (PAT-2141) additive `identity` (serial, hardware model, computer name, architecture, OS name/version/build, agent version, first/last seen — the same `devices` columns `GET /admin/devices/{deviceID}` reads, minus `hw_uuid`) and `hardware` (CPU, memory, physical disks with SMART status, storage volumes, battery health — the same `device_hardware`/`device_disk`/`device_storage_volume` data the admin endpoint and the portal PDF's Hardware health section read) blocks, each with its own `status` (`complete`/`partial`/`unavailable`/`not_collected`) and evidence timestamps/freshness; never zeros or empty arrays standing in for an uncollected section. (PAT-2135) `device.retirement`, the same object as the roster's. (PAT-2294) `device.findings_open`, `device.encryption_ok` and `device.patch_pending`, the roster's three figures for this device, computed by the same code. (PAT-2496) `encryption_ok` is the one encryption state (`report.FetchEncryptionStates`) the insurance evidence pack and the Encryption & Disk Posture report also read, so the three surfaces agree, and each `compliance_signals[]` entry carries an additive boolean `undetermined`, `true` exactly when its `status` is `fail` only because the value could not be read (no observed value; the shared `isUndeterminedEval` predicate), so a client can show it as unknown rather than failed. (PAT-2324) `device.device_class` and `device.os_caption`, the roster's values for this device, from the same derivation. (PAT-2262) additive `firmware`: BIOS vendor, version, SMBIOS version and release date plus system and baseboard identity from `device_firmware_current`, observation only; `status` is `not_reported` (never sent the block: older agent or macOS), `unavailable` (tried, read nothing), `partial` or `complete`, and each section keeps its last-read values with its own `status`/`reported_at` (see `contracts/portal-api.md`). (PAT-2263) additive `kernel_drivers`: the blocklist enforcement state, both driver lists' provenance and staleness, and the device's listed and Unknown drivers matched by hash (see `contracts/portal-api.md`). `404` for other-tenant devices (never `403` — no existence oracle) |
| `PUT /v1/portal/devices/{deviceID}/retirement` | PAT-2135. **Admin role only.** `{"retired": bool, "reason": "optional, at most 500 characters"}`. Records the customer's Retire device decision (or its reversal) as one append-only `device_retirement_decisions` row; the same state again is `200` with `changed: false` and no row. Per-device advisory lock serialises writers. Another tenant's or an unknown device is `404`. Never reversed automatically: a retired device that reports again stays retired and reads `reported_after_retirement: true`. Retired devices are counted apart (`devices_retired`) and left out of stale and missing counts: overview `devices_retired` and `oldest_successful_ingest`, the software governance `coverage` block, the portal report PDF's "Devices not reporting" and roster, the software governance PDF, and the stale endpoints report (own section) |
| `GET /v1/portal/devices/{deviceID}/retirement/history` | PAT-2135. One device's retire/unretire decisions, newest first (`limit` 1 to 500, default 100; `offset`), with the current `retirement`. Every portal role |
| `PUT /v1/portal/device-list` | PAT-2135. **Admin role only.** The customer's own device list (the portal parses the CSV and sends `{"filename", "entries": [{"hostname", "serial"}]}`), replacing the current one; earlier uploads kept in `device_list_uploads` / `device_list_entries`. 1 to 10,000 entries, 2 MiB body, hostname required unless serial given, each field at most 255 characters with no control characters, duplicates collapse. `400` with `error` (`invalid_entry`, `empty_list`, `too_many_entries`, `invalid_filename`, `invalid_request`) and, for a bad row, `items[0].index`. Clearing is `DELETE`, never an empty upload |
| `DELETE /v1/portal/device-list` | PAT-2135. **Admin role only.** Clears the list, recorded as a `cleared` upload row; a no-op (`changed: false`) when there is no current list |
| `DELETE /v1/portal/device-list/entries/{entryID}` | PAT-2271. **Admin role only.** Removes exactly one entry from the tenant's current list by its `entry_id` (from a `GET` response's `matched` or `on_list_never_seen` row); same lock, CSRF/auth pattern and audit shape as the bulk `DELETE` above, via the new append-only `device_list_entry_deletions`. `200 {"deleted": true, "entry_id"}`. `404 not_found` for another tenant's entry, a superseded upload's entry, an unknown id, or no current list |
| `GET /v1/portal/device-list` | PAT-2135, extended by PAT-2271. The current list (`null` before any upload or after a clear) reconciled against the tenant's devices: `matched_count`, `matched` (one row per matched entry plus the device it matched, including `retired`; always exactly `matched_count` long, never capped), `on_list_never_seen` and `seen_not_on_list` (retired devices excluded from the latter; an entry matching a retired device counts as matched). `on_list_never_seen` and `seen_not_on_list` are each capped at 500 with a `_total` and `truncated`; `matched` never is. `matched` and `on_list_never_seen` rows each carry `entry_id`, the stable `device_list_entries.id` behind them, for the per-entry `DELETE` above. Serial match (trimmed, upper case; placeholder serials such as `To be filled by O.E.M.`, all zeros or under 4 characters count as none) when both sides have one, otherwise hostname (lower case, trimmed, trailing dots and `.local` removed), then a first-DNS-label fallback between an FQDN and a short name when the label is unique among unmatched entries and devices. Every portal role |
| `GET /v1/portal/findings` | Open CVE findings aggregated per (CVE, app, version); empty when CVE matcher data absent |
| `GET /v1/portal/driver-findings` | (PAT-2263) Kernel drivers whose reported hash is on Microsoft's recommended driver block rules or loldrivers.io, one row per (device, driver), with list provenance and the device's blocklist enforcement; paginated `?limit`/`?offset`; hash matching only, so an empty list is not a clean bill (see `contracts/portal-api.md`) |
| `GET /v1/portal/software` | Uncapped, paginated (`limit`/`offset`) and searchable current `device_apps` inventory, grouped by identifier/platform. Returns exact searched total plus estate-wide metering/freshness coverage. A removal candidate requires every current installation to have fresh authoritative `metering_status=ok` evidence and no use within 90 days; unmetered, mixed, partial, stale, and unknown coverage never becomes unused or a removal candidate. Canonical identity is nullable and emitted only for a direct reviewed alias match across the entire group. Each product row additionally carries an estate-wide `cve_assessment` object (PAT-2028), rolled up across every installation of the product in the tenant; see "CVE assessment state" below. Optional `device_id` (PAT-2156, UUID): validated against the verified tenant (`400` malformed, `404` unknown or another tenant's device — the same `404` either way), narrows rows to that device's own current installations, scopes `coverage` to the device, scopes `cve_assessment` to that device's installed versions instead of the estate-wide rollup, and adds `first_seen_on_device`. `search`/`limit`/`offset`/sort are unchanged; the unfiltered response is byte-identical to before PAT-2156. Full response contract: `contracts/portal-api.md`. |
| `GET /v1/portal/software/new` | PAT-2009/PAT-2031. Products first seen on the tenant since `since` (RFC 3339 or `YYYY-MM-DD`) or, by default, since the tenant's last review (latest `software_approval_decisions` row). First seen is the earliest `software_installations.first_seen_at` across every device, removed installations included. Applications and current named tooling identities carry first-seen date, current device count, first device and approval state; tooling has `type: "observation"`, `platform: ""`, `identity_basis: "observation"` and exact `observation_kind`/`observation_source`. `?format=csv`. Urgency (PAT-2093) remains application-only. |
| `GET /v1/portal/software/drift` | PAT-2009/PAT-2031. Unapproved and Unreviewed installed products (worst state per product), counts by state, 26-week trend (live current week plus recorded weekly captures, unrecorded weeks `null`), top 10 devices by Unapproved product count, and the Unapproved-present list (product, devices, who marked it, since when). Resolution uses the shared `softwaregov` resolver for applications/extensions, Homebrew and named tooling identities, so a policy state is consistent across portal reads. `?format=csv`; 422 `estate_too_large` over 250,000 inventory rows. |
| `GET /v1/portal/software/approved` | PAT-2009. Every Approved application, extension and (PAT-2058) Homebrew formula/cask policy with `approved_by`, `approved_via` (`portal` from the PAT-2007 decision audit, else `operator`) and `approved_at` with its basis. `?format=csv`. PAT-2393: also lists declared software with nothing installed, and every row carries `source`, `declaration_id`, `identity_state`, `observation_state`, `effective_approval_state` and installation counts (see `contracts/portal-api.md`). |
| `GET /v1/portal/reports/software/unsupported`, `GET /v1/portal/reports/software/unsupported/devices` | PAT-2147 (SAM, PAT-2146). Every application and OS on every device with its support state: `supported`, `ending_within_90_days`, `unsupported`, or `unknown` with a reason (no published mapping, lifecycle data not fetched or older than 7 days, version not matched to a cycle, Windows edition not reported). The first returns summary counts per state, the `basis` (evidence times, devices assessed/stale, what is not counted), the `cyber_essentials` evidence block, and paged product rows; `/devices` is the paged per-installation drill-down (`device_id`, `product_key` filters). Both take `state`, `kind`, `platform`, `limit`, `offset` and `?format=csv` (every installation row, formula injection neutralised). Every portal role reads. Lifecycle data: endoflife.date via staff-published mappings only. 422 `estate_too_large` over 250,000 installations. Contract: `contracts/portal-api.md`. |
| `GET /v1/portal/reports/software/remote-access`, `GET /v1/portal/reports/software/remote-access/devices` | PAT-2148 (SAM, PAT-2146). Every remote access tool and RMM agent (`internal/categorytag` categories `remote_access`/`rmm_agent`, seeded by migration `0197`), by device and (PAT-2075) by user, with the tenant's existing software-approval state (`internal/softwaregov`) — never a parallel allow list. RMM agents are counted apart so an MSP's own tooling is never an unsanctioned-remote-access finding; unsanctioned rows sort first. The first returns summary counts per category and state, the `basis`, and paged product rows; `/devices` is the paged per-device (and per-user) drill-down (`device_id`, `product_key` filters). Both take `category`, `kind`, `state`, `platform`, `limit`, `offset` and `?format=csv`. Every portal role reads. Detection is catalogue-limited (the `basis.statement` says so). 422 `estate_too_large` over 250,000 installations. Contract: `contracts/portal-api.md`. |
| `GET /v1/portal/reports/software/version-sprawl` | PAT-2150 (SAM, PAT-2146). Version sprawl per installed application product (operating systems excluded): distinct live versions, oldest, newest, the vendor's latest release where Patched holds a trusted source for it (`endoflife.date` staff-published mapping, then the curated `app_catalog_entries` catalogue, then a reserved but unpopulated `vendor_feed` slot — never the newest version merely seen on the estate), devices more than one major version behind the estate's own newest live major (a version that does not parse to a major is `devices_not_comparable`, never behind or current), and the CVE count on the oldest live version (only matched findings Patched already holds; `not_assessed`, never `0`, when no CPE mapping covers the product). `basis` states devices assessed/stale/retired-excluded and what is not counted. PAT-2509: a catalogue entry is matched on an exact product name (a name that only contains the other does not match), with its signer also required where the entry has one and never on signer alone. It counts only if verified within 7 days (`definition.catalogue_max_age_days`), and `endoflife.date` only if fetched within 7 days. A figure lower than a version running on the estate is withheld, so `latest_released` and `latest_released_source` read `null`. `latest_released_source` gains `label` (display wording) and `checked_at` (when the source was last refreshed) beside its unchanged machine `name`. The CSV gains `latest_released_checked_at` as its last column, and its `latest_released_source` column carries the label, never `curated_catalogue`. Takes `platform`, `limit`, `offset` and `?format=csv` (one row per product, unpaged). Every portal role reads. 422 `estate_too_large` over 250,000 installations. Contract: `contracts/portal-api.md`. |
| `GET /v1/portal/reports/software/publishers`, `GET /v1/portal/reports/software/publishers/devices` | PAT-2152 (SAM, PAT-2146). Every currently installed application grouped by the publisher its code signing evidence proves — the macOS Team ID or the Windows Authenticode signer pinned to its signing root (PAT-2121's `AuthenticodePublisherKey`) — never the display name or registry Publisher string. Reuses PAT-2093's own trust classifier (`internal/softwaregov.classifyMacTrust`/`classifyWindowsTrust`) rather than re-deriving signing logic. Four groups, most attention-worthy first: `unsigned_or_adhoc`, `invalid`, `unverified` (missing evidence, or a signature that cannot be independently pinned — the raw registry Publisher is never shown even though the overview reads it labelled unverified), `verified` (one pinned publisher; `trusted` is this tenant's own PAT-2121 approval of that exact identity). The first returns summary counts, the `basis`, and paged publisher rows (`publisher_key`, `group`, `platform`, `identity_basis`, `publisher`, `trusted`, `signing`, `signer_class`, `notarisation`, `product_count`, `device_count`, `installation_count`); `/devices` is the paged per-installation drill-down (`device_id`, `product_key` filters). Both take `group`, `platform`, `publisher_key`, `limit`, `offset` and `?format=csv`. Every portal role reads. 422 `estate_too_large` over 250,000 installations. Contract: `contracts/portal-api.md`. |
| `GET /v1/portal/reports/software/duplicate-tools` | PAT-2151 (SAM, PAT-2146). Consolidation candidates: within eight curated categories (PDF editors, screen recorders, VPN clients, password managers, file sync, video conferencing, remote access — reused from PAT-2148, not duplicated — and note taking; `internal/duplicatetools`, seeded by migration `0198`), the distinct products present, grouped by each rule's `product_key` so one product's macOS/Windows/Homebrew-cask identities count once, with install counts, devices, users and the tenant's existing approval state (least favourable across the product's platforms). A category is flagged at three or more distinct products; the ticket's other rule (two or more *paid* products) is not implemented — it needs PAT-2143's price catalogue, and `basis.paid_products_rule_pending` says so. A category with zero matched products is omitted, never a zero-count row. Takes `category`, `product_key`, `limit`, `offset` and `?format=csv` (per-device/per-user rows, unpaged). Every portal role reads. 422 `estate_too_large` over 250,000 installations. Contract: `contracts/portal-api.md`. |
| `GET /v1/portal/software-alerts`, `GET /v1/portal/software-alerts/{id}`, `POST /v1/portal/software-alerts/{id}/acknowledge` | PAT-2097. Unapproved software alert lifecycle: tenant list (status, product and device filters, limit/offset, open first), one alert with its append-only history, and acknowledge (portal `admin` only, optional note up to 1000 characters, idempotent, 409 when resolved, 404 for another tenant's id). Shapes in `contracts/portal-api.md`. |
| `GET /v1/portal/mdm/jamf/coverage` | PAT-2145. Jamf Pro coverage from webhooks, every portal role: `connector` health (`status` `not_configured`, `revoked`, `awaiting_first_event`, `amber` or `ok`; amber when no event for 24 hours or the claimed Jamf instance changed), `basis` (`since` = first event, "From Jamf webhooks since <date>", no-backfill and no-delete-event caveats), `counts`, and three buckets paged by `limit` (1 to 500, default 100) / `offset`: `gap` (Jamf reports it, Patched never saw it; `jamf_state` `enrolled` or `dep_assigned_only`), `not_reported_by_jamf` (a macOS device Patched sees that no Jamf event matches; not a claim it is unmanaged. `mdm_state` from the agent's own evidence: `other_mdm` with vendor and server host, `jamf_no_event_yet` (only when an instance is claimed and the Mac names it), `enrolled_mdm_unidentified`, `unmanaged` (the agent reports no MDM, counted as `agent_reports_no_mdm`) or `unknown`) and `covered`. `?bucket=` returns one bucket. Matched by serial (placeholders absent), UDID against `devices.hw_uuid` as fallback. Retired devices excluded; Windows devices never in `unmanaged`. A Jamf-silent Mac reads "not heard from Jamf in N days" (30 days or more), never removed. `?format=csv` is every row, unpaged, with the basis on each row and formula injection neutralised |
| `GET /v1/portal/mdm/jamf/setup` | PAT-2145. Every portal role. The webhook URL (`JAMF_WEBHOOK_PUBLIC_BASE_URL` + `/v1/webhooks/jamf/{webhookID}`, `null` before setup), token status (exists, created, last rotated, revoked; never the token), `check_in_enabled`, the four events with `required` / `subscribed`, and the Header Authentication JSON to paste into Jamf Pro |
| `PUT /v1/portal/mdm/jamf/setup` | PAT-2145. **Admin role only.** `{"check_in_enabled": bool, "reset_jamf_instance": true}`, either or both: subscribe or unsubscribe the optional `ComputerCheckIn`; forget the pinned Jamf instance so the next claim is pinned afresh. `409 not_configured` before a token exists. Audited in `jamf_webhook_audit` |
| `POST /v1/portal/mdm/jamf/token` | PAT-2145. **Admin role only.** No body (or `{}`). Creates the connector and its first token (`201`, `action: token_created`) or rotates the token (`200`, `token_rotated`; the old token stops working on commit, the URL does not change). The plaintext `token` (`pjwh_` + 43 characters) is in this response only, `Cache-Control: no-store`; only its SHA-256 is stored. Each new token starts a new token generation and clears the pinned Jamf instance. Audited |
| `DELETE /v1/portal/mdm/jamf/token` | PAT-2145. **Admin role only.** Revokes the token: every event is `401` until a new one is created. Deletes the Jamf device records first seen under the revoked token (anything a leaked token fabricated), keeping Macs first seen under an earlier token; coverage refills from Jamf's next events once a new token is in place. `devices_deleted` and a plain-language `note` in the response, the count in the audit row. No-op (`changed: false`) when there is no active token |
| `DELETE /v1/portal/mdm/jamf/devices` | PAT-2145. **Admin role only.** Deletes every Mac Jamf has reported for the tenant; the connector, token and URL are kept and the list refills from Jamf's next events. `409 not_configured` without a connector. Audited with the count |
| `GET`/`PUT /v1/portal/software-notifications` | PAT-2009/PAT-2205. The unapproved software alert (default on), new software notification (default off) and independently cursor-backed AI tooling notification (default off), plus destination counts. AI preference changes are append-only audited. `PUT` needs portal `admin`. |
| `GET /v1/portal/homebrew/summary` | PAT-2013. Homebrew estate summary: devices by `collection_status` (`complete`, `partial`, `not_present`, `failed`, `not_reported` kept distinct), distinct formulae/casks/taps, third-party taps, and estate software installations, with a cask counted once only when its app link is `reported_path` (PAT-2032). Additive (PAT-2058) `unreviewed_count`/`unapproved_count`: distinct current formulae and casks together (taps excluded, not approvable) resolved to those two states. Full contract: `contracts/portal-api.md`. |
| `GET /v1/portal/homebrew/formulae` | PAT-2013. Paginated, searchable estate formulae grouped by name and tap, with versions, device counts, on-request vs dependency counts, homepage and source url. Dependency-only entries hidden unless `include_dependencies=true`. Additive (PAT-2058) `approval_state` (`approved`\|`unapproved`\|`ignored`\|`unreviewed`, never null) and `product_key` (`homebrew:formula:<name>`, tap-qualified as `homebrew:formula:<tap>/<name>` when the tap is not the formula's own default), resolved by the same `softwaregov` resolver as applications and extensions. |
| `GET /v1/portal/homebrew/casks` | PAT-2013. Paginated, searchable estate casks grouped by token and tap, with versions, device counts, app names and how many devices link the cask to an app bundle already in inventory. Additive (PAT-2058) `approval_state` and `product_key` (`homebrew:cask:<token>`, tap-qualified as `homebrew:cask:<tap>/<token>` when not the cask's own default tap), same rules as formulae above. |
| `GET /v1/portal/homebrew/taps` | PAT-2013. Paginated taps in use with device counts and remote urls; `homebrew/core` and `homebrew/cask` hidden unless `include_core=true`; taps outside the `homebrew/` organisation flagged `third_party`. |
| `GET /v1/portal/homebrew/devices` | PAT-2013. Paginated per-device Homebrew state (status, truncation, prefixes with owner, issues, package counts), including macOS devices that have not reported (`not_reported`). |
| `GET /v1/portal/homebrew/devices/{deviceID}` | PAT-2013. One device's Homebrew state and a paginated brew list (optional `kind`: `formula`, `cask` or `tap`), with cask-to-app links. Another tenant's device is `404`. |
| `GET /v1/portal/ai-tooling/summary` | PAT-2021/PAT-2109. AI Tooling tab estate summary, plus `vulnerability_products` per exact identity/version. State is `assessed`, `pending` or `not_assessed`; finding count and highest severity are null outside assessed. OSV and NVD provenance stays explicit. Full contract: `contracts/portal-api.md`. |
| `GET /v1/portal/ai-tooling/devices` | PAT-2021/PAT-2109. Paginated (`limit`/`offset`), every tenant device with per-block authority-aware counts and additive exact-version `vulnerability_products`. Tenant scope comes only from verified portal identity. |
| `GET /v1/portal/ai-tooling/devices/{deviceID}/items` | PAT-2206. Paginated current allowlisted tooling items, including currently-present tagged AI desktop apps and browser extensions alongside IDE/package/model/MCP evidence. Desktop usage is exact-identity, fresh-metering evidence only; CSV uses the same builder and includes type-specific model/MCP fields. Foreign devices are 404 and raw attributes, payload content, paths, credentials, MCP args and URL queries are excluded. |
| `GET /v1/portal/extensions` | Browser extensions aggregated per (extension, browser) with PAT-826 `approval_state` (`approved`\|`unapproved`\|`ignored`\|`unreviewed`), versions seen, device count, and per-device hostnames. SQL-enforced GitHub-Non-Author-Review caps: 500 rows (unapproved/unreviewed first) + 50-device drill-down, exact totals kept below the source-row cap, `truncated`/`devices_truncated` flags. EXCEPTION: above a raw (ungrouped) 100k-row-per-tenant source cap the request fails closed instead — a clean 200 with `total:0`, empty `extensions`, `truncated:true`, and `estate_too_large:true`; that last field is the only way to tell this degraded case apart from a tenant with genuinely zero extensions, and is logged server-side (tenant + raw row count) since it can be permanent for a large legitimate tenant. Optional `device_id` (PAT-2156, UUID): same tenant-validated `400`/`404` rule as `GET /v1/portal/software`'s `device_id`, narrows rows to that device's own current extensions (all existing fields, same caps), unfiltered response unchanged. |
| `GET /v1/portal/tagged-products` | PAT-2015/PAT-2206: live category tags grouped by product, with exact distinct device counts, a bounded 100-device membership list and truncation flag, plus a decision-safe `approval_target` or null. Tagged desktop apps add explicit metering coverage/state and nullable exact-identity `last_used_at`; no missing, stale or unavailable signal becomes a never-used claim. Optional `category`, `subtype`, `limit`, `offset`; fails closed above 50,000 source rows. Full contract: `contracts/portal-api.md`. |
| `GET /v1/portal/me` | PAT-2007. The caller's `{"email","tenant_id","role"}`. `role` is `owner` (PAT-1883), `admin` or `viewer`; a domain-matched identity (no `portal_users` row) is always `viewer`. For hiding write controls only; every write re-checks the role server-side. |
| `GET /v1/portal/software-products` | PAT-2393. Curated product identities a software declaration can be resolved to, by required `platform` (`macos`, `windows`) and optional `query` (at most 128 characters); at most 50 rows with `has_more`. Active products and reviewed exact or high confidence aliases only; never a display name. Every portal role reads. |
| `GET /v1/portal/software-declarations`, `GET /v1/portal/software-declarations/{id}`, `GET /v1/portal/software-declarations/{id}/history` | PAT-2393. The tenant's software declarations with `approval_state`, `identity_state`, `observation_state`, `effective_approval_state`, `source` and installation counts, and the append-only creation and resolution history. Every portal role reads. Another tenant's id is `404`, the same as an unknown one. |
| `POST /v1/portal/software-declarations`, `POST /v1/portal/software-declarations/{id}/resolve` | PAT-2393. **Admin role only**, re-checked in the write transaction. Declare approved software before any endpoint reports it, and match a declaration to a curated identity. Approval reaches the existing policy store only through a verified match: a curated macOS bundle ID and Team ID, or on Windows one stable Authenticode publisher observed on every current installation. A declaration is not proof of installation, trust or compliance and never changes a finding or a count. Full contract in `contracts/portal-api.md` "Software declarations". |
| `PUT /v1/portal/software-approvals` | PAT-2007 (applications, browser extensions), PAT-2058 (Homebrew) and PAT-2031 (named tooling observations). **Admin role only.** Sets 1 to 500 products to `approved`, `unapproved`, `ignored` or `unreviewed`, with an optional `reason` (at most 1000 characters). Writes into the matching tenant policy table and appends one `software_approval_decisions` row per changed product. All or nothing. Linked Homebrew casks inherit their app policy and are refused as separate decisions. See "Software approval writes" below. |
| `GET /v1/portal/software-approvals/history` | PAT-2007. Paged (`limit` 1 to 500, default 100; `offset`) decision history, newest first, for the whole tenant or one product (same fields as a write item). Every portal role may read it. |
| `GET /v1/portal/software-approvals/history/export` | PAT-2007. The same history as one file, `format=csv` or `json` (default `json`), `Content-Disposition: attachment`, not paged. Over 50,000 decisions it fails closed with `413 export_too_large`. CSV cells that a spreadsheet would read as a formula are prefixed with `'`. |
| `GET /v1/portal/reports/catalogue` | Fourteen customer-facing report definitions, including `ai-tooling-evidence` and `insurance-evidence`; customer-safe fields only, with no current tier gating. PAT-2406: `local-admin` is admin only, carries `"admin_only": true` and is sent to an admin only (every other caller gets thirteen) |
| `GET /v1/portal/insurance-evidence` | PAT-2258. The cyber insurance evidence pack: each renewal-form endpoint question answered from an existing read model with source path, `as_of`, `unknown_devices` and a plain-English answer (PAT-2496: the disk encryption answer names up to ten reporting devices observed off, by hostname), plus the questions Patched cannot evidence (always present, `not_evidenced_by_patched`). `?format=json` (default), `csv` (one row per question) or `pdf`. Any portal role; tenant from the identity only. See `contracts/portal-api.md` |
| `POST /v1/portal/exports/table-pdf` | PAT-2405. Renders a table the portal posts (the rows of one of its CSV list exports) as a branded A4 landscape PDF, so a list's PDF and CSV show the same rows. Body: `export` (one of sixteen allow-listed keys; the platform owns each title), optional `filters`, `columns` (1 to 40), `rows` (up to 10,000, each exactly `len(columns)` strings) and optional `total_rows`. Reads only the tenant name, from the identity, and stores nothing. Every portal role, except `local-admins` (admin only, `403 admin_role_required`). `400 invalid_request` on any unknown field or shape error, `413` over 16 MiB. See `contracts/portal-api.md` |
| `GET /v1/portal/reports` | History of portal-generated reports, including stable `report_type`, customer label and `formats` (`["pdf","csv"]`, or `["pdf"]` for a report generated before PAT-2405) (`report_records` rows with `source='portal'` only). PAT-2406: `local-admin` records are left out for anyone but an admin, and `total` counts what is shown |
| `POST /v1/portal/reports` | Generate one of the fourteen customer-facing report types; strict `report_type` or rollout alias `type`. Omission remains `executive-summary` for compatibility. Every role, except `local-admin` (admin only, `403 admin_role_required`; PAT-2406) |
| `GET /v1/portal/reports/{id}` | Download a portal-generated report. `?format=pdf` (default; an absent or empty `format` is the PDF) or `?format=csv` (PAT-2405: `text/csv; charset=utf-8`, rendered from the same data as the PDF in the same generation). Any other value, or a repeated `format`, is `400`. A record with no CSV (generated before PAT-2405) answers `404 {"error":"csv_not_available"}` and its PDF still downloads. `404` for other-tenant or admin-source records, in either format. Scheduled reports get both files. Same role, tenant scoping and audit as the PDF; the read-only service identity can download both. PAT-2406: a `local-admin` record is admin only (`403 admin_role_required`, either format, however it was generated). Contract: `contracts/portal-api.md` |
| `GET /v1/portal/reports/schedule` | Compatibility alias for the tenant's `executive-summary` schedule; `{"configured": false}` when unset |
| `PUT /v1/portal/reports/schedule` | Compatibility alias to create/replace the `executive-summary` schedule. Admin only (`403 admin_role_required`; PAT-2408) |
| `GET /v1/portal/reports/schedules` | All report schedules configured by the authenticated tenant |
| `GET /v1/portal/reports/schedules/{reportType}` | One customer-facing typed schedule; unconfigured is `200` with `configured:false` |
| `PUT /v1/portal/reports/schedules/{reportType}` | Create/replace one typed schedule: `cadence`, optional cadence selector, `hour_utc`, `enabled`. Admin only (`403 admin_role_required`; PAT-2408); every role reads schedules |
| `POST /v1/portal/enrolment` | Mint a single-use, 24h agent enrolment token for the caller's own tenant (PAT-453; admin only, PAT-2407: `403 admin_role_required` otherwise); redeems via `POST /v1/enrol` like any other token |
| `POST /v1/portal/enrolment-keys` | Create a reusable, revocable tenant enrolment key (PAT-2250; admin only); plaintext returned once |
| `GET /v1/portal/enrolment-keys` | List the tenant's enrolment keys with usage and status (every role); never the plaintext |
| `POST /v1/portal/enrolment-keys/{keyID}/revoke` | Revoke an enrolment key (admin only); enrolled devices keep their credentials |

**CVE assessment state (PAT-2024):** `GET /v1/portal/devices`,
`GET /v1/portal/devices/{deviceID}` and `GET /v1/portal/findings` each carry an
additive `cve_assessment` object. Per product and per device, `state` is
`assessed` (mapped and matched; `finding_count` and `last_matched_at` set, and
`finding_count: 0` means no known CVEs), `pending` (mapped, current versions
not matched yet; count `null`) or `not_assessed` (no CPE mapping, so no CVE
statement; count `null`, never `0`). Device detail adds a `products` list; the
roster carries the device roll-up only. The findings endpoint adds tenant-level
`last_feed_sync_at`, `last_full_match_at` (estate-wide, `null` until first
recorded), `queued_observations` and assessed/pending/not-assessed product
counts. Matching is change-driven: the extractor queues products whose
installed versions changed and drains the queue every poll cycle; a published
or changed `app_cpe_mappings` row re-matches existing observations; a feed sync
re-matches only products whose mapping resolves to a changed CPE; the nightly
full match stays as the backstop. Full shape: `contracts/portal-api.md`
("CVE assessment state"). Source: `internal/cvepipeline/`, migration 0161.

**Homebrew CVE findings (PAT-2023):** Homebrew formulae and casks are matched
through the same store and appear in `GET /v1/portal/findings` with `app` set to
`"<name> (Homebrew formula)"` or `"<token> (Homebrew cask)"`, plus three
additive fields present only on Homebrew rows: `source` (`homebrew_formula` or
`homebrew_cask`), `confidence_tier` (`high`: curated mapping and version in an
NVD range; `low`: version not confirmable, including HEAD builds and
pre-releases such as `3.0.0-rc1` that the comparator cannot order against the
NVD bound (OpenSSL letter releases such as `1.1.1w` compare exactly since
PAT-2044); the weakest across the aggregated
devices; `medium` is reserved and never produced)
and `install_reasons` (distinct `on_request` / `dependency` / `unknown`). The
admin `GET /admin/devices/{deviceID}/cve-findings` rows add `fixed_version` and,
on Homebrew rows only, `package_source`, `package_name`, `install_reason`,
`required_by` (parent formulae whose receipts list it), `mapping_basis` and
`confidence_tier`. Matching reads the device's current Homebrew list, so only a
complete or `not_present` Homebrew report removes a Homebrew finding, and
lifecycle closure requires the `homebrew` authoritative scope. A formula with no
mapping produces no finding and, when its receipt names homebrew/core or
homebrew/cask, is recorded in `homebrew_cpe_review_queue`.
**Deviation from the ticket, for security:** PAT-2023 asked for exact
homepage / source URL matches to be auto-accepted as mappings. Those URLs are
endpoint-reported and a mapping applies to every tenant, so such a match is
stored only as the review row's `suggested_cpe_key` and produces no finding
until a person curates it through `POST /admin/homebrew/review/{id}/map` or
`.../accept-suggestion` (PAT-2046; see "Homebrew CPE review queue" below).
The first-seen metadata is kept and a
disagreeing later report sets `metadata_conflict`. Low-tier Homebrew rows are
excluded from the overview's critical/high attention vote. Homebrew findings carry no `cve_assessment` product state yet. Source:
`internal/cvematch/homebrew.go`, `internal/cvepipeline/homebrew.go`, migration
0168.

**Estate-wide CVE assessment state (PAT-2028):** `GET /v1/portal/software`
carries the same three-state `cve_assessment` object on every product row,
additive alongside the existing usage/metering fields, but rolled up across
every installation of the product in the tenant rather than one device: the
portal is stateless and cannot build an estate-wide state for a page of
products from the per-device reads above. `state` is `not_assessed` when no
observed name for the product resolves to a CPE mapping anywhere in the
tenant (`finding_count` and `last_matched_at` both `null`, never `0`),
`pending` when the product is mapped and at least one installation is queued
or has not been matched at its current version (`finding_count` set to the
count from the last completed match, `last_matched_at` `null`), or `assessed`
when every installation is current (`finding_count` the distinct-CVE count
across every mapped installation, `last_matched_at` the OLDEST timestamp
across them, i.e. a floor: every installation was matched at least that
recently). `finding_count` uses the same `device_cve_findings` definition as
the per-device `finding_count` above. Source: `internal/cvepipeline/estate.go`
(`AssessEstateProducts`).

**Agent enrolment token (PAT-453):** mints through the same
`mintTenantEnrolmentToken` core as the admin bootstrap-token mint
(`internal/handlers/enrolment.go`), so token TTL, single-use semantics, and
`/v1/enrol` redemption are identical — only the tenant source (verified
portal identity, never the request body) and the audit actor differ. Body
optional; the only field is `delivery_path` (`"mdm"` only on this surface;
defaults when omitted). A client-supplied `tenant_id` in the body is
rejected outright by strict JSON decoding — there is no code path that lets
the caller choose the tenant. Admin role only (PAT-2407): a viewer, or an
identity resolved through `tenant_email_domains`, gets
`403 admin_role_required` and no token is written; the role is re-read in
the transaction that inserts the token (`requirePortalAdmin`, as for
enrolment keys) and checked before the rate limit. Guarded by a **dedicated, per-tenant** rate
limit separate from the read surface's per-identity limit — see below.
Every mint writes an `enrollment_token_audit` row with `actor_email` set to
the caller's verified email (migration 0077; the admin mint path has no
per-user identity and always writes `NULL`).

**Decommissioned tenant refuses to mint or enrol (PAT-1757):** both mint
paths (this one and the admin `POST /admin/tenants/{id}/bootstrap-tokens`,
which share `mintTenantEnrolmentToken`) return `409` for a tenant whose
`tenant_decommission` directive mode is not `"none"`, naming the mode and
`set_at` in the body. `POST /v1/enrol` independently refuses to redeem ANY
enrolment token (including one minted before the directive was set)
against a decommissioned tenant, before the token is consumed or any
credential is issued. There is no override flag: the only path past either
gate is clearing the directive first via
`PUT /admin/tenants/{id}/decommission` with `mode=none`. Full contract:
`contracts/portal-api.md`.

**Invalidate-on-regenerate is scoped to `delivery_path` (PAT-836):** minting
a new token supersedes the tenant's prior unconsumed token(s) of the **same**
`delivery_path` only, atomically with the insert (migration 0084 adds
`bootstrap_tokens.superseded_at`; a superseded token is permanently
unredeemable, same as an expired or already-consumed one — `410 Gone
"enrollment_token superseded by a newer token"` from `POST /v1/enrol`).
`email-link` (single download link, one per tenant) supersedes; `mdm` (fleet
enrolment — N devices legitimately enrol concurrently against N outstanding
tokens) never does, and minting on one path never touches tokens on the
other. This portal endpoint only ever mints `mdm`, so in practice a portal
re-mint never invalidates a still-outstanding portal-issued token — the
supersede behaviour is only observable via the admin mint's `email-link`
path. Full contract: `contracts/portal-api.md`. Source:
`internal/handlers/portal_enrolment.go`, `internal/handlers/enrolment.go`.

**Operator revoke (PAT-2287):** an unused token from either mint path can be
ended early with `POST /admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke`
(see Internal routes). `POST /v1/enrol` then refuses it with the same `410`
and body as an expired token, so the reason is not disclosed.

**Tenant enrolment keys (PAT-2250):** a reusable `pek_…` key, stored as
SHA-256 only (migration 0211), redeems at `POST /v1/enrol` in the same field
as a single-use token, so installers need no change. Each enrolment is
recorded in `tenant_enrolment_key_uses`; the `max_devices` cap counts
distinct devices and is enforced under a `FOR UPDATE` lock on the key row,
taken in the same position as the `bootstrap_tokens` row (credential row,
then tenants row). Revoked, expired or exhausted keys return `410`.
Full contract: `contracts/portal-api.md`. Source:
`internal/handlers/enrolment_keys.go`.

**Typed scheduled reports (PAT-703, PAT-1847):** an in-process ticker in
`patched-api` runs every minute, claims due `portal_report_schedules` rows
(`enabled AND next_run_at <= now()`, `FOR UPDATE SKIP LOCKED`), and passes each
row's `report_type` through the same generator as `POST /v1/portal/reports`.
There is one schedule per `(tenant_id, report_type)`. Crash recovery uses the
same composite identity plus `schedule_slot`, so types sharing a due instant
remain independent. Month days 29–31 clamp to month end; a slot that already
ran is skipped, never duplicated; generation failures retry after 15 minutes.
Email delivery is deferred and history-only for v1. Source:
`internal/reportsched/`, `internal/handlers/portal_schedule.go`, migrations
0061 and 0148.

#### Software approval writes (PAT-2007, PAT-2058)

Portal roles: `portal_users.role` is `admin` or `viewer` (migration 0181).
Rows that existed when 0181 ran were backfilled to `admin`; every new row
defaults to `viewer`. The operator grants a tenant's first admin with
`POST /admin/portal-users {"role":"admin"}`. A user matched only by email
domain has no row and is always a viewer. The role is read from the database
inside the write transaction, never from the client or a cached session.

State mapping into the existing policy store (no new store):

| Portal state | Application (`tenant_app_policies`) | Browser extension (`tenant_extension_policies`) | Homebrew formula/cask (`tenant_homebrew_policies`, PAT-2058) |
|---|---|---|---|
| `approved` | `approved` | `approved` | `approved` |
| `unapproved` | `unapproved` | `unapproved` | `unapproved` |
| `ignored` | `unmanaged` | `ignored` | `unmanaged` |
| `unreviewed` | row deleted | row deleted | row deleted |

Portal-written application rows always carry `enforcement_tier =
report_deploy` (the lowest rung); the caller cannot set a tier. `notes` is
set to the reason, and an extension row's `approved_by` to the caller's
email. The write touches only the product's own row: for an application the
row keyed on exactly that identifier (and Team ID) and platform, with no
`winget_id` or `name`.

**Homebrew formulae and casks (PAT-2058).** Item shape:
`{"type":"homebrew_formula"|"homebrew_cask","name":"<formula name or cask
token>","tap":"<optional>"}`. `name` is required and is normalised
(lower-cased, whitespace-collapsed) before matching; `tap` is optional and,
when given as the package's own default tap (`homebrew/core` for a formula,
`homebrew/cask` for a cask) or omitted, is treated identically to an
unrecorded tap (`softwaregov.NormalizeHomebrewTap`) — a formula reported
with an explicit default tap and one reported with no tap resolve to the
same row and the same `product_key`. `tenant_homebrew_policies` has no
`mandatory` vocabulary and no `enforcement_tier`: PAT-2058's scope is
Approved/Unapproved/Ignored/Unreviewed only, so there is no
`operator_managed` refusal path for Homebrew, and Homebrew is deliberately
excluded from the App Control checks below (those apply to applications and
browser extensions only). Same identity confirmation discipline as an
application: the item is refused `422 unconfirmed_identity` unless this
tenant's own inventory (`software_installations`, identity kind
`homebrew_formula`/`homebrew_cask`) has actually reported that exact (name,
tap) pair — there is no name-only ambiguity to confirm away here, since a
formula name or cask token is already the package's own namespaced identity
(PAT-2013), so `422 name_only` never applies to a Homebrew item.
**Deliberately excluded from unapproved-alert generation** (PAT-2009/2097):
`software_unapproved_episodes.policy_kind` only admits `application`/
`browser_extension` (0183); a Homebrew approval decision still writes its
`software_approval_decisions` audit row and feeds the drift report, it just
never opens or resolves an alert episode or raises a `software.unapproved`
email/webhook. Flagged as a possible follow-up, not built here, since
Homebrew's alert shape (no device-actuation story, no publisher-key trust
path) has not been designed.

Windows publisher key (PAT-2121, migration 0189). When a Windows application
row is written as `approved`, by this endpoint or by the operator
`PUT /admin/tenants/{tenantID}/app-policies` (`platform: "windows"`, the
identifier taken from `bundle_id`, else `winget_id`), the server stores
`tenant_app_policies.publisher_key`:
`authenticode:<root SHA-256>:<leaf Subject DN>`, the DN trimmed with every
whitespace run collapsed to one space and case kept
(`softwaregov.AuthenticodePublisherKey`). It is derived
(`softwaregov.DeriveAuthenticodePublisherKey`) from this tenant's own
evidence for that identifier: each current installation's latest
`software_observations` row (every installation's, when all are removed).
It is stored only when there is at least one installation and every one is
`valid`, has a `microsoft` or `public` root with a thumbprint and a signer,
and all yield one key; otherwise, and on every non-approved write, NULL. No
evidence or disagreeing evidence never refuses the approval. The key is
never accepted from a client: the portal's strict schema rejects
`publisher_key` as an unknown key (`400 invalid_request`), and the operator
endpoint rejects any `publisher_key` field, in any spelling and even `null`,
with `400`. The portal approval of an already-approved product is a no-op
and does not re-derive the key; an operator PUT always does. The overview's
new software urgency reads a trusted Windows product whose key is on an
approved row for a different product as `low`
(`authenticode_publisher_has_approved_products`; rules in
`contracts/portal-api.md`).

Refusals (JSON body `{"error","message","items":[{"index","code","message"}]}`):

| Status | `error` / item `code` | When |
|---|---|---|
| `403` | `admin_role_required` | Caller is not an admin. Checked before the body is read. |
| `400` | `invalid_request`, `too_many_items` | Bad shape: unknown key, case or Unicode-fold variant of a key, duplicate key, trailing content, unknown state, 0 or more than 500 items, reason over 1000 characters, duplicate product, a field that does not belong to the item's type, a browser other than `chrome`, `edge`, `firefox`, `safari` or `any`. |
| `422` | `name_only` | An application item with no identifier. The product is known by display name only. |
| `422` | `unconfirmed_identity` | An application whose identifier is not confirmed: confirmed means a macOS bundle ID with a Team ID that this tenant's inventory has actually observed for it (`device_apps` or a `macos_bundle_team` installation), or, with no Team ID, an identifier that a curated `software_product_aliases` row (not `name_publisher` or `display_name`) vouches for. A client-supplied Team ID with no such evidence is refused. For a Homebrew formula or cask (PAT-2058): this tenant's own `software_installations` evidence has never reported that exact (name, tap) pair. |
| `409` | `operator_managed` | An operator `mandatory` row would resolve for this application under the resolver's own matching (Team ID, bundle ID, Winget ID or every name this tenant has observed for the identifier, uncapped since PAT-2091), not only the row keyed exactly like the item. Stops a more specific portal row from shadowing a mandatory one. It can only see names already reported, so the resolver backs it up (PAT-2091, below). |
| `409` | `app_control_managed` | On a tenant with App Control on, a Chrome, Edge, Firefox or `any` extension item that is either being set to `unapproved`, or whose extension id already has an operator-set (`source = 'operator'`, PAT-2089) `unapproved` row for chrome, edge, firefox or `any` (an operator block), whatever the new state. The customer's own earlier `unapproved` rows are not a block. The operator manages extension blocking there, so the portal can neither add nor lift a block. Safari is exempt: Safari rows never reach the blocklist (it fans out to chrome, edge and firefox only) and Safari removal is not actuated (0178). |

If any item is refused, nothing is written.

The success body is `{"batch_id","state","changed_count","warning_count",
"results":[{"index","type","product_key","previous_state","new_state",
"changed","protected_warning","protected"}]}`. `protected_warning` is `true`
(and `protected` names the `category`, `vendor` and `product_name`) when an
application on the tenant's effective protected-software list (PAT-1801) is
set to `unapproved`. The write still succeeds.

Protection matching uses Team ID or signer and macOS bundle ID first.
Observed Windows package identifiers are never treated as MSI ProductCodes.
An observed display name can match only the protected product name, never
an executable name, and a failed strong identity match does not fall back
to a display-name warning.

**Protected software set Unapproved: one rule on both paths (PAT-2088).**
This endpoint and the operator `PUT /admin/tenants/{tenantID}/app-policies`
apply the same function (`checkProtectedUnapprovedApp`,
`internal/handlers/protected_unapproved.go`): warn and allow, and refuse
only where the Unapproved would feed enforcement for the tenant. The
operator endpoint used to refuse with `409`; it now writes the row and its
`200` body carries the same `protected_warning` and `protected` fields
(`false`/`null` otherwise). The only Unapproved that reaches an agent as
enforcement is an operator-set, non-Safari extension row on an App Control
tenant (the signed extension blocklist, PAT-2089), and the protected list is
keyed on application identity, which no extension row carries. An
application Unapproved reaches no agent as enforcement: it is posture drift,
an alert and a removal-campaign citation, and removal campaigns refuse a
protected target themselves at create and at authorise. So no path refuses
today; a refusal would come back as `409` on the operator endpoint and as
item code `protected_software` (`409 refused`) here. Matching, on both
paths: the Team ID and bundle ID as written, or failing both the name, then
every name and Windows publisher this tenant's inventory reports for the
identifier.

No path to actuation. A portal decision never creates a removal campaign,
removal task, extension removal request, install intent or allowlist entry.
The one projection of this store that reaches agents, the signed
`app_control.extension_blocklist`, is empty for every tenant without App
Control (`tenants.app_control_enabled`), carries only operator-set rows
(`tenant_extension_policies.source = 'operator'`, PAT-2089) on a tenant with
it, and on an App Control tenant the portal cannot add an extension
`unapproved`. Every row this endpoint writes is stamped `source = 'portal'`,
so an extension a customer marked `unapproved` while App Control was off
stays out of the blocklist when the operator switches App Control on later;
the operator sees it as a suggestion (`portal_suggestions` on
`GET /admin/tenants/{tenantID}/extension-policies`) and enforces it only by
adopting it (`PUT .../extension-policies/{entryID}`, which stamps
`operator`). One existing, non-actuating
effect remains and is intended: an application set to `unapproved` appears
in the signed posture (`GET /v1/posture`) as `unapproved_present` drift, and
the macOS menu bar app and the Windows tray show that as a text notice on the
end user's device. Customer admins should know that marking an installed
application Unapproved will show that notice to the people using it.

**Application rows: provenance and mandatory precedence (PAT-2091).** Every
`tenant_app_policies` row this endpoint writes carries `source = 'portal'`;
the operator `PUT /admin/tenants/{tenantID}/app-policies` stamps `operator`
(migration 0201), and `GET .../app-policies` reports `source` on each row.
The resolver (`apppolicy.Index.Resolve`, used by posture, drift, finding
lifecycle, software governance state and alerts, and the portal software
inventory's `policy_state`) never
lets a portal row outrank an operator `mandatory` row, whatever the
specificity: when an operator mandatory row matches the installed app on its
platform, portal rows drop out of the resolution and the result is what the
operator's rows alone resolve to. This covers an approval written before the
app was first reported (for example a Windows app approved by its curated
alias, while the operator has it mandatory by name): once a device reports
the app under that name it resolves `mandatory`, and further portal writes
for it are refused `409 operator_managed`.

**Operator extension-policy list: provenance and suggestions (PAT-2089).**
`GET /admin/tenants/{tenantID}/extension-policies` (admin listener, managed
tier) returns `{"tenant_id","entries":[...],"app_control_enabled",
"portal_suggestions":[...]}`. Each entry carries `source`: `operator` (the
admin API, `POST`/`PUT .../extension-policies`) or `portal` (this endpoint).
`portal_suggestions` repeats the `source = 'portal'` entries, in any state,
when App Control is on, and is `[]` when it is off (nothing feeds the
blocklist then). A suggestion never reaches an agent; the operator enforces
one by updating that entry (`PUT .../extension-policies/{entryID}`), which
stamps `source = 'operator'`. Additive fields; existing readers are
unaffected.

**Status codes:** `503` unconfigured (fail closed), `401` bad/missing JWT,
`403` verified email with no active `portal_users` mapping (the PAT-1883
`/v1/portal/signup/*` routes are the exception: they need no mapping), `404`
missing or other-tenant resource, `429` per-identity rate limit
(`PORTAL_RATE_LIMIT_RPM`, default 120; `PORTAL_RATE_LIMIT_BURST`, default 30,
keyed by verified email; `Retry-After` set) — `POST /v1/portal/enrolment`
additionally enforces its own per-**tenant** limit (`PORTAL_ENROL_MINTS_PER_HOUR`,
default 10; `PORTAL_ENROL_WINDOW_MINUTES`, default 60).

Every authenticated request (including denials) is audit-logged to
`portal_access_log`.

**Source:** `internal/portalauth/`, `internal/handlers/portal.go`,
`internal/report/portal.go` — added PAT-693. Spec locked in PAT-330.

---

## Internal routes

### `POST /admin/tooling-vulnerability-mappings`

Creates a pending exact IDE-extension or local-runtime CPE mapping proposal.
It never publishes the mapping. `POST /admin/tooling-vulnerability-mappings/{id}/review`
then accepts `review_state` (`published` or `rejected`) and non-empty
`reviewed_by`. Publishing invalidates and queues matching current observations;
these internal routes are the staff trust boundary and tenant portal traffic
cannot call them.

### `GET /health`

Same shape as the public health check; separate binding.

**Auth:** network-only (Tailscale).
**Response `200 OK`:** same as public health.

---

### `POST /admin/tenants`

Create a new tenant. Returns credentials that are shown exactly once — store them immediately.

**Auth:** network-only (Tailscale).

**Request body:**
```json
{
  "name": "Acme Ltd",
  "intune_tenant_id": "00000000-0000-0000-0000-000000000000"
}
```

| Field | Required | Notes |
|---|---|---|
| `name` | **yes** | Human-readable tenant name |
| `intune_tenant_id` | no | Customer's Entra/Azure tenant ID; optional at creation |

**Response `201 Created`:**
```json
{
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "bearer_token": "base64url-token",
  "hmac_secret_b64": "base64-encoded-32-byte-secret",
  "warning": "store bearer_token and hmac_secret_b64 immediately — neither is recoverable; rotation requires a new tenant or admin SQL."
}
```

**How credentials are stored:**

| Credential | Stored as | Why |
|---|---|---|
| `bearer_token` | SHA-256 hash only | Token never needs to be read back; comparison is hash-to-hash |
| `hmac_secret` | Raw bytes | HMAC verification requires the actual secret material |

**Deploying to the endpoint:**
```bash
# /etc/patched/bearer-token — the plaintext bearer_token value
# /etc/patched/hmac-secret  — the plaintext hmac_secret_b64 value (base64, uploader decodes it)
# /etc/patched/tenant-id    — the tenant_id UUID
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"name is required"` | Empty or missing `name` field |
| `400 Bad Request` | `"invalid JSON body"` | Malformed JSON |
| `500 Internal Server Error` | `"internal error"` | DB insert failed or entropy source error |

---

### `POST /admin/tenants/{tenantID}/rotate-credentials`

Mint a new bearer token + HMAC secret for a tenant. Previous active credentials expire after a grace window (default 24 h, config: `CREDENTIAL_GRACE_HOURS`), giving endpoints time to pick up the new values before the old ones stop working. Both old and new credentials are valid during the grace period.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` — the tenant to rotate |

**No request body required.**

**Response `201 Created`:**
```json
{
  "tenant_id":       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "credential_id":   7,
  "bearer_token":    "base64url-new-token",
  "hmac_secret_b64": "base64-encoded-32-byte-secret",
  "grace_until":     "2026-12-13T12:00:00Z",
  "warning":         "store bearer_token and hmac_secret_b64 immediately — neither is recoverable after this response. Old credentials expire at grace_until."
}
```

`credential_id` is the `tenant_credentials.id` of the new row.

**Deployment workflow:**
```bash
# 1. Rotate — note the new bearer_token and hmac_secret_b64
curl -s -X POST http://127.0.0.1:8081/admin/tenants/<uuid>/rotate-credentials | jq .

# 2. Before grace_until: push updated /etc/patched/{bearer-token,hmac-secret} to endpoints via Intune
# 3. After all endpoints have restarted: old credentials expire automatically
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No active tenant for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB update/insert failed or entropy source error |

**Source:** `internal/handlers/admin.go` — (PAT-339).

---

### `DELETE /admin/tenants/{tenantID}` — soft-revoke (offboard)

Soft-revokes a tenant by setting `revoked_at = now()`. The tenant's agents are immediately blocked from ingesting (bearer auth joins `tenants` and checks `t.revoked_at IS NULL`). The tenant is hidden from `GET /admin/tenants` and the overview, but all data is preserved. Operation is reversible via `POST /admin/tenants/{tenantID}/restore`.

Idempotent: calling again on an already-revoked tenant returns 200 with the existing `revoked_at`.

**Auth:** network-only (Tailscale).

**Response `200 OK`:**
```json
{"tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "revoked_at": "2026-12-15T12:00:00Z"}
```

| Status | Body | Cause |
|---|---|---|
| `400` | `"tenantID must be a UUID"` | Path param isn't a UUID |
| `404` | `"tenant not found"` | No tenant row for that UUID |

---

### `GET /admin/tenants/revoked`

Returns id, name, and `revoked_at` for every soft-revoked tenant, ordered newest-first.

**Auth:** network-only (Tailscale).

**Response `200 OK`:**
```json
{"tenants": [{"id": "...", "name": "Acme Ltd", "revoked_at": "2026-12-15T12:00:00Z"}]}
```

Returns `{"tenants": []}` when no tenants are revoked.

---

### `POST /admin/tenants/{tenantID}/restore`

Reinstates a soft-revoked tenant by clearing `revoked_at`. Idempotent: no-op on an already-active tenant.

**Auth:** network-only (Tailscale).

**Response `200 OK`:**
```json
{"tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "active"}
```

| Status | Body | Cause |
|---|---|---|
| `400` | `"tenantID must be a UUID"` | Path param isn't a UUID |
| `404` | `"tenant not found"` | No tenant row for that UUID |

---

### `DELETE /admin/tenants/{tenantID}/purge` — hard-purge (irreversible)

Permanently deletes a tenant and all child rows via `ON DELETE CASCADE`. **This operation cannot be undone**: all devices, apps, compliance data, raw payloads, authored assessment bytes and generated report files (`REPORT_STORAGE_ROOT/<tenantUUID>/`, the PDF and CSV renderings) are deleted.

The handler locks and rechecks the revoked tenant and whether artifact metadata exists inside one database transaction. Before the `DELETE`, it atomically renames `REPORT_STORAGE_ROOT/assessments/<tenantUUID>` into the root-confined `.assessment-purge-quarantine/` directory using no-follow, descriptor-relative filesystem operations. A definite pre-commit failure restores the directory. The post-rename DELETE/COMMIT phase ignores client cancellation and uses `TENANT_PURGE_DB_TIMEOUT` (Go duration, default `5m`) so large tenant cascades receive a production-sized bounded window. An ambiguous `COMMIT` result never republishes bytes: the non-success response reports `commit_outcome_unknown` and leaves any residue quarantined for database reconciliation. After a confirmed commit, cleanup does not reopen the served assessments hierarchy. The tenant's generated-report directory `REPORT_STORAGE_ROOT/<tenantUUID>` is quarantined, restored and cleaned up by exactly the same mechanism and in the same transaction window (an absent directory is not an error); only a canonical UUID tenant ID ever reaches the filesystem, so the path can never be the storage root, `assessments` or another tenant's directory. The response reports the first quarantine path still on disk as `quarantine_residue`.

Requires the tenant to already be soft-revoked. Returns `409 Conflict` if the tenant is still active — offboard first.

**Auth:** network-only (Tailscale).

**Response `200 OK`:**
```json
{"tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "purged": true, "purge_status": "committed"}
```

| Status | Body | Cause |
|---|---|---|
| `400` | `"tenantID must be a UUID"` | Path param isn't a UUID |
| `404` | `"tenant not found"` | No tenant row for that UUID |
| `409` | `"offboard before purge"` | Tenant is still active — revoke first |
| `500` | `"assessment artifact quarantine failed"` | The assessment path or quarantine boundary is unsafe or could not be moved; database purge is rolled back |
| `500` | `"report file quarantine failed"` | The generated-report path or quarantine boundary is unsafe or could not be moved; any already-moved assessment bytes are restored and the database purge is rolled back |
| `500` | JSON with `"purge_status":"quarantine_failed_restored"` and no residue | A post-rename verification/durability step failed, but bytes were restored and the tenant remains live |
| `500` | JSON with `"purge_status":"quarantine_failed_residue_retained"`, `"cleanup_pending":true` and `"quarantine_residue"` | A post-rename failure could not safely restore; the tenant remains live and the exact residue must be restored, never deleted |
| `500` | JSON with `"purge_status":"precommit_failed_restored"` and no residue | Database DELETE or definitely rolled-back COMMIT failed and bytes were restored |
| `500` | JSON with `"purge_status":"precommit_failed_residue_retained"`, `"cleanup_pending":true` and `"quarantine_residue"` | Database purge did not commit but restore failed; the live tenant's exact residue must be restored, never deleted |
| `500` | JSON with `"purge_status":"quarantine_failed_restored_unverified"` or `"precommit_failed_restored_unverified"` and no residue | Rename-back occurred but verification or directory fsync failed; bytes are at the served path and require operator verification, not quarantine cleanup |
| `202` | JSON with `"purged":true`, `"cleanup_pending":true` and `"quarantine_residue"` | Database purge committed and the served path is absent, but quarantine cleanup needs the operator recovery procedure |
| `202` | JSON with `"purged":true`, `"purge_status":"committed_cleanup_durability_unconfirmed"`, no `"cleanup_pending"` and no residue | Quarantine removal completed, but fsync of the quarantine directory failed. The reported residue path is deliberately omitted because it no longer exists; investigate the storage durability error rather than running residue cleanup. |
| `503` | JSON with `"purge_status":"commit_outcome_unknown"` and any `"quarantine_residue"` | Commit acknowledgement was ambiguous; do not restore or delete residue until the tenant row is reconciled |

**Reading the `_unverified` suffix (PAT-1512).** On every other failure status the
handler knows the state of the bytes. `_unverified` is the one case where it does not,
and the distinction matters during an incident:

- `quarantine_failed_restored_unverified` — the rename into quarantine failed, the
  rename back to the served path succeeded, but the follow-up identity check or the
  directory fsync did not complete.
- `precommit_failed_restored_unverified` — the database DELETE or commit failed, the
  rename back succeeded, and again the verification or fsync did not complete.

In both cases the bytes are believed to be at their ordinary served path and the tenant
is still live, but that has not been confirmed. Treat it as "verify the served path by
hand", not as a residue to clean up: there is no `quarantine_residue` to act on, and
running the residue recovery procedure against a live tenant's real data is the wrong
move. This is deliberately distinct from `..._restored`, where verification did pass.

The operator recovery procedure for every quarantine outcome above, including which
residue may be deleted and which must be restored, is in
`api-vps-artefacts/OPERATIONS.md` under "Tenant purge assessment quarantine recovery
(PAT-1407)". Read it before acting on any `cleanup_pending` or `quarantine_residue`
response.

**Source:** `internal/handlers/admin.go` — (PAT-431).

---

### `GET /admin/tenants/{tenantID}/export` — GDPR data export bundle

Assembles a single machine-readable JSON bundle of everything Patched holds for a tenant: hosts (with per-host primary-user attribution), installed apps, patches, compliance signals, compliance evaluations, vulnerabilities, generated reports, and the enforcement audit log. Backs the customer data-portability / access obligation under UK GDPR / IoM DPA 2018. Read-only — never mutates.

With the optional `?user=<account>` query param the bundle is scoped to a single named user: only the devices they are the primary user of (matched case-insensitively against `primary_user_account` or `primary_user_display`) and the data attributed to those devices. Tenant-wide records (reports, enforcement audit) are excluded from a user-scoped export so it cannot leak other individuals' data — this fulfils a Data Subject Request for that person.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Query param:**

| Param | Notes |
|---|---|
| `user` | Optional. When set, scopes the bundle to that individual's data (DSR). |

**Response `200 OK`:**
- `Content-Type: application/json`
- `Content-Disposition: attachment; filename="patched-export-<tenantID>.json"`
- Body: the export bundle. Top-level `scope` is `"tenant"` or `"user"`; `user_filter` is present when scoped.

| Status | Body | Cause |
|---|---|---|
| `400` | `"tenantID must be a UUID"` | Path param isn't a UUID |
| `400` | `"user must be non-empty when provided"` | `?user=` supplied but blank — rejected so a blank filter can't silently return a whole-tenant export |
| `404` | `"tenant not found"` | No tenant row for that UUID |

**Source:** `internal/handlers/tenant_export.go` — added 2026-07-10 (PAT-136).

---

### `GET /admin/reports/catalogue`

Returns the immutable 18-entry report registry used by internal consumers.
Each entry includes the stable `type`, customer-safe `label` and `description`,
`default_frequency`, `customer_facing`, `subject_scope` (`tenant` or `device`),
and `admin_pdf_path` template. This endpoint is the source of truth for report
labels and Go-service paths, replacing dashboard-local path maps.

**Auth:** `ADMIN_API_TOKEN` through the internal router middleware.

The registry contains the 18 tenant PDF types plus `device-compliance`. Exactly
fourteen tenant types are customer-facing, including PAT-2009's `new-software`,
`software-drift` (which carries the Unapproved-present list) and
`approved-software`, and PAT-2258's `insurance-evidence`, served on the internal listener at
`/admin/reports/{new-software|software-drift|approved-software|ai-tooling-evidence|insurance-evidence}/{tenantID}.pdf`
(404 for an unknown tenant). The registry is product metadata, not a
tenant entitlement decision.

---

### `GET /admin/reports/{deviceID}/compliance.pdf`

Generate and stream the CIS L1 compliance PDF for a single device.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `deviceID` | UUID | `devices.id` — found via psql or the dashboard |

**Response `200 OK`:**
- `Content-Type: application/pdf`
- `Content-Disposition: attachment; filename="compliance-<hostname>-<timestamp>.pdf"`
- Body: binary PDF bytes

The filename uses the device's `hostname` when available; falls back to the UUID.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"deviceID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"device not found"` | No device row for that UUID |
| `500 Internal Server Error` | `"internal error"` | Report fetch or PDF render failed |

**Example:**
```bash
curl -o compliance.pdf \
  http://127.0.0.1:8081/admin/reports/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/compliance.pdf
```

---

### `GET /admin/reports/executive-summary/{tenantID}.pdf`

Generate and stream the estate-level executive summary PDF for a tenant.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` — found via psql |

**Response `200 OK`:**
- `Content-Type: application/pdf`
- `Content-Disposition: attachment; filename="executive-summary-<tenant-name>-<timestamp>.pdf"`

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | Report fetch or PDF render failed |

**Example:**
```bash
curl -o exec-summary.pdf \
  http://127.0.0.1:8081/admin/reports/executive-summary/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.pdf
```

---

### Authored assessment artifact delivery (PAT-1405)

This path delivers the specialist-authored Endpoint Assurance PDF or DOCX. It
is separate from generated compliance/evidence reports.

- `POST /admin/tenants/{tenantID}/assessment-artifacts/approve` is internal
  and staff-only through the dashboard. It accepts multipart fields
  `engagement_reference`, `document_version`, `generated_at` and `document`.
  The server accepts PDF or structurally valid DOCX bytes up to 25 MiB,
  derives the storage path, hashes the bytes and records the named approver.
  A tenant/engagement/version can be approved only once.
- `POST /admin/tenants/{tenantID}/assessment-artifacts/{artifactID}/download-tokens`
  is internal and staff-only. JSON fields are `recipient` and optional
  `expires_in_hours` (1 to 720, default 168). It returns a single-use opaque
  token; only the SHA-256 token hash is stored.
- `POST /admin/assessment-download-tokens/{token}/redeem` is internal and is
  called by the dashboard's Access-bypassed recipient route over Tailscale
  with the admin service token. It checks
  expiry and first use under a row lock, re-reads the approved server-derived
  path, verifies the exact byte hash, records the download audit and returns
  the PDF/DOCX as an attachment. Missing bytes or an integrity failure do not
  burn the token.

Approval and token issuance require `X-Patched-Actor-Email`, supplied from the
dashboard's authenticated named staff session. Download responses are
`no-store`, `nosniff` and `no-referrer`. The bearer token in the recipient URL
is the existing recipient boundary; no Cloudflare Access account is required.

---

### `PUT /admin/agent-config/{tenantID}`

Update the per-tenant agent configuration. Bumps `config_version` by 1, invalidating any ETag the agent currently holds. The next agent poll will receive the updated config with a fresh Ed25519 signature.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Request body:**
```json
{
  "tier": "patch",
  "proxy": {
    "mode": "system",
    "bypass_when_off_corp": false
  },
  "updated_by": "admin@patched.im"
}
```

`updated_by` defaults to `"system"` if omitted.

**Response `200 OK`:**
```json
{
  "tenant_id":      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "config_version": 2,
  "key_id":         "d16608de1a7b17fb"
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `400 Bad Request` | `"invalid JSON body"` | Malformed JSON |
| `400 Bad Request` | `"tier must be ..."` | Invalid tier or proxy.mode value |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB upsert or signing failed |

**Source:** `internal/handlers/agent_config.go` — (PAT-281); `log_request` field added PAT-286.

---

### `PATCH /admin/agent-config/{tenantID}/blocked-versions`

Atomically add or remove one version from the signed agent configuration's
`blocked_versions` kill switch. This is the incident-response write path: it
preserves every other `agent_config.body` JSONB field and increments the shared
`config_version` only when the effective set changes.

**Auth:** network-only (Tailscale).

**Request body:**

```json
{
  "action": "add",
  "label": "slack",
  "version": "4.51.180"
}
```

`action` is `add` or `remove`. `label` and `version` are exact, non-empty
strings with no surrounding whitespace or control characters; labels also
reject path separators and `..`. Attribution is established by the server as
`admin_shared_token`; caller-supplied actor fields are rejected.

**Response `200 OK`:**

```json
{
  "blocked_versions": {"slack": ["4.51.180"]},
  "changed": true,
  "config_version": 12,
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}
```

An identical add or absent remove returns `changed:false` without bumping
`config_version`. A tenant with no persisted agent-config row returns `409`
rather than synthesising a baseline during an incident mutation.

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Invalid tenant UUID |
| `400 Bad Request` | `"invalid JSON body"` | Malformed, trailing, or unknown JSON fields |
| `400 Bad Request` | validation message | Invalid action, label, or version |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `409 Conflict` | `"agent config not initialised"` | Tenant exists but has no persisted agent-config row |
| `500 Internal Server Error` | `"internal error"` | Transaction or stored-config validation failed |

**Source:** `internal/handlers/blocked_versions.go` — PAT-1238.

---

### `GET /admin/tenants/{tenantID}/agent-logs`

List bundle metadata for all agent log bundles stored for a tenant. Does **not** return bundle bytes; use the fetch endpoint for individual downloads.

**Auth:** Network-only (Tailscale internal listener).

**Path parameter:** `tenantID` — UUID of the tenant.

**Response — 200 OK:**

```jsonc
{
  "logs": [
    {
      "id":                1,
      "device_id":         "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6",
      "request_id":        "f1e2d3c4-b5a6-7f8e-9d0c-b1a2c3d4e5f6",
      "received_at":       "2026-12-19T12:00:00Z",
      "bundle_size_bytes": 8192
    }
  ],
  "total": 1
}
```

Ordered by `received_at DESC`. `logs` is always an array (empty `[]` when no bundles exist).

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Invalid path parameter |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

---

### `GET /admin/tenants/{tenantID}/agent-logs/{requestID}`

Download a single gzipped JSON-lines log bundle.

**Auth:** Network-only (Tailscale internal listener).

**Path parameters:** `tenantID`, `requestID` — both UUIDs.

**Response — 200 OK:** Raw gzipped bytes (`Content-Type: application/octet-stream`, `Content-Encoding: gzip`). The `Content-Disposition` header names the file `agent-log-<requestID>.jsonl.gz`.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` or `"requestID must be a UUID"` | Invalid path parameter |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `404 Not Found` | `"log bundle not found"` | No bundle with that `request_id` for this tenant |
| `500 Internal Server Error` | `"internal error"` | DB read failed |

**Source:** `internal/handlers/agent_logs.go` — added PAT-286.

---

### `GET /admin/ops/hmac-compatibility`

Returns bounded, estate-wide evidence for deciding when the targetless-v2 and
legacy body-only HMAC compatibility branches can be retired.

**Auth:** `ADMIN_API_TOKEN` on the Tailscale-only internal listener. The route
does not exist on the public listener.

**Response `200 OK`:**

```json
{
  "enabled": true,
  "max_distinct_agent_versions": 64,
  "total_accepted": 42,
  "observations": [
    {
      "signing_form": "v3",
      "agent_version": "0.17.0",
      "accepted_count": 42,
      "first_seen_at": "2026-09-20T08:00:00Z",
      "last_seen_at": "2026-09-20T09:00:00Z"
    }
  ]
}
```

Signing forms are the closed set `v3`, `targetless_v2`, `body_only`, and
`Unknown`. Missing, invalid, or unsafe agent versions are reported as
`Unknown`. At most 64 distinct sanitised versions are retained; new values
beyond that limit also fold into `Unknown`. This is a denial-of-service and
storage-cardinality boundary against authenticated clients reporting unbounded
version strings, not a sampling target. The fixed response bound is 260 rows.
The aggregate contains no tenant/device identifiers, bearer tokens, HMAC
secrets, signatures, request timestamps/nonces, request bodies, source IPs, or
user-agent strings.

The telemetry write begins only after the inventory success response is
written. It survives client cancellation after acceptance but has its own
two-second deadline, bounding the request-handler and database-transaction
lifetime; failure is logged and never changes the already-issued response.

Set `HMAC_COMPATIBILITY_TELEMETRY_ENABLED=false` and restart to stop new writes
without changing any request-signature acceptance fallback. Existing aggregate
rows remain readable until `0154_hmac_compatibility_telemetry_rollback.sql` is
applied.

---

### `GET /admin/health`

Return service health indicators and headline metrics in a single call. Designed to drive a dashboard home panel. Each sub-query runs with its own 5-second timeout; partial failures degrade individual fields to `null`/`0` rather than returning a 500.

**Auth:** network-only (Tailscale).

**Response `200 OK`:**
```json
{
  "service_health": {
    "db_reachable": true,
    "ingestion_freshness": {
      "most_recent_ingest_at": "2026-12-12T10:00:00Z",
      "stalest_tenant": {
        "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "tenant_name": "Acme Corp",
        "last_ingest_at": "2026-12-10T08:00:00Z",
        "hours_stale": 50.5
      }
    },
    "catalogue_job": {
      "last_run_at": null,
      "last_run_status": "unknown"
    },
    "cert_expiry": [
      {
        "device_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
        "subject_cn": "*.example.com",
        "not_after": "2026-07-01T00:00:00Z",
        "days_left": 19
      }
    ],
    "backup_jobs": [
      {
        "job": "db-r2",
        "label": "DB → R2 (api-01)",
        "status": "ok",
        "last_success_at": "2026-12-14T03:00:12Z",
        "detail": "snapshot 20261214_030000"
      }
    ],
    "assessment_storage": {"compatible": true}
  },
  "metrics": {
    "total_tenants": 3,
    "total_endpoints": 47,
    "compliance_pct": 82.5,
    "open_findings_by_severity": {
      "critical": 2,
      "high": 8,
      "medium": 15,
      "low": 4,
      "informational": 0
    },
    "platform_split": {
      "macos": 45,
      "windows": 2
    },
    "reports_generated": 0
  }
}
```

**`service_health` field descriptions:**

| Field | Notes |
|---|---|
| `db_reachable` | `true` if `pool.Ping` succeeds within 5 s |
| `ingestion_freshness.most_recent_ingest_at` | `MAX(received_at)` across all of `raw_payloads`; `null` if no payloads yet |
| `ingestion_freshness.stalest_tenant` | The non-revoked tenant whose latest ingest is oldest; `null` if no tenants/payloads |
| `ingestion_freshness.stalest_tenant.hours_stale` | `time.Since(last_ingest_at)` in hours, rounded to one decimal |
| `catalogue_job` | **Stub.** Always returns `{"last_run_at": null, "last_run_status": "unknown"}` — no catalogue-job tracking table exists yet |
| `cert_expiry` | System Keychain certs expiring within 30 days (from `device_certificates.not_after`); capped at 20 rows; empty array `[]` when none |
| `backup_jobs` | One entry per `*.json` heartbeat file in `PATCHED_BACKUP_HEALTH_DIR` (default `/srv/backup/health`); sorted by `job`; empty array `[]` when the dir is missing/empty/disabled. Each backup job writes its own file on success. Fields: `job` (id; falls back to filename), `label` (display name; falls back to `job`), `status` (`"ok"`/`"success"` = healthy, anything else = failed), `last_success_at` (RFC3339, `null` if never), `detail` (optional free text). Staleness/colour is computed by the dashboard — red when `last_success_at` is >26h old or `status` is not ok. |
| `assessment_storage` | `compatible:true` only when assessment metadata state is readable and every required component of `REPORT_STORAGE_ROOT` can be opened as a real directory without following symlinks. An absent `assessments` hierarchy is healthy only while `assessment_artifacts` is empty; existing metadata makes it fail closed. `false` includes a fail-closed detail and means tenant purge cannot safely proceed. |

**`metrics` field descriptions:**

| Field | Notes |
|---|---|
| `total_tenants` | Non-revoked tenant count |
| `total_endpoints` | Total row count in `devices` |
| `compliance_pct` | Pass rate across latest evaluation per (device, rule); `not_applicable` excluded from denominator; one decimal place; `null` if no evaluations |
| `open_findings_by_severity` | Count of `fail` evaluations (latest per device+rule) per severity level; missing severities emit `0` |
| `platform_split.macos` | Devices where `os = 'macOS'` |
| `platform_split.windows` | Devices where `os = 'Windows'` |
| `reports_generated` | Always `0` — no PDF generation tracking table exists yet |

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `500 Internal Server Error` | `"internal error"` | JSON encoding failure (extremely unlikely) |

**Note:** individual sub-query failures do not cause a 500. They log at `WARN` level and degrade the affected field to `null`/`0`/`[]`.

**Example:**
```bash
curl http://127.0.0.1:8081/admin/health | jq .
```

**Source:** `internal/handlers/health_admin.go` — (PAT-347); `backup_jobs` (PAT-387).

---

### `GET /admin/tenants/overview`

Return a summary row for every non-revoked tenant. Powers the Customers list in the dashboard console.

**Auth:** network-only (Tailscale).

**Response `200 OK`:**
```json
{
  "tenants": [
    {
      "id":                   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "name":                 "Acme Ltd",
      "tier":                 "report_deploy",
      "macos_enabled":        true,
      "windows_enabled":      false,
      "device_count":         42,
      "active_last_7d":       38,
      "compliance_pct":       91.3,
      "crit_high_fail_count": 5,
      "backup_status_counts": {
        "ok":        30,
        "stale":      4,
        "none":       6,
        "sync_only":  2
      }
    }
  ]
}
```

Fields:

| Field | Notes |
|---|---|
| `tier` | From `agent_config.body.tier`; defaults to `"report_deploy"` when absent |
| `compliance_pct` | Average per-device compliance %; NA evaluations excluded from denominator |
| `crit_high_fail_count` | Sum of `critical`+`high` failing evaluations (latest per rule, across enabled-platform devices) |
| `backup_status_counts` | PAT-948: partition of this tenant's eligible devices across four backup buckets (`report.BackupBucket`) — `ok` (has a recent backup), `stale` (backup exists but >= 7 days old), `none` (no backup mechanism detected), `sync_only` (only a sync mechanism like OneDrive/iCloud, never counted as backed up). The four counts sum to fewer than `device_count` whenever some devices predate PAT-679/680 and have never reported `backup_status` at all. |

Revoked tenants are excluded. Devices on a disabled platform are excluded from aggregates.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Source:** `internal/handlers/admin_overview.go` — (PAT-340).

---

### `GET /admin/tenants/{tenantID}/devices`

Return the fleet roster for a tenant with per-device compliance summaries. Powers the Customer-detail fleet view in the dashboard console.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Query params:**

| Param | Default | Notes |
|---|---|---|
| `limit` | `500` | Max rows to return; capped at 500 |
| `offset` | `0` | Rows to skip (offset-based pagination) |

**Response `200 OK`:**
```json
{
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "total":     42,
  "limit":     500,
  "offset":    0,
  "devices": [
    {
      "id":         "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
      "hostname":   "MBP-Alice",
      "serial":     "C02XJ0XFJHD3",
      "os":         "macOS",
      "os_version": "15.4.1",
      "last_seen":  "2026-12-11T09:14:22Z",
      "compliance": {
        "pass":           14,
        "fail":            3,
        "not_applicable":  1,
        "error":           0,
        "compliance_pct": 82.4
      },
      "backup": {
        "has_backup":            true,
        "backup_type":           "time_machine",
        "last_backup_at":        "2026-12-10T09:00:00Z",
        "last_backup_days_ago":  1,
        "stale":                 false,
        "sync_only":             false,
        "bucket":                "ok"
      }
    }
  ]
}
```

`backup` (PAT-948) is omitted entirely — not `null` — for a device that has never reported `backup_status` (predates PAT-679/680, or the stored value failed to parse). `bucket` is the derived `report.BackupBucket` classification: `"ok"` | `"stale"` | `"none"` | `"sync_only"`.

Devices on a disabled platform are excluded. Ordered by hostname, then device ID.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Source:** `internal/handlers/admin_overview.go` — (PAT-340).

---

### `GET /admin/tenants/{tenantID}/bootstrap-tokens`

Lists the tenant's enrolment tokens that `POST /v1/enrol` would still accept: not consumed, not expired, not superseded by a newer email-link token, and not revoked. Newest first. Use it to find the id of a token to revoke. It never returns a token's hash, and the plaintext is not stored anywhere to return.

The filter is the enrolment consume step's own predicate, so a listed token is exactly one that could still enrol a device, apart from tenant-level gates checked at enrol time (a decommission directive, a trial device cap). An offboarded tenant still lists, so its outstanding tokens can be revoked.

**Auth:** `ADMIN_API_TOKEN`, internal listener only (same as the mint).

**Response `200 OK`** (`Cache-Control: no-store`):
```json
{
  "tokens": [
    {
      "token_id":      "uuid",
      "created_at":    "RFC3339",
      "expires_at":    "RFC3339",
      "delivery_path": "mdm | email-link"
    }
  ]
}
```

| Status | Body | When |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Source:** `internal/handlers/bootstrap_token_revoke.go` (PAT-2287).

---

### `POST /admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke`

Ends an unused enrolment token before its 24-hour expiry, for example one minted for a machine that then can't be reached, or one pasted somewhere it shouldn't be. Takes no body. Sets `bootstrap_tokens.revoked_at` once and never clears it (migration 0217).

From then on `POST /v1/enrol` refuses the token with exactly the response an expired token gets (`410 Gone`, `"enrollment_token expired"`), so whoever holds it can't tell it was revoked. Devices already enrolled are not affected; revoking a token never touches issued credentials.

Every revoke that changes something writes an `enrollment_token_audit` row with `action = 'revoke'`, `actor = 'admin_shared_token'` (the only identity the shared admin token can vouch for, see "Admin audit attribution" above), and the token's own `delivery_path` and `expires_at`; `generated_at` is the revoke time. The revoke and its audit row commit together: a revoke that can't be recorded is not applied.

A repeat revoke succeeds with `changed: false` and the original `revoked_at`, and writes nothing. An expired or superseded token can still be revoked, which is harmless.

**Auth:** `ADMIN_API_TOKEN`, internal listener only (same as the mint).

**Response `200 OK`** (`Cache-Control: no-store`):
```json
{
  "token_id":   "uuid",
  "revoked_at": "RFC3339",
  "changed":    true
}
```

| Status | Body | When |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"bootstrap token not found"` | No such token for this tenant. Another tenant's token id, an unknown id and a malformed id all get this same response, so the route can't be used to learn whether a token exists under a different tenant |
| `409 Conflict` | `"bootstrap token already consumed: ..."` | A device already enrolled with it. Nothing changes; revoke the device with `POST /admin/devices/{deviceID}/revoke` instead |
| `500 Internal Server Error` | `"internal error"` | DB write failed; nothing was revoked |

There is no `/v1/admin/.../enrollment-tokens` alias for this route or the list. The mint's alias exists only because the PAT-548 agent-enrolment contract named that path.

**Source:** `internal/handlers/bootstrap_token_revoke.go`, `internal/handlers/enrolment.go` (`consumeBootstrapToken`) (PAT-2287).

---

### `POST /admin/devices/{deviceID}/credentials`

Issue a per-device bearer token + HMAC secret so the agent on that device can authenticate `GET /v1/posture`. The credential is stored as a `tenant_credentials` row with `device_id` set, so `auth.LookupDeviceByBearer` can derive the device from the token without any client-supplied ID.

**Auth:** network-only (Tailscale).

**Response `201 Created`:**
```json
{
  "device_id":       "uuid",
  "credential_id":   42,
  "bearer_token":    "base64url-32-bytes",
  "hmac_secret_b64": "base64-32-bytes",
  "warning":         "store bearer_token and hmac_secret_b64 immediately — neither is recoverable after this response."
}
```

Provision one credential per device after first extraction. The agent stores the credential in its secure keychain/DPAPI store and uses it for both `GET /v1/posture` calls.

**Source:** `internal/handlers/admin_device_creds.go` — (PAT-466).

---

### `GET /admin/devices/{deviceID}`

Return full device metadata and compliance posture as JSON. Same data as the PDF compliance report (mirrors `report.Fetch`).

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `deviceID` | UUID | `devices.id` |

**Response `200 OK`:**
```json
{
  "generated_at": "2026-12-12T10:00:00Z",
  "tenant":       "Acme Ltd",
  "device": {
    "id":            "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
    "serial":        "C02XJ0XFJHD3",
    "hw_uuid":       "...",
    "hostname":      "MBP-Alice",
    "computer_name": "Alice's MacBook Pro",
    "hw_model":      "Mac14,2",
    "arch":          "arm64",
    "os":            "macOS",
    "os_version":    "15.4.1",
    "os_build":      "24E263",
    "agent_version": "0.4.0",
    "first_seen":    "2026-07-10T08:00:00Z",
    "last_seen":     "2026-12-11T09:14:22Z"
  },
  "compliance": {
    "total":          18,
    "pass":           14,
    "fail":            3,
    "not_applicable":  1,
    "error":           0,
    "compliance_pct": 82.4
  },
  "evaluations": [
    {
      "rule_key":       "cis_filevault",
      "title":          "Ensure FileVault Is Enabled",
      "severity":       "critical",
      "status":         "fail",
      "observed_value": "Off",
      "evaluated_at":   "2026-12-11T09:14:22Z"
    }
  ],
  "pending_updates": [],
  "patch_history":   [],
  "app_count":       87,
  "backup": {
    "has_backup":           true,
    "backup_type":          "time_machine",
    "last_backup_at":       "2026-12-10T09:00:00Z",
    "last_backup_days_ago": 1,
    "stale":                false,
    "sync_only":            false,
    "notes":                null,
    "bucket":               "ok"
  },
  "agent_health_degraded": [
    {
      "kind": "tcc_denied",
      "subject": "browser_extensions",
      "reason": "full_disk_access_missing",
      "first_seen": "2026-09-20T09:00:00Z",
      "last_seen": "2026-09-24T09:00:00Z",
      "count": 5
    }
  ]
}
```

`evaluations` are ordered: fail → error → not_applicable → pass, then by severity (critical first), then rule_key.

`backup` (PAT-948) mirrors `devices.backup_status` plus the derived `bucket` (`report.BackupBucket`: `"ok"` | `"stale"` | `"none"` | `"sync_only"`) so the dashboard doesn't have to re-implement the bucket rule client-side. Omitted entirely (not `null`) when the device has never reported `backup_status` — either it predates PAT-679 (macOS)/PAT-680 (Windows), or the stored value failed to parse.

`agent_health_degraded` (PAT-2099) is this device's currently open rows from the `agent_health.degraded` channel (PAT-1064): `device_agent_health` filtered to this `deviceID`, unscoped by tenant since this whole endpoint already is. Always an array (empty, never omitted or null) when the device has no open faults. Each entry is `kind`/`subject`/`reason`/`first_seen`/`last_seen`/`count` — the documented-not-enforced vocabulary in `docs/PAYLOAD_SCHEMA.md`'s "Agent health object" section, including the macOS-only `tcc_denied` kind (`browser_extensions`/`mcp_servers`/`ide_extensions`/`package_managers` subjects, `full_disk_access_missing` reason). See `GET /admin/tenants/{tenantID}/agent-health` (`internal/handlers/agent_health.go`, not separately documented in this file) for the tenant-wide, per-device-grouped view of the same table — that one also carries `ever_succeeded`, which this per-device list omits since it's for current state, not recovery history.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"deviceID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"device not found"` | No device row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query or JSON encoding failed |

**Source:** `internal/handlers/admin_overview.go` — (PAT-340).

---

### `GET /admin/tenants/{tenantID}/audit-events`

Tenant-wide, date-range-bounded read over `audit_events` (`POST /v1/events`'s durable store) — "who installed what, over what period" across the whole fleet, not one device. Intended for a compliance/audit report generator or a downstream CSV export (the `portal` repo's `GET /devices.csv`, PAT-701, builds CSV statelessly from a JSON API response the same way — this endpoint returns JSON and leaves CSV serialisation to that kind of downstream consumer, since no Go-side CSV output exists anywhere in this repo to reuse instead).

**Auth:** network-only (Tailscale) — no application-layer auth, same as every other `/admin/*` route.

**Query params:**

| Param | Required | Default | Notes |
|---|---|---|---|
| `since` | **yes** | — | RFC3339. Lower bound, inclusive. |
| `until` | no | now | RFC3339. Upper bound, exclusive. Must be after `since`. |
| `limit` | no | 500 | Clamped to 1–1000. |
| `before` | no | — | RFC3339 half of a composite pagination cursor **within** `[since, until)`. Must be supplied together with `before_id`. |
| `before_id` | no | — | `audit_events.id` (UUID) half of the composite cursor. Must be supplied together with `before`. Set both to the previous page's `next_before.occurred_at` / `next_before.id` to page further back through a wide date range. |
| `event_type` | no | — | Exact match against the six contract event types. |
| `device_id` | no | — | Exact match. |

`before`/`before_id` are a composite (occurred_at, id) keyset cursor, not a bare timestamp like `enforcement-audit`'s `before` — `occurred_at` alone can't disambiguate rows that share an identical timestamp, which is routine on a table fed continuously by every device on the estate. The pair together give a stable total order; using `before` without `before_id` (or vice versa) is rejected.

**Response `200 OK`:**
```json
{
  "events": [
    {
      "id": "9516cc19-d13a-4dbf-9d41-7f59e720e495",
      "device_id": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
      "event_type": "verification_failed",
      "label": "googlechrome",
      "version": "125.0.6422.60",
      "reason": "signer_mismatch",
      "platform": "macos",
      "occurred_at": "2026-12-20T16:00:00Z"
    }
  ],
  "next_before": {
    "occurred_at": "2026-12-20T16:00:00Z",
    "id": "9516cc19-d13a-4dbf-9d41-7f59e720e495"
  }
}
```

`next_before` is present only when the page was full (`len(events) == limit`) — pass its `occurred_at`/`id` back as `before`/`before_id` to fetch the next page within the same `[since, until)` window. `null` means the window is exhausted.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `400 Bad Request` | `"since is required and must be RFC3339"` | `since` missing or unparseable |
| `400 Bad Request` | `"until must be RFC3339"` | `until` present but unparseable |
| `400 Bad Request` | `"until must be after since"` | Empty or inverted range |
| `400 Bad Request` | `"limit must be a positive integer"` | `limit` present but not a positive int |
| `400 Bad Request` | `"before and before_id must be supplied together"` | Only one half of the composite cursor present |
| `400 Bad Request` | `"before must be RFC3339"` | `before` present but unparseable |
| `400 Bad Request` | `"before_id must be a UUID"` | `before_id` present but not a UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Source:** `internal/handlers/audit_events_admin.go`, `internal/report/audit_events.go` — added 2026-08-10 (PAT-1022).

---

### `GET /admin/tenants/{tenantID}/enforcement-audit`

Returns the append-only endpoint enforcement trail used by the staff console's Enforcement Evidence workspace. Events prove that an agent completed or skipped administrator removal, application blocking, extension blocklist application, or browser-extension removal. Device identity is enriched with the current hostname when the audit record's immutable device ID matches a tenant device.

**Auth:** network-only (Tailscale).

**Query params:**

| Param | Required | Default | Notes |
|---|---|---|---|
| `limit` | no | 100 | Positive integer, capped at 1000. |
| `before` | no | — | RFC3339 cursor over `ingested_at`. |
| `device_id` | no | — | Exact immutable device-ID match. |
| `device` | no | — | Case-insensitive partial match over device ID, hostname or computer name. |
| `event_type` | no | — | Repeatable or comma-separated closed event types. Unknown values are rejected. |

Supported event types are `admin_removed`, `admin_removal_skipped`, `app_blocked`, `app_block_skipped`, `extension_blocklist_pushed` and `extension_removed`.

**Response `200 OK`:**

```json
{
  "events": [{
    "id": "9516cc19-d13a-4dbf-9d41-7f59e720e495",
    "device_id": "a573dcbc-7b0e-4424-9831-63179930cf3a",
    "hostname": "MacBook-Pro",
    "event_type": "admin_removed",
    "subject": "temporary-admin",
    "details": {"method": "dscl"},
    "occurred_at": "2026-08-14T07:30:00Z",
    "ingested_at": "2026-08-14T07:30:02Z"
  }],
  "next_before": null
}
```

`hostname` is an empty string when the audit record cannot be enriched. `next_before` is present only when a full page is returned.

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Invalid tenant ID. |
| `400 Bad Request` | `"limit must be a positive integer"` | Invalid limit. |
| `400 Bad Request` | `"before must be RFC3339"` | Invalid cursor. |
| `400 Bad Request` | `"event_type contains unknown value ..."` | Filter is outside the closed event contract. |
| `500 Internal Server Error` | `"internal error"` | Database query failed. |

**Source:** `internal/handlers/enforcement_audit.go` — added under PAT-603, filtered and hostname-enriched under PAT-1352.

---

### `GET /admin/tenants/{tenantID}/findings`

Finding actions and evidence-backed closure history use
`POST/GET /admin/tenants/{tenantID}/finding-dispositions`,
`GET /admin/tenants/{tenantID}/finding-lifecycle`, and
`GET /admin/tenants/{tenantID}/finding-lifecycle/history`. The neutral CIS,
CVE and software contract, event authority and freshness rules are documented
in [FINDING_LIFECYCLE.md](FINDING_LIFECYCLE.md).

Notifications raised from those transitions, and the channels tenant owners
configure to receive them, are documented in
[NOTIFICATIONS.md](NOTIFICATIONS.md). The routes are
`/admin/tenants/{tenantID}/notification-channels`,
`/admin/tenants/{tenantID}/notification-channels/{channelID}/deliveries`,
`/admin/tenants/{tenantID}/notification-channels/{channelID}/test` and
`/admin/tenants/{tenantID}/notification-deliveries`.

The two lifecycle reads are bounded and accept the same query parameters:

| Param | Default | Notes |
|---|---|---|
| `finding_kind` | all | Optional `cis`, `cve` or `software` filter |
| `finding_key` | all | Optional exact stable finding key |
| `device_id` | all | Optional UUID; aggregate CVEs have no device ID |
| `limit` | `500` | Page size, capped at `500` |
| `offset` | `0` | Rows to skip |

Current responses contain a `findings` array; history responses contain an
`events` array. Both also return `limit`, `offset`, `returned`, and the
backwards-compatible `total` field. `returned` and `total` are the number of
rows in this page, not an unbounded matching-row count.

Return all failing and error evaluations across a tenant's fleet, ordered by severity (critical first). Powers the PAT-322 findings view in the dashboard console.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Query params:**

| Param | Default | Notes |
|---|---|---|
| `limit` | `500` | Max rows to return; capped at 500 |
| `offset` | `0` | Rows to skip (offset-based pagination) |

**Response `200 OK`:**
```json
{
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "total":     12,
  "limit":     500,
  "offset":    0,
  "findings": [
    {
      "device_id":    "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
      "hostname":     "MBP-Alice",
      "rule_key":     "cis_filevault",
      "title":        "Ensure FileVault Is Enabled",
      "severity":     "critical",
      "status":       "fail",
      "evaluated_at": "2026-12-11T09:14:22Z"
    }
  ]
}
```

Only `fail` and `error` statuses are included. Devices on a disabled platform are excluded. Ordered: severity (critical → high → medium → low), then status (fail before error), then rule_key, then device_id.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Source:** `internal/handlers/admin_overview.go` — (PAT-340).

---

### `GET /admin/tenants/{tenantID}/metering`

Return per-app software-metering aggregates rolled up across a tenant's entire fleet. One row per (app name, platform) pair. Powers the Software Metering screen in the dashboard console.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Query params:**

| Param | Default | Notes |
|---|---|---|
| `limit` | `500` | Max rows to return; capped at 500 |
| `offset` | `0` | Rows to skip (offset-based pagination) |

**Response `200 OK`:**
```json
{
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "total":     87,
  "limit":     500,
  "offset":    0,
  "apps": [
    {
      "name":               "Slack",
      "platform":           "macOS",
      "install_count":      40,
      "metering_ok_count":  38,
      "fleet_last_used_at": "2026-12-13T09:00:00Z",
      "fleet_launch_count": 4821
    }
  ]
}
```

Fields:

| Field | Notes |
|---|---|
| `install_count` | Number of devices in the tenant's fleet that have this app installed |
| `metering_ok_count` | Devices where the agent reported a reliable Spotlight read (`metering_status = 'ok'`); subset of `install_count` |
| `fleet_last_used_at` | `MAX(last_used_at)` across all devices; `null` when no device has usage data |
| `fleet_launch_count` | `SUM(launch_count)` restricted to devices with `metering_status = 'ok'`; `null` when none qualify |

`null` values mean no metering data was collected: Spotlight indexing disabled on the endpoint, agent predates metering support, or Windows (metering not yet implemented).

Ordered: `fleet_last_used_at DESC NULLS LAST`, then app name alphabetically.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Example:**
```bash
curl http://127.0.0.1:8081/admin/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/metering | jq .
```

---

### `GET /admin/tenants/{tenantID}/metering/breakdown`

Return the per-device usage breakdown for a single named app within a tenant's fleet. Drill-down counterpart to the fleet aggregate endpoint above.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Required query param:**

| Param | Notes |
|---|---|
| `app_name` | App name exactly as it appears in `device_apps.name` (use the fleet aggregate to discover names) |

**Optional query params:**

| Param | Default | Notes |
|---|---|---|
| `limit` | `500` | Max rows to return; capped at 500 |
| `offset` | `0` | Rows to skip |

**Response `200 OK`:**
```json
{
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "app_name":  "Slack",
  "total":     40,
  "limit":     500,
  "offset":    0,
  "devices": [
    {
      "device_id":      "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
      "hostname":       "MBP-Alice",
      "os":             "macOS",
      "metering_status": "ok",
      "last_used_at":   "2026-12-13T09:00:00Z",
      "launch_count":   122
    }
  ]
}
```

Fields:

| Field | Notes |
|---|---|
| `metering_status` | `"ok"` (reliable read), `"spotlight_disabled"`, `"no_user_session"`, or `null` (old agent / non-macOS) |
| `last_used_at` | `null` when metering data is unavailable or app was never launched (interpret with `metering_status`) |
| `launch_count` | Lifetime cumulative count from Spotlight; `null` when unavailable |

Ordered: `last_used_at DESC NULLS LAST`, then hostname alphabetically.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `400 Bad Request` | `"app_name query param is required"` | Missing `app_name` query param |
| `404 Not Found` | `"tenant not found"` | No tenant row for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Example:**
```bash
curl "http://127.0.0.1:8081/admin/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/metering/breakdown?app_name=Slack" | jq .
```

**Source:** `internal/handlers/metering.go` — (PAT-366).

---

### `GET /admin/tenant-app-policy/{tenantID}`

Return the fleet default and all per-app overrides for a tenant. Policies are ordered by platform then identifier.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Response `200 OK`:**
```json
{
  "tenant_id":       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "default_enabled": true,
  "policies": [
    {
      "id":         "cccccccc-dddd-eeee-ffff-000000000000",
      "platform":   "macos",
      "identifier": "com.apple.Safari",
      "name":       "Safari",
      "publisher":  "Apple Inc.",
      "enabled":    false,
      "created_at": "2026-12-13T10:00:00Z",
      "updated_at": "2026-12-13T10:00:00Z"
    }
  ]
}
```

`default_enabled` reflects `tenants.app_updates_default_enabled` — the fleet-wide default that applies to any app with no explicit `policies` row. `policies` contains only per-app overrides.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No active tenant for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Example:**
```bash
curl http://127.0.0.1:8081/admin/tenant-app-policy/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee | jq .
```

---

### `PUT /admin/tenant-app-policy/{tenantID}/default`

Flip the fleet-wide default for app updates (`tenants.app_updates_default_enabled`). The change is recorded in `tenant_app_policy_changes`.

**Auth:** network-only (Tailscale).

**⚠️ Security note:** This endpoint drives agent behaviour on customer endpoints. The GitHub-Non-Author-Review gate applies before first customer ship. Prefer cert-over-secret auth and fast-rotation credentials for long-lived admin integrations.

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Request body:**
```json
{
  "enabled":    true,
  "changed_by": "admin@patched.im"
}
```

| Field | Required | Notes |
|---|---|---|
| `enabled` | **yes** | `true` = update all apps by default; `false` = leave all apps alone by default |
| `changed_by` | no | Actor string; defaults to `"system"` if omitted |

**Response `200 OK`:**
```json
{
  "tenant_id":       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "default_enabled": true
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `400 Bad Request` | `"invalid JSON body"` | Malformed JSON |
| `404 Not Found` | `"tenant not found"` | No active tenant for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB update failed |

**Example:**
```bash
curl -X PUT http://127.0.0.1:8081/admin/tenant-app-policy/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/default \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "changed_by": "admin@patched.im"}'
```

---

### `PUT /admin/tenant-app-policy/{tenantID}/apps`

Upsert a per-app update override. On conflict (`tenant_id`, `platform`, `identifier`) the existing row is updated. The change is recorded in `tenant_app_policy_changes`.

**Auth:** network-only (Tailscale).

**⚠️ Security note:** Same security gate as the estate default route — GitHub-Non-Author-Review before first customer ship.

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Request body:**
```json
{
  "platform":   "macos",
  "identifier": "com.apple.Safari",
  "name":       "Safari",
  "publisher":  "Apple Inc.",
  "enabled":    false,
  "changed_by": "admin@patched.im"
}
```

| Field | Required | Notes |
|---|---|---|
| `platform` | **yes** | `"macos"` or `"windows"` |
| `identifier` | **yes** | Bundle ID (macOS) or MSI product code / registry uninstall key (Windows). Matches `device_apps.identifier`. |
| `name` | no | Display name (e.g. `"Safari"`); stored for dashboard rendering |
| `publisher` | no | Publisher name; stored for dashboard rendering |
| `enabled` | **yes** | `true` = updater keeps this app current; `false` = updater leaves this app alone |
| `changed_by` | no | Actor string; defaults to `"system"` if omitted |

**Response `200 OK`:**
```json
{
  "id":         "cccccccc-dddd-eeee-ffff-000000000000",
  "platform":   "macos",
  "identifier": "com.apple.Safari",
  "name":       "Safari",
  "publisher":  "Apple Inc.",
  "enabled":    false,
  "created_at": "2026-12-13T10:00:00Z",
  "updated_at": "2026-12-13T10:00:00Z"
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `400 Bad Request` | `"invalid JSON body"` | Malformed JSON |
| `400 Bad Request` | `"platform must be ..."` | Unknown platform value |
| `400 Bad Request` | `"identifier is required"` | Empty identifier |
| `404 Not Found` | `"tenant not found"` | No active tenant for that UUID |
| `500 Internal Server Error` | `"internal error"` | DB upsert failed |

**Example:**
```bash
curl -X PUT http://127.0.0.1:8081/admin/tenant-app-policy/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/apps \
  -H "Content-Type: application/json" \
  -d '{"platform": "macos", "identifier": "com.apple.Safari", "name": "Safari", "enabled": false}'
```

---

### `DELETE /admin/tenant-app-policy/{tenantID}/apps/{policyID}`

Remove a per-app override. After deletion the app inherits the fleet default again. The removal is recorded in `tenant_app_policy_changes`. Use `GET /admin/tenant-app-policy/{tenantID}` to find the `policyID`.

**Auth:** network-only (Tailscale).

**Path params:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |
| `policyID` | UUID | `tenant_app_update_policies.id` from the GET response |

**Response `200 OK`:**
```json
{"deleted": true}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Path param isn't a valid UUID |
| `400 Bad Request` | `"policyID must be a UUID"` | Path param isn't a valid UUID |
| `404 Not Found` | `"tenant not found"` | No active tenant for that tenantID |
| `404 Not Found` | `"policy not found"` | No override row for that policyID under this tenant |
| `500 Internal Server Error` | `"internal error"` | DB delete failed |

**Source:** `internal/handlers/app_update_policy.go` — (PAT-364).

---

### `GET /admin/tenants/{tenantID}/apps`

Returns the tenant's installed-app inventory grouped by `(identifier, platform)`,
including per-device evidence and a truthful catalogue/update classification.
Internal listener only (Tailscale).

**Catalogue identity contract (PAT-1160):** a catalogue row matches only when
both product names are non-empty and either name contains the other,
case-insensitively. When `app_catalog_entries.verified_signer` is non-null, the
installed `team_id` must also equal it. Signer equality never creates a match
by itself, because one signer may publish several unrelated products. Known
helper/sub-app identities (including Firefox crash reporter/updater and Zoom
helper bundles) remain inventory evidence but are never catalogue-matched or
actionable.

**Response `200 OK`:**

```json
{
  "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "apps": [
    {
      "id": "com.google.Chrome",
      "name": "Google Chrome",
      "platform": "macos",
      "device_count": 2,
      "version_spread": [
        {"version": "125.0", "device_count": 1},
        {"version": "126.0", "device_count": 1}
      ],
      "update_available": true,
      "updates_enabled": true,
      "target_version": "126.0",
      "catalog_label": "googlechrome",
      "evidence_at": "2026-08-04T09:30:00Z",
      "evidence_state": "update_available",
      "devices": [
        {
          "device_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
          "hostname": "mac-01",
          "version": "125.0",
          "last_seen": "2026-08-04T09:30:00Z",
          "update_state": "update_available"
        }
      ]
    }
  ]
}
```

`target_version` and `catalog_label` are empty strings when no verified
catalogue match exists. `evidence_at` is the latest `device_apps.last_seen`
for the grouped app (null only when there is no evidence row). App-level and
device-level states use the same four values:

| State | Meaning |
|---|---|
| `update_available` | A verified catalogue match exists and at least one non-empty installed version is older than `target_version`. |
| `current` | A verified catalogue match exists and all installed versions are non-empty and at or newer than `target_version`. |
| `evidence_unavailable` | A verified catalogue match exists, but one or more installed versions are empty/unknown and no known older version confirms an update. |
| `not_catalogued` | No verified product match exists; helpers/sub-apps deliberately use this state. |

The legacy `update_available` boolean remains for compatibility, but is `true`
only when `evidence_state` is `update_available`. Empty/unknown installed
versions can never set it.

**Errors:** `400` invalid tenant UUID, `404` tenant not found, `500` database
read failure.

**Source:** `internal/handlers/tenant_apps.go` — truthful evidence contract
added by PAT-1160.

---

### `GET /admin/tenants/{tenantID}/cve-findings`

Return pre-matched CVE findings for all devices under a tenant, grouped by CVE with a per-CVE device list. Results are ordered by CVSS score descending. Findings are refreshed nightly by `patched-cve-sync --mode=scheduled`: NVD/application matching, CISA KEV/SOFA exploitation evidence, then official Apple/MSRC OS-advisory matching. The admin response below retains its existing shape; exploitation provenance is exposed by the portal findings contract and generated PDF/XLSX reports.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Response `200 OK`:**
```json
{
  "findings": [
    {
      "cve_id":      "CVE-2024-12345",
      "description": "A heap buffer overflow in...",
      "description_source": "nvd",
      "cvss_v3_score": 9.8,
      "severity":    "CRITICAL",
      "published_at": "2024-03-15T00:00:00Z",
      "devices": [
        {
          "device_id":        "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
          "hostname":         "MBP-Alice",
          "app_name":         "Google Chrome",
          "app_version":      "120.0.6099.130",
          "match_confidence": "version_confirmed"
        }
      ]
    }
  ],
  "total": 1
}
```

`match_confidence` values:
- `"version_confirmed"` — installed version falls within a known NVD vulnerable range.
- `"version_unverified"` — product matches but NVD provides no usable version-range bounds; potentially affected.

Since PAT-2107 the matcher also applies the device platform and the CVE's age before a finding exists: a CVE whose NVD CPEs apply only on another platform (target_sw `windows` or `android` on a Mac, or an AND configuration requiring another OS) produces no finding; an exact-version CPE is matched as that single version; and a finding that would be `version_unverified` is not reported when the CVE was published more than three years ago. Confirmed findings are never age-cut.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"missing tenantID"` | Path param absent |
| `500 Internal Server Error` | `"db error"` | DB query failed |

**Source:** `internal/handlers/cve.go` — (PAT-335).

---

### `GET /admin/devices/{deviceID}/cve-findings`

Return pre-matched CVE findings for a single device, ordered by CVSS score descending.

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `deviceID` | UUID | `devices.id` |

**Response `200 OK`:**
```json
{
  "findings": [
    {
      "cve_id":           "CVE-2024-12345",
      "description":      "A heap buffer overflow in...",
      "description_source": "nvd",
      "cvss_v3_score":    9.8,
      "severity":         "CRITICAL",
      "published_at":     "2024-03-15T00:00:00Z",
      "app_name":         "Google Chrome",
      "app_version":      "120.0.6099.130",
      "match_confidence": "version_confirmed",
      "last_seen_at":     "2026-12-15T03:00:12Z"
    }
  ],
  "total": 1
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"missing deviceID"` | Path param absent |
| `500 Internal Server Error` | `"db error"` | DB query failed |

**Source:** `internal/handlers/cve.go` — (PAT-335).

---

### `GET /admin/tenants/{tenantID}/needs-attention`

Returns ranked per-device app rows that need attention for a tenant — the server-side three-way join of software inventory × provenance records × CVE findings (PAT-458). Blocks PAT-275 (dashboard "Needs attention" view).

**Auth:** network-only (Tailscale).

**Path param:**

| Param | Type | Notes |
|---|---|---|
| `tenantID` | UUID | `tenants.id` |

**Categories and rank:**

| Category | Rank | Condition |
|---|---|---|
| `vulnerable` | 0 | ≥1 unresolved CVE in `device_cve_findings` for this device+app+version |
| `out_of_date` | 1 | `provenance_records.body->>'state' = 'update_available'`, or installed version differs from `app_catalog_entries.latest_version`, and not vulnerable |
| `blocked` | 2 | `provenance_records.body->>'state' = 'verification_failed'` |

An app that is both vulnerable and out-of-date appears only as `vulnerable`. Items are ordered by rank then by CVSS descending then by app name.

**Response `200 OK`:**
```json
{
  "items": [
    {
      "device_id":         "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "hostname":          "mac-01.example.com",
      "app_name":          "Google Chrome",
      "identifier":        "com.google.Chrome",
      "installed_version": "100.0.4896.75",
      "available_version": "126.0.6478.127",
      "category":          "vulnerable",
      "rank":              0,
      "cve_ids":           ["CVE-2024-1234"],
      "max_cvss":          9.8,
      "max_severity":      "CRITICAL",
      "verified_signer":   null,
      "failure_reason":    null
    }
  ],
  "summary": {
    "total":      5,
    "vulnerable": 2,
    "out_of_date": 2,
    "blocked":    1
  },
  "by_device": [
    {
      "device_id":   "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "hostname":    "mac-01.example.com",
      "total":       3,
      "vulnerable":  1,
      "out_of_date": 2,
      "blocked":     0
    }
  ]
}
```

**Fields — `items[]`:**

| Field | Type | Notes |
|---|---|---|
| `device_id` | UUID string | Device the app is installed on |
| `hostname` | string | Device hostname |
| `app_name` | string | App display name |
| `identifier` | string | Bundle ID (macOS) / product code (Windows); empty string if absent |
| `installed_version` | string | Installed version; empty string if absent |
| `available_version` | string\|null | Latest known-good version from provenance or catalog; null for CVE-only rows |
| `category` | string | `vulnerable` \| `out_of_date` \| `blocked` |
| `rank` | integer | 0 = vulnerable, 1 = out_of_date, 2 = blocked |
| `cve_ids` | string[] | CVE IDs (sorted); empty array when not vulnerable |
| `max_cvss` | number\|null | Highest CVSS v3 score across linked CVEs |
| `max_severity` | string\|null | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW`; null when no CVE |
| `verified_signer` | string\|null | Expected signer from provenance record; null when not from provenance |
| `failure_reason` | string\|null | Populated for `blocked` items only; from `provenance_records.body->>'failure_reason'` |

**Provenance body convention:** `provenance_records.body` is expected to carry `device_id` (UUID text) and `app_name` (text) so the join can be keyed per device. When no provenance record exists for a device+app, the catalog fallback (`app_catalog_entries`) drives `out_of_date` detection.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400 Bad Request` | `"tenantID must be a UUID"` | Non-UUID path param |
| `404 Not Found` | `"tenant not found"` | UUID not in `tenants` table |
| `500 Internal Server Error` | `"internal error"` | DB query failed |

**Source:** `internal/handlers/needs_attention.go` — (PAT-458). **Requires GitHub-Non-Author-Review before customer ship.**

---

### Portal user CRUD — `/admin/portal-users` (PAT-693)

Manages the `portal_users` email → tenant mappings behind the customer
portal (`/v1/portal/*` on the public listener). Internal listener only,
behind `ADMIN_API_TOKEN`.

| Route | Behaviour |
|---|---|
| `GET /admin/portal-users[?tenant_id=<uuid>]` | List mappings: `{"users": [{"email","tenant_id","tenant_name","role","created_at","disabled_at"}], "total": n}` |
| `POST /admin/portal-users` with `{"email","tenant_id","role"?}` | `201` upsert, returns `{"email","tenant_id","role","created_at","disabled_at"}`. Re-POSTing an existing email re-enables it and moves it to the given tenant (idempotent onboarding). `role` (PAT-2007; `owner` since PAT-1883) is optional, `owner`, `admin` or `viewer`: omitted, a new row is `viewer`, an existing row on the same tenant keeps its role, and a row moved to a different tenant drops to `viewer`. `owner` is accepted only while `SELF_SERVICE_SIGNUP_ENABLED` is on; with it off the request is `400` ("role owner needs self-service sign-up enabled") and nothing changes, because the customer portal does not yet treat an owner as admin-level. An existing owner row is unaffected. The body is decoded strictly: unknown, case-variant or duplicate keys are `400`. `400` invalid email/UUID/role, `404` unknown tenant |
| `DELETE /admin/portal-users/{email}` | Soft-disable: sets `disabled_at`; row survives for audit-trail linkage. `200` `{"email","disabled_at"}`, `404` unknown email. Sets `disabled_by = 'operator'` (PAT-1883), also on a member an owner had disabled, so the tenant's owner cannot undo it; re-POSTing the address re-enables it and clears the marker |

**Source:** `internal/handlers/portal_users.go` — added PAT-693.

---

### Tenant email-domain CRUD — `/admin/tenant-email-domains` (PAT-127)

Manages the `tenant_email_domains` domain → tenant auto-binding fallback
behind the customer portal SSO login (see `contracts/portal-api.md` for the
full resolution order against `portal_users`). Internal listener only,
behind `ADMIN_API_TOKEN`.

| Route | Behaviour |
|---|---|
| `GET /admin/tenant-email-domains[?tenant_id=<uuid>]` | List domains: `{"domains": [{"domain","tenant_id","tenant_name","created_at","disabled_at"}], "total": n}` |
| `POST /admin/tenant-email-domains` with `{"domain","tenant_id"}` | `201` register/re-enable. Re-POSTing a domain already active for the SAME tenant is idempotent. `400` invalid domain/UUID, `404` unknown tenant, `409` domain already actively registered to a DIFFERENT tenant (reassignment must go through an explicit disable first) |
| `DELETE /admin/tenant-email-domains/{domain}` | Soft-disable: sets `disabled_at`; row survives for audit-trail linkage. `200` `{"domain","disabled_at"}`, `404` unknown/already-disabled domain |

A domain can only be actively claimed by one tenant — enforced by a partial
unique index (migration 0075) so this can never be misconfigured into
cross-tenant ambiguity at write time.

**Source:** `internal/handlers/portal_email_domains.go` — added PAT-127.

---

### Catalogue review, hosting and discovery pipeline (retired, PAT-2249)

The internal-listener routes that fed the signed catalogue were removed with
it. Each now returns `404`:

- `GET /admin/catalogue/candidates` (PAT-627 / PAT-847), the cross-tenant
  discovery review queue.
- The catalogue review model (PAT-850 to PAT-853, PAT-1315, PAT-1546):
  `GET /admin/catalogue/products`, `GET /admin/catalogue/target-operations`,
  `POST /admin/catalogue/review`, `POST /admin/catalogue/review/bulk`,
  `POST /admin/catalogue/add`, `POST /admin/catalogue/dismiss`,
  `POST /admin/catalogue/revoke`, `GET /admin/catalogue/pipeline-ready`,
  `POST /admin/catalogue/state`, `POST /admin/catalogue/promote`,
  `POST /admin/catalogue/demote` and
  `GET|POST /admin/catalogue/vendor-origins`,
  `DELETE /admin/catalogue/vendor-origins/{id}`.
- The discovery job model (PAT-848 S1 / PAT-943): `GET|POST /admin/discovery/jobs`,
  `POST /admin/discovery/jobs/state`, `GET /admin/discovery/baseline` and
  `GET|POST /admin/discovery/runs`.
- The tenant execution-policy store (PAT-1538):
  `GET|POST /admin/tenants/{tenantID}/execution-policies` and
  `DELETE /admin/tenants/{tenantID}/execution-policies/{policyID}`.

Their tables stay in the database, unread, until a separate migration drops
them; `docs/SCHEMA.md` describes them as they were. Unrelated routes that share
the word "catalogue" are unchanged: the report catalogue
(`GET /admin/reports/catalogue`, `GET /v1/portal/reports/catalogue`), the
shadow-IT catalogue (`GET /admin/shadow-it/catalogue`) and the retired
`GET /v1/catalogue` (`410`, PAT-2246).

### Ring rollout creation and mandatory install intents (retired, PAT-2246)

`POST /admin/tenants/{tenantID}/ring-rollouts` (PAT-1397) and the mandatory
install evaluation, emergency and retry routes
(`POST /admin/tenants/{tenantID}/mandatory-install-intents/evaluate`,
`/emergency` and `/{id}/retry`, PAT-1399) were removed with the signed
catalogue they verified against. `GET /v1/agent-config` no longer delivers
mandatory install intents; `mandatory_install_intents` was never present in
the signed payload served while legacy execution was quarantined, and it is
now never emitted. The remaining ring-rollout status, pause, resume, skip and
emergency routes are unchanged.

What remains of PAT-1399 is read-only history and receipt handling for intents
recorded before retirement:

- `GET /admin/tenants/{tenantID}/mandatory-install-intents` returns current
  per-device state, exact target provenance, delivery attempt and event count.
  Results are bounded (`limit` defaults to 100, maximum 500), may be filtered
  by `state`, and continue with the returned `next_after` plus
  `next_after_id` cursor pair.
- `POST /v1/mandatory-install-status` is device-credential-only and requires
  the exact v3 HMAC binding for method, endpoint id `mandatory_install_status`,
  timestamp, nonce and body. It accepts `received`, `installing`, `succeeded`
  and `failed` in order for an already delivered intent, retains every event,
  and fails closed on replay or any device/product/platform/version/checksum
  substitution. It rejects a body larger than the configured maximum before
  HMAC or JSON processing. Device-reported `error` text is limited to 1024
  UTF-8 bytes.
- Changing or deleting a `mandatory` app policy cancels that policy's queued or
  delivered intents; received, installing and terminal intents are retained.

No endpoint install executor is part of this API.

### Software category tags: `/admin/software-categories/*` (PAT-2015)

Internal listener only, behind `ADMIN_API_TOKEN`. Staff maintenance for the
global category model of PAT-2001: categories and subtypes, match rules and
tags on normalised product identities. None of these tables holds a tenant
identifier. Deliberately not under `/admin/catalogue/*`, which is the
quarantined legacy package catalogue: this is classification, not packaging.

**Rule types** (`identifier_type`, with `qualifier` where the identifier has
two parts). Values are normalised on write and matched by exact equality.

| `identifier_type` | `qualifier` | Platform | Matches today |
|---|---|---|---|
| `macos_bundle_id` | none | macos (forced) | macOS apps by `CFBundleIdentifier` |
| `macos_team_id` | bundle ID (required) | macos (forced) | the one macOS app with that bundle ID signed by that Team ID. A bare Team ID is refused: it would tag every app the vendor ships |
| `windows_authenticode` | product name (required) | windows (forced) | Windows apps whose reported Authenticode signer and display name both match. The Windows agent does not report an app signer yet, so these rules match nothing until it does; the registry `Publisher` is deliberately not used |
| `browser_extension` | `chrome_web_store`, `edge_addons`, `firefox_addons`, `safari_app_extension` | any, macos or windows | Chrome Web Store IDs match in Chrome, Edge and other Chromium browsers; Edge Add-ons IDs in Edge; Firefox add-on IDs in Firefox. Chromium IDs must be 32 letters a to p. Safari App Extension IDs are the extension's bundle identifier (e.g. `com.1password.safari.extension`), matching `device_browser_extensions` rows reported with `browser = "safari"` (PAT-2064) |
| `ide_extension` | `vscode_marketplace`, `open_vsx`, `jetbrains_marketplace` | any, macos or windows | not ingested yet (PAT-2021) |
| `package` | `brew_formula`, `brew_cask` (macos), `npm`, `pip` (any), `winget` (windows) | as listed | `winget` matches Windows apps reported with a canonical Winget ID today. `brew_formula` and `brew_cask` (PAT-2094) match Homebrew formula and cask installations by normalised name -- ingested onto `software_installations` since PAT-2013 (`internal/extractor/homebrew_inventory.go`), just not wired to the matcher until PAT-2094; whether a given device's agent currently sends the `homebrew` block is a separate, agent-side question (PAT-2021/2032), and these rules simply have nothing to match until it does. `pip` names follow PEP 503 |
| `mcp_server` | none | any, macos or windows | matches an MCP server by the name the user chose in their own client config, so no product rule can reliably catch one |
| `kind` | none | any (forced) | PAT-2094: matches every observation of one named observation kind, not an identifier value. Deliberately narrow -- `internal/categorytag.kindRuleKinds` allows exactly one value, `mcp_server`, because every MCP server is AI tooling by definition (it is what gives an AI tool access to local files and systems). Not a general "tag everything of kind X" mechanism; extending the allowed set is a Go code change, not an admin API call |

A display name alone, or a publisher alone, is never a rule.

**Lifecycle.** A rule is created as `draft`, which never matches.
`publish` backfills first and flips second: the backfill runs in bounded
chunks (1,000 observations, one transaction each, selected by exact
normalised value through an index) while the rule is still a draft, so its
tags are invisible to the read API and ignored by ingest. When every chunk
has committed, one short transaction checks the rule is still the same draft
version, flips it to `published` and audits it. A rule therefore reads
published only once its tags exist; a publish that fails or times out leaves
a draft that retrying completes; an edit or retire mid-publish makes the flip
return `409`. An observation first reported during the backfill is tagged by
its device's next ingest. The internal listener's write timeout is 15
seconds: a large publish can outlive the client's response yet still finish
server side. A retry sent while it is still running returns `409` when the
first flip lands first; a retry sent after it finished finds the rule
published, re-runs its reconcile and returns `200`. `GET .../rules/{id}`
shows the outcome either way. Publishing an already published rule re-runs its
reconcile and is not audited.

A published rule can be edited: `version` increments, the edit commits, then
its tags are reconciled in the same chunks (new matches tagged; tags whose
observation now carries a different identifying value retired with reason
`rule_changed`). A published rule cannot change its `identifier_type`, or
its `qualifier` for a `package` rule: that would move it to a different kind
of observation and leave the old tags live, so the edit returns `409`;
retire the rule and create a new one. Platform changes are allowed. If that reconcile cannot finish the response is `500` with
the edit saved and a message to run `POST /admin/software-categories/backfill`,
which completes it. Editing a
draft retires any hidden tags an unfinished publish left. `retire` is
terminal and one transaction: the rule stops matching and its live tags are
retired with reason `rule_retired`. Retire takes the rule `FOR UPDATE`;
ingest and backfill read it `FOR SHARE`, so a retired rule never gains a live
tag. Admin writes are retried once on a deadlock (`40P01`).

**Retired tags are marked, not deleted.** `software_category_tags` keeps
`retired_at` and `retired_reason`, so a tenant's record of what was
classified, when, and by which rule survives a rule change, the same
evidence-and-decisions-are-separate principle the observation domain follows.
The read API filters retired tags out.

**Absence is no opinion.** A live tag is retired as `no_longer_matches` only
on authority: its installation was closed under an authoritative inventory
scope, or the observation positively carries a different identifying value
(a different signer, Team ID or product). A payload that merely omits
`team_id` or `signed_by`, or carries no usable display name, keeps the tag.

One case is deliberate. On macOS the Team ID is part of an installation's
identity, so a payload that drops `team_id` makes the extractor close the
signed installation and open an unsigned one. The closed installation's tags
are retired, including Team ID rule tags, and the unsigned one does not match
a Team ID rule, because that rule asserts signed provenance. A bundle-ID rule
tags the new installation again on the same ingest.

**Ingest.** The extractor evaluates published rules and product tags for each
device's apps and browser extensions inside the ingest transaction, under a
savepoint (the PAT-2024 pattern). A failure rolls back only the tag writes,
logs a warning, and never fails the extraction; the device's next ingest or
`POST /admin/software-categories/backfill` repairs it. With nothing published
the cost is one existence probe.

**Audit.** Every create, edit, publish and retire of a rule or product tag
writes one row to `software_category_audit` with `before` and `after`
snapshots. Update, delete and truncate raise, which stops accidental
writes. Known limitation, shared with the other audit tables: the owning
role, `patched`, runs both migrations and the app and can disable the
triggers; see AGENTS.md. The
authoritative `actor` is always `admin_shared_token`; an optional body
`actor` is stored as `claimed_actor` and never trusted (PAT-1135), with the
observed source address.

| Route | Behaviour |
|---|---|
| `GET /admin/software-categories` | Vocabulary: `categories` with `subtypes`, `identifier_types`, `browser_stores`, `ide_marketplaces`, `package_sources`, `platforms` |
| `GET /admin/software-categories/rules[?state=draft\|published\|retired]` | `{rules: [...]}`, newest first |
| `POST /admin/software-categories/rules` | Body `{identifier_type, identifier_value, qualifier?, platform?, category, subtype, notes?, actor?}`. `201 {rule, backfill}` as a draft. `400` invalid, `409` a live rule already covers the same identifier and classification |
| `GET /admin/software-categories/rules/{id}` | One rule. `404` unknown |
| `PUT /admin/software-categories/rules/{id}` | Full replacement of the editable fields (same body as create). `200 {rule, backfill}`; an unchanged body writes nothing. `409` retired |
| `POST /admin/software-categories/rules/{id}/publish` | Optional body `{actor}`. `200 {rule, backfill: {tagged, retired}}`. `409` retired |
| `POST /admin/software-categories/rules/{id}/retire` | Optional body `{actor}`. `200 {rule, backfill}`. `409` already retired |
| `GET /admin/software-categories/rules/{id}/audit` | `{entries: [{id, entity_type, entity_id, action, actor, claimed_actor, source_addr, before, after, at}]}`, oldest first |
| `GET /admin/software-categories/product-tags[?state=published\|retired]` | `{product_tags: [...]}` |
| `POST /admin/software-categories/product-tags` | Body `{canonical_key, category, subtype, notes?, actor?}` naming a `software_products` row. Live at once; tags every installation resolved to that product. `201 {product_tag, backfill}` |
| `POST /admin/software-categories/product-tags/{id}/retire` | Optional body `{actor}`. `200 {product_tag, backfill}` |
| `GET /admin/software-categories/product-tags/{id}/audit` | As for rules |
| `POST /admin/software-categories/backfill` | Re-runs every published rule and product tag, each in its own transaction. Idempotent recovery path; writes no audit row. `200 {backfill}` |

Rule JSON: `{id, identifier_type, identifier_value, qualifier, platform,
category, subtype, notes, version, state, created_by, created_by_claimed,
created_at, updated_at, published_at, retired_at}`.

### Software catalogue review: `/admin/software-catalogue/*` (PAT-2404)

Internal listener only, behind `ADMIN_API_TOKEN`; never mounted on the public
or portal routers. Staff promote an identity that devices report, with signing
evidence, into a reviewed `software_product_aliases` row, and withdraw one.
Semantics, the evidence bar and the effect on tenants are in
[SOFTWARE_DOMAIN.md](SOFTWARE_DOMAIN.md#operator-review-of-an-observed-identity-pat-2404).
Deliberately not under `/admin/catalogue/*`, the quarantined legacy package
catalogue: this is identity, not packaging.

A reviewed alias resolves installations of that identity for **every tenant**
on their next report. Treat a review as an estate-wide change.

Errors are `{"error": "..."}`. Bodies are strict: an unknown field, a case or
fold variant of a known one, trailing content or a non-object body is `400`.
`limit` is refused (`400`) outside its range, never clamped.

| Route | Behaviour |
|---|---|
| `GET /admin/software-catalogue/candidates?platform=macos\|windows[&query=][&limit=]` | Identities among current installations that have no live alias, of kind `macos_bundle_team` or `windows_native_publisher` only. `platform` is required. `query` (at most 128 characters) is a case-insensitive substring of the identity value, companion, an observed name or an observed publisher. `limit` 1 to 200, default 50. `200 {candidates, total, has_more}`, most devices first. |
| `GET /admin/software-catalogue/aliases[?platform=][&limit=]` | Reviewed aliases, retired ones included, newest first. `limit` 1 to 1000, default 200. `200 {aliases, total, has_more}`. |
| `POST /admin/software-catalogue/reviews` | Body `{platform, identity_kind, identity_value_normalized, companion_value_normalized, canonical_name, vendor_name, reason, actor}`, all required. The four identity fields only name the candidate and are compared exactly as given. `201 {alias, revived}`. `400` malformed or blank field; `404` no device currently reports that identity; `409` the identity already has a live alias, the named product exists but is not active or is under another vendor, or a retired alias is being reviewed under a different product; `422` unsupported kind, or the evidence is below the bar. |
| `POST /admin/software-catalogue/aliases/{id}/retire` | Body `{reason, actor}`, both required. `200 {alias}`. `404` unknown id; `409` already retired, or not a reviewed alias. |

Candidate JSON: `{platform, identity_kind, identity_value_normalized,
companion_value_normalized, observed_names, observed_publishers, device_count,
tenant_count, evidence, promotable, blocked_reason}`. `observed_names` and
`observed_publishers` are distinct values, at most 10 each. `evidence` is
`{signing_states: {<verdict>: installations}}` and, on Windows,
`root_kinds` (distinct roots among valid signatures) and
`authenticode_publisher_key_count` (distinct publisher keys among valid
signatures under a `microsoft` or `public` root). `not_reported` counts
installations with no verdict. `blocked_reason` is present only when
`promotable` is false: `bad_signature_present`, `team_id_malformed`,
`no_signed_installation`, `publisher_missing`, `no_valid_authenticode` or
`enterprise_root_only`. No tenant identifier is returned.

Alias JSON: `{alias_id, product_id, canonical_name, vendor_name,
lifecycle_state, platform, identity_kind, identity_value_normalized,
companion_value_normalized, match_confidence, provenance, evidence, created_by,
created_at, last_reviewed_at, retired_at}`. `created_by` is the claimed actor
of the latest review.

`actor` is a claim, stored as `created_by` and as the audit row's
`claimed_actor`; the audit row's `actor` is always `admin_shared_token`
(PAT-1135).

### Homebrew CPE review queue: `/admin/homebrew/review/*` (PAT-2046)

Internal listener only, behind `ADMIN_API_TOKEN`. Staff curation for
PAT-2023's `homebrew_cpe_review_queue`: the global, tenant-free backlog of
official-tap Homebrew formulae and casks that report with no curated CPE
mapping. The nightly full match (`internal/cvepipeline.MatchHomebrewFull`) is
the only writer of new queue rows; this API is the only writer of a Homebrew
curated `app_cpe_mappings` row. Deliberately not under
`/admin/software-categories/*`, which is classification, not vulnerability
matching, and shares no table with this queue.

**Event path.** A mapping curated here is picked up automatically, with no
further action from this API: PAT-2045's `cvepipeline.SyncMappingSnapshot`
diffs `app_cpe_mappings` against `cve_mapping_snapshot` on every drain cycle
(the extractor's poll loop) and does not care who or what wrote the row. A
freshly curated Homebrew mapping is therefore queued as a `mapping` job on
the next cycle, expanded to every active device whose current Homebrew list
carries the formula or cask, and matched, with no new payload and no full
match required. Existing installs on devices that already reported the package
gain findings on that same drain.

**Estate prevalence** is the count of devices, across every tenant, whose
current Homebrew list (`homebrew_current_entries`) carries the row's formula
or cask today. **Reporting tenant count** (`reporting_tenant_count`) is the
count of distinct tenants behind those devices, from the same table, same
join key. Both are computed live on every `GET`, never stored on the queue
row; the response never carries a tenant or device identifier, only these
two aggregate counts.

**Lifecycle.** A row starts `pending`. `map` and `accept-suggestion` both
insert one curated `app_cpe_mappings` row (`source_type` `homebrew_formula`
or `homebrew_cask` matching the row's `package_kind`, `review_state`
`curated`) and mark the queue row `mapped`; `dismiss` marks it `dismissed`.
All three require the row to be `pending` (`409` otherwise), so a mapped or
dismissed row cannot be silently re-actioned. Both curating actions validate
the CPE key (`cpe_vendor:cpe_product`, case-insensitive, neither half empty
or containing `:` or whitespace) actually exists in the local NVD store
(`cve_feed_entries.cpe_patterns`) before writing anything: `400`
(`ErrUnknownCPEKey`) if it does not, so a mapping can never be curated onto a
key with zero CVE presence.

`accept-suggestion` carries two independent trust gates, both `409` unless
explicitly overridden, because a suggestion is never staff-authored: it is a
guess `internal/cvepipeline`'s nightly run derived from one report's own
homepage or source URL.

- `confirm_conflict: true` is required when the row's `metadata_conflict` is
  set: at least one other device's report disagreed with the first-seen
  metadata the suggestion rests on.
- `confirm_single_reporter: true` is required when fewer than two distinct
  tenants currently report the package (`reporting_tenant_count < 2`, counted
  live at request time, same as the list column). `metadata_conflict` only
  ever fires when two reports disagree, so a formula or cask with exactly one
  reporting tenant can carry a plausible suggestion with **no** conflict ever
  recorded: a single malicious or simply wrong tenant, otherwise accepted
  estate-wide on one click. This gate is independent of `confirm_conflict`:
  either can be required without the other.

Both flags default to `false` and are carried into the audit row exactly as
given, so a reviewer can later see which trust gate, if any, staff overrode.

**Audit.** Every `map`, `accept_suggestion` and `dismiss` writes one row to
`homebrew_review_audit` with `before` and `after` snapshots (the `after` on a
curating action also carries the new mapping's id, vendor and product, plus
`confirmed_conflict` and `confirmed_single_reporter` as supplied on the
request). Update, delete and truncate raise, same append-only shape as
`software_category_audit`. The authoritative `actor` is always
`admin_shared_token`; an optional body `actor` is stored as `claimed_actor`
and never trusted (PAT-1135), with the observed source address.

| Route | Behaviour |
|---|---|
| `GET /admin/homebrew/review[?status=pending\|mapped\|dismissed][?kind=formula\|cask][?sort=recent\|prevalence]` | `{reviews: [...]}`. Default sort is most recently seen first; `sort=prevalence` orders by estate prevalence, highest first |
| `POST /admin/homebrew/review/{id}/map` | Body `{cpe_vendor, cpe_product, actor?}`. `200 {review}`. `400` invalid, malformed or unknown key, `404` unknown id, `409` row is not pending |
| `POST /admin/homebrew/review/{id}/accept-suggestion` | Body `{confirm_conflict?, confirm_single_reporter?, actor?}`, or no body. Curates the row's own `suggested_cpe_key`. `200 {review}`. `400` no suggestion on the row or the key is unknown, `409` row is not pending, contested metadata without `confirm_conflict: true`, or fewer than two reporting tenants without `confirm_single_reporter: true` |
| `POST /admin/homebrew/review/{id}/dismiss` | Optional body `{actor}`. `200 {review}`. `409` row is not pending |

Review JSON: `{id, package_kind, name, homepage, source_url, status,
suggested_cpe_key, metadata_conflict, metadata_conflict_count, first_seen_at,
last_seen_at, resolved_at, estate_prevalence, reporting_tenant_count}`. Never
a tenant or device identifier.

### Automatic CVE mapping proposals: `/admin/cve-mapping-proposals/*` (PAT-2138)

Internal listener only, behind `ADMIN_API_TOKEN`. The staff review queue for
CPE mappings the platform proposes automatically for installed products with
none. The full contract, object shapes, states and reasons are in
`contracts/cve-mapping-proposals-admin.md`; the dashboard review page is built
against it.

| Route | Behaviour |
|---|---|
| `GET /admin/cve-mapping-proposals[?state=pending\|needs_review\|auto_published\|approved\|rejected\|superseded\|all][&limit=&offset=]` | `{status, counts, total, limit, offset, proposals}`. Default: open proposals (pending and needs_review), oldest first. `status.proposer` / `status.digest` report `ok`, `degraded` with a reason (`model_unavailable`, `nvd_unavailable`, `linear_token_missing`, `linear_api_error`), or `unknown` before a first run. Each proposal carries live `affected_devices` and `affected_tenants` counts |
| `GET /admin/cve-mapping-proposals/{id}` | `{proposal}` with candidates, model choice and rationale, evidence, live affected device and tenant counts, `covered_names` and the audit trail. `404` unknown id |
| `POST /admin/cve-mapping-proposals/{id}/approve` | Body `{cpe_vendor?, cpe_product?, actor?}` or none. Publishes (or curates an automatic mapping) with the model's choice or another of the proposal's own candidates, never a free-form CPE. `200 {proposal}`. `400` no choice and none given, or not a candidate; `404`; `409` wrong state or already mapped |
| `POST /admin/cve-mapping-proposals/{id}/reject` | Optional body `{actor}`. Rejects an open proposal; on a published one, revokes it: the mapping row is deleted, devices are re-matched, and the findings it produced are recorded `withdrawn`, never `verified_fixed`, with no notification. `200 {proposal}`, `404`, `409` |

Every action writes `cpe_mapping_proposal_audit` with the PAT-1135 actor
split. Automatic actions are audited as actor `cpe_proposer`.

### Software lifecycle mappings: `/admin/lifecycle/*` (PAT-2147)

Internal listener only, behind `ADMIN_API_TOKEN`. Staff review of the links
between a canonical product identity and its endoflife.date product, the data
behind `GET /v1/portal/reports/software/unsupported`. Same shape as the
PAT-2046 and PAT-2138 review queues: a mapping is `proposed` until staff
publish it, and only `published` mappings change what a customer sees.

A mapping names the identity exactly as `software_installations` carries it:
`platform`, `identity_kind` (`macos_bundle_team`, `macos_bundle`,
`homebrew_formula`, `homebrew_cask`, `windows_winget`,
`windows_native_publisher`, `windows_native`; never a display name), the
normalised `identity_value` and the exact `companion_value` (Team ID,
publisher, tap, or `''`). `identity_kind` `os` maps the operating system
itself (`identity_value` is the platform). `version_rule` picks the cycle
from the installed version: `major` (`154.0.1` to `154`), `major_minor`
(`3.12.4` to `3.12`), `regex` (one capture group, e.g. `^1\.(8)\.` for
Corretto 8), `macos_major` (`15.4.1` to `15`, `10.15.7` to `10.15`), or
`windows_build` (the build in `10.0.BUILD` picks the feature release; the WMI
caption picks the edition, Unknown when it is absent and the editions'
dates differ).

| Route | Behaviour |
|---|---|
| `GET /admin/lifecycle/mappings[?status=proposed\|published\|rejected]` | `{mappings}`, each with the slug's `lifecycle_fetched_at`, `lifecycle_cycle_count`, `lifecycle_last_error`, and a live `estate_installation_count` (current installations across every tenant; a count only, never a tenant or device id) |
| `POST /admin/lifecycle/mappings` | Body `{platform, identity_kind, identity_value, companion_value?, eol_slug, version_rule, version_regex?, rolling?, rolling_window_days?, notes?, actor?}`. `201 {mapping}` as `proposed`. `rolling: true` opts the mapping into the rolling-release rule below, with `rolling_window_days` (1 to 90, default 21) overriding the window. `400` invalid (display-name kinds, bad slug, a regex without exactly one group, kind on the wrong platform, a `macos_bundle_team` with no Team ID, `rolling_window_days` without `rolling`, a window outside 1 to 90, `rolling` on an `os` mapping); `409` a live mapping already covers the identity |
| `POST /admin/lifecycle/mappings/{id}/publish` | Optional body `{actor}`. `200 {mapping}`. `409` not proposed, or the slug has no fetched cycles yet (refresh first; this also catches a mistyped slug) |
| `POST /admin/lifecycle/mappings/{id}/reject` | Optional body `{actor}`. Rejects a proposal, or withdraws a published mapping (its rows read Unknown from the next report). `409` already rejected |
| `GET /admin/lifecycle/products` | `{products, cache_ttl_days}`: every slug's `fetched_at`, `last_attempt_at`, `last_error`, `cycle_count` and `stale` (older than 7 days) |
| `POST /admin/lifecycle/refresh` | Optional body `{slug?, actor?}`. Refetches one slug, or every slug a proposed or published mapping names. Answers `202 {status: "started", slugs}` at once and runs detached (a full refresh can outlast the 15 s write timeout); read the outcome from `GET /admin/lifecycle/products`. `409` when a refresh (this or the scheduled one) already holds the lock |

**Rolling-release rule (PAT-2171).** The source dates a browser major as ending
when the next one ships, two to four weeks out, so under the ordinary rule
every current install would read `ending_within_90_days`. A mapping with
`rolling_window_days` set (`GET` shows it; `null` is the ordinary rule) is
judged by release order: the latest released major is `supported`; the
previous major is `supported` while the latest is under `rolling_window_days`
whole UTC days old, `unsupported` from that day on; every older major is
`unsupported`; it never reads `ending_within_90_days`. Cycles the source flags
`is_lts` (Firefox ESR) keep their own dates and the ordinary rule. A cycle with
no release date reads `unknown` (`no_release_data`). Report rows for a rolling
mapping carry a `note` and, when `supported`, no `days_to_eol` or `eol_date`.
The five Chrome and Firefox seed mappings are rolling and were published by
migration 0219. The source has no Chrome Extended Stable cycle, so an Extended
Stable install reads `unsupported` once it is two or more majors behind.

Every mapping write is audited in append-only `lifecycle_mapping_audit`
(`seed`, `propose`, `publish`, `reject`, `withdraw`) with the PAT-1135 actor
split. The scheduled refresh is `patched-cve-sync --mode=lifecycle-sync`, also
run as the last stage of the nightly `--mode=scheduled`; see
`api-vps-artefacts/OPERATIONS.md`.

Source: `internal/lifecycle`, `internal/handlers/lifecycle_admin.go`.

### Software governance notifications (PAT-2009)

```text
GET /admin/tenants/{tenantID}/software-notifications
PUT /admin/tenants/{tenantID}/software-notifications   {"unapproved_alerts_enabled": false}
```

Same body and response as `/v1/portal/software-notifications`
(`contracts/portal-api.md`); a write records `updated_by: "operator"`. 404 for
an unknown or revoked tenant.

**The unapproved software alert.** Event `software.unapproved_detected`, on
for every tenant unless turned off. Raised when a customer admin
(`PUT /v1/portal/software-approvals`) or the operator
(`PUT /admin/tenants/{tenantID}/app-policies`, extension policy add or update)
moves a product into Unapproved while it is installed on at least one device
(`trigger: "marked"`, one alert listing every device), and when extraction of
a report with current evidence time finds an Unapproved product on a device
not yet alerted in the current episode (`trigger: "observed"`, one alert per
product and device). Dedupe is the ledger
`software_unapproved_alerted_devices` keyed by (episode, device); an episode
is one transition of the policy row into Unapproved
(`software_unapproved_episodes`). Delivery is transactional with the ledger:
a `webhook_deliveries` row for every enabled `tenant_webhooks` endpoint
subscribed to the event (sent by the PAT-134 sweeper, body-only signature as
for `vulnerability.discovered`), and an email to `tenants.contact_email` sent
by the software governance runner in `patched-api` through the Graph mailer:
immediately for `marked`, one daily digest at 07:00 UTC for `observed`. No
contact email: the alert is recorded `no_recipient` and the webhook still
goes. Raising never makes a network call and never fails the approval write
or the extraction.

**The new software notification.** Event `software.first_seen`, off by
default. With it on, the runner raises one daily digest (window ending 07:00
UTC) into every enabled PAT-1888 notification channel subscribed to
`software.first_seen`; see `docs/NOTIFICATIONS.md`.

**Weekly capture.** The same runner records each tenant's governance counts
once a day into `software_governance_weekly`, the source of the drift trend.

Source: `internal/softwaregov/`, `internal/handlers/portal_software_governance.go`.

### Unapproved software alert lifecycle (PAT-2097)

```text
GET  /admin/software-alerts?status=open,acknowledged&tenant_id=<uuid>&limit=100&offset=0
POST /admin/tenants/{tenantID}/software-alerts/{id}/acknowledge   {"note": "optional"}
```

The operator queue lists tracked alerts across every active tenant, oldest
first by `open_since` (raised, or last re-opened). Default statuses are open
and acknowledged; `status` takes any comma-separated subset of `open`,
`acknowledged`, `resolved`. Each row is the portal alert object
(`contracts/portal-api.md`) plus `tenant_id`, `tenant_name`, `open_since` and
`age_seconds`. The acknowledgement is the portal one with actor kind
`operator` (`acknowledged_by: "operator"`); the id must belong to the tenant
in the path, and the tenant must be active, or it is 404.

Lifecycle, all on `software_unapproved_alerted_devices` (0184) with every
change appended to `software_unapproved_alert_transitions`:

- **Policy resolves** (`approved`, `ignored`, `policy_removed`) in the same
  transaction as the policy write: `PUT /v1/portal/software-approvals`,
  `PUT /admin/tenants/{tenantID}/app-policies`,
  `DELETE /admin/tenants/{tenantID}/app-policies/{entryID}`,
  `PUT` and `DELETE /admin/tenants/{tenantID}/extension-policies/{entryID}`,
  via `softwaregov.ResolvePolicyAlertsTx`. Ingest re-applies the rule as a
  safety net for any other writer.
- **Absence resolves** (`not_observed`) only in the extractor's post-commit
  hook (`internal/extractor/unapproved_alerts.go` calling
  `softwaregov.ReconcileDevice`), for a report with authoritative evidence
  time, and for an application only when `collection_status.apps` was
  `complete` on schema v3 and the prune ran (PAT-2063). The no-signal safety
  valve is never authority for this. Per-user installs stay present while any
  user scope asserts them (PAT-2075). Extensions use the PAT-2055
  `extpresence` rule; a device that never sent the status block never
  resolves an extension alert.
- **Superseded**: the same hook resolves `superseded` (detail evidence
  `governed_by_other_policy`, with the winning policy kind, id and state)
  when the alert's product is still on the device, matched by identifier or
  display name across the whole device, but another policy row or none now
  governs it. Opening a new episode (`OpenEpisodeTx`) resolves the earlier
  episodes' active alerts `superseded` (evidence `superseded_episode`) in
  the same transaction, so a (policy, device) has at most one active alert.
- **Re-open**: only an alert resolved `not_observed`, or `superseded` with
  evidence `governed_by_other_policy` (never `superseded_episode`), of the policy's latest
  episode, when the policy is still Unapproved and the product is observed
  on the device again under that policy. The policy value and the latest
  episode are read in one statement, and every writer of either holds the
  tenant alert lock (`OpenEpisodeTx` included), taken after the policy lock
  and policy row locks. No email or webhook; it sets
  `reopen_digest_pending`, and the next daily digest lists it once.

Source: `internal/softwaregov/lifecycle.go`, `internal/softwaregov/alert_views.go`, `internal/handlers/software_alerts.go`.

---

### Shadow IT evidence and exceptions (PAT-1354)

Internal listener only, behind `ADMIN_API_TOKEN`. Shadow IT catalogue matches
are detection evidence, not proof that an application is outside the tenant's
approved software policy and not proof of an endpoint action. The separate
`GET /admin/tenants/{tenantID}/app-policy-drift` route remains authoritative
for `unapproved_present` policy drift.

| Route | Behaviour |
|---|---|
| `GET /admin/tenants/{tenantID}/shadow-it/findings` | Returns every current installed-software match against `shadow_it_catalogue`, including allowed matches, with hostname, immutable device ID, application identifier, first/last observation and policy metadata. `exceptions` separately lists every allowed tenant exception, including exceptions whose application is no longer in current inventory, so they remain reviewable and reversible. Empty arrays are never `null`. |
| `PUT /admin/tenants/{tenantID}/shadow-it/{label}` | Records or reverses one catalogue exception. Body: `{policy:"allow"\|"flag", reason?, actor?}`. `reason` is required for `allow`. The authoritative actor is always the server-established `admin_shared_token`; caller identity is stored separately as `claimed_actor`, with source address. The current row and append-only `tenant_shadow_it_policy_changes` audit row are written in one transaction. This route changes reporting policy only. It does not block, remove or push software to an endpoint. |

---

## Gotchas

- **`raw_payload_id` ≠ extracted.** A `200` from `POST /v1/inventory` means the payload is stored in `raw_payloads`. The extractor worker processes rows asynchronously. If the extractor is lagging (check `extraction_attempts` and `extraction_error` on the row), the device and compliance data won't appear in reports yet.
- **Internal routes have no timeout safety valve at MVP.** Report generation on a tenant with many devices could take longer than the 60-second `middleware.Timeout` budget. If reports time out, the PDF render is the bottleneck — check the report package's DB queries first.
- **Bearer token is unrecoverable.** Only the SHA-256 hash is stored. If a bearer token is lost, create a new tenant or write a SQL migration to replace the hash with a new token's hash.
- **No nonce/replay protection yet.** `X-Patched-Timestamp` and `X-Patched-Nonce` headers are accepted by the collector (see `next-session-plan.md`) but not validated by the service at MVP. A captured valid request could be replayed within the token's lifetime. This is deferred to v1.1.
