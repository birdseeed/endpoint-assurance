# Agent Enrollment Contract

**Status:** Frozen — this document is the interface boundary between `github.com/Patched-LTD/updater`
(agent-side implementation) and `github.com/Patched-LTD/patched.im` (platform-side implementation).
Changes to any interface defined here require coordinated updates in both repos.

**Related tickets:** PAT-543 (epic), PAT-544 (macOS agent), PAT-545 (Windows agent),
PAT-546 (bundle stamp-point), PAT-548 (platform `/v1/enrol`), PAT-549 (revocation + UI),
PAT-550 (Deploy agent tab)

---

## Overview

Agents are distributed as generic, unsigned-during-pilot / notarized-at-GA artifacts (one tarball
per platform). Tenant-specificity is injected at enrolment time via a **single-use, short-TTL
enrollment token** — not by embedding long-lived credentials in the download.

Two delivery paths are supported for every tenant; both converge on the same on-device token
location and the same `/v1/enrol` exchange:

| Path | Mechanism | Gatekeeper/SmartScreen |
|---|---|---|
| **MDM (preferred)** | Config Profile / Platform Script writes token file; Windows MSI property | Bypassed (MDM runs as root/SYSTEM) |
| **Email-link (fallback)** | Signed ~48 h download link serves a stamped bundle | Required — notarized `.pkg` + Authenticode MSI are the go-live gate |

Two independent clocks protect the email-link path:
- **Download link TTL** — ~48 h, regenerable on demand (a re-generate invalidates the previous token immediately)
- **Enrollment token TTL** — ≤ 24 h, single-use (burns on first successful `/v1/enrol`; any second use → 410)

---

## 1. Enrollment endpoint

### `POST /v1/enrol`

Called by the agent on first run when an enrollment token is present but no bearer credentials
exist. The token itself is the only credential for this call — no prior bearer token required.

#### Request

```json
{
  "enrollment_token": "<opaque single-use token>",
  "device_id": "<hardware UUID>"
}
```

`device_id` is the platform hardware UUID:
- macOS: `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`
- Windows: `(Get-WmiObject -Class Win32_ComputerSystemProduct).UUID`

#### Responses

| Status | Meaning | Agent behaviour |
|---|---|---|
| 200 OK | Enrolled successfully | Write credentials, delete token |
| 410 Gone | Token consumed or expired | Enter suspended state, do not retry |
| 401 | Token invalid / malformed | Log error, do not retry |
| 429 | Rate limited | Backoff and retry |
| 5xx | Transient server error | Retain token, retry on next poll cycle |

#### 200 Response body

```json
{
  "tenant_id": "<uuid>",
  "device_id": "<confirmed hardware UUID>",
  "bearer_token": "<per-device opaque token>",
  "hmac_secret": "<per-device secret>"
}
```

`bearer_token` and `hmac_secret` are **unique to this `{tenant_id, device_id}` pair** — not shared
across devices. The agent writes them to the existing credential store and deletes the enrollment
token atomically before proceeding.

#### Security requirements

- **Single-use:** token is consumed on the first 200 response. Subsequent calls with the same
  token must return 410, even within the TTL window.
- **TTL:** ≤ 24 h from issuance. Expired tokens return 410.
- **Rate limiting:** limit by source IP to mitigate brute-force against opaque token space.
- **Replay protection:** include a nonce or bind the token to the requesting tenant so a token
  cannot be replayed against a different tenant's enrolment endpoint.
- **No prior auth:** the enrollment token is the sole credential; do not require a bearer token
  on this call.

---

## 2. Enrollment token issuance (admin-facing)

### `POST /v1/admin/tenants/{tenant_id}/enrollment-tokens`

Admin-session authenticated. Called by the dashboard when generating MDM artifacts or an
email-link download.

#### Response

```json
{
  "enrollment_token": "<opaque>",
  "tenant_id": "<uuid>",
  "expires_at": "<ISO-8601 timestamp>",
  "token_id": "<uuid>"
}
```

- Token is bound to `tenant_id` at issuance
- TTL ≤ 24 h
- Invalidation: generating a new token via Regenerate in the dashboard calls this endpoint again
  and immediately invalidates any prior unconsumed token for this tenant

---

## 3. Device registry

The platform maintains one row per enrolled device.

### Schema

```sql
CREATE TABLE enrolled_devices (
  device_id    TEXT        PRIMARY KEY,
  tenant_id    UUID        NOT NULL REFERENCES tenants(id),
  bearer_token TEXT        NOT NULL,  -- bcrypt/Argon2 hash of the issued token
  hmac_secret  TEXT        NOT NULL,  -- AES-256-GCM encrypted at rest
  enrolled_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen    TIMESTAMPTZ,
  revoked      BOOLEAN     NOT NULL DEFAULT false,
  revoked_at   TIMESTAMPTZ
);
```

### Auth middleware update

All agent API calls (`/v1/agent-config`, `/v1/posture`, `/v1/allowlist`, `/v1/provenance`, etc.)
must:
1. Look up the incoming `Authorization: Bearer` token against `enrolled_devices` (hashed match)
2. Update `last_seen = now()` on each authenticated call
3. Check `revoked` — if true, return `401` immediately (agent enters suspended state)
4. Attribute the call to `{tenant_id, device_id}` for audit logging and per-device telemetry

---

## 4. Revocation endpoint

### `POST /v1/devices/{device_id}/revoke`

Admin-session authenticated. Scoped to the authenticated admin's tenant — cannot revoke devices
belonging to a different tenant.

#### Response

```json
{
  "device_id": "<confirmed>",
  "revoked_at": "<ISO-8601 timestamp>"
}
```

#### Behaviour

- Sets `enrolled_devices.revoked = true` and `revoked_at = now()` immediately
- **Pull-based:** no push to the device. The agent discovers revocation on its next API call
  when auth middleware returns `401`. The agent sees only that generic `401`, not the reason (see
  Suspended state below). Agent enters suspended state (stops collecting/uploading;
  LaunchDaemon/Service continues running so re-enrolment is possible).
- Audit log entry: `{admin_id, tenant_id, device_id, action: "revoke", timestamp}`

---

## 5. Agent on-device behaviour

### Token storage locations

| Platform | Location | Permissions |
|---|---|---|
| macOS | `/etc/patched/enrollment-token` | `0600`, owned `root:wheel` |
| Windows | Windows Credential Manager: `Patched/EnrollmentToken` | SYSTEM |

### First-run enrolment logic (channel-agnostic)

Both delivery paths (MDM and email-link) land the token at the same location. The agent's
enrolment step is identical regardless of how the token arrived:

```
if enrollment-token present AND bearer-token absent:
    POST /v1/enrol {enrollment_token, device_id}
    on 200:  write {tenant_id, bearer_token, hmac_secret} atomically → delete enrollment-token
    on 410:  log PATCHED_ENROLLMENT_EXPIRED → enter suspended state → do not retry
    on 5xx:  retain token → retry on next poll cycle
    on 401:  log PATCHED_ENROLLMENT_INVALID → enter suspended state → do not retry
if bearer-token present:
    skip (idempotent — never overwrite good credentials)
```

Atomic write pattern (macOS): write to a `.tmp` sibling, `fsync`, `mv` into place — same
pattern as `endpoint/verify-agent-config.py`.

### Suspended state

Triggered by: `410` or `401` during enrolment, or `401` from `/v1/agent-config`.

```
write /etc/patched/suspended  (macOS)  |  persist Suspended flag (Windows)
log PATCHED_AUTH_REJECTED (agent-config 401) / PATCHED_ENROLLMENT_EXPIRED / PATCHED_ENROLLMENT_INVALID (macOS enrol) / PATCHED_ENROL_REJECTED (Windows enrol)
exit without collecting or uploading
```

A `401` does not mean the device was revoked. The server returns the same generic `401` for every
authentication failure so the response never discloses the reason: credential expired or unknown,
tenant or device revoked, clock skew outside the replay window, nonce replay, or a bearer token and
HMAC secret that do not match (including a secret that no longer decrypts server-side). Neither agent
can tell these apart, so neither logs a revocation. Both log `PATCHED_AUTH_REJECTED` with that list
of causes and suspend (PAT-1745). The suspended marker clears on the next signature-verified `200`
from `/v1/agent-config`.

The LaunchDaemon / Windows Service continues running. Re-enrolment clears the suspended marker
(admin must generate a new enrollment token and deliver it via either path).

---

## 6. Bundle stamp-point contract (Path 2 — email-link)

Generic release bundles ship a placeholder `enrollment.json` so the dashboard can inject a token
at download time without triggering a rebuild.

### Format shipped in the bundle

```json
{"enrollment_token": null}
```

### Stamping procedure (platform / download service)

1. Fetch the latest generic bundle from GitHub Releases
2. Replace `enrollment.json` content: `{"enrollment_token": "<single-use token>"}`
3. Re-archive (tarball for macOS; MSI property injection or transform for Windows)
4. Mint a signed, time-limited (~48 h) download URL for the stamped artifact
5. **Do not** re-compute `manifest.sha256` for the rest of the bundle — `enrollment.json` is
   excluded from the hash manifest so stamping does not invalidate bundle integrity

### Installer auto-detection (macOS)

`endpoint/install.sh` and `macos/install.sh` auto-detect `enrollment.json` in the same directory
as the installer and read `enrollment_token` from it. Explicitly passing `--enrollment-token`
on the command line takes precedence (used for MDM Platform Script delivery).

**PAT-1126: `macos/install.sh` always runs `endpoint/install.sh` too.** The macOS release
tarball ships both installers together (`install.sh` plus a sibling `endpoint-install.sh` +
`patched-updater/`, produced by `tools/build-bundle.sh`); `install.sh` resolves the enrollment
token (or direct credentials) once and passes it straight through to `endpoint-install.sh`, so
there is one enrolment per device, not two. Collector-only is no longer a real installer output —
`install.sh` refuses to proceed (and installs nothing) if `endpoint-install.sh` is missing from
the tarball. See `macos/README.md` for the reasoning (a collector-only box has no decommission
mechanism) and the degraded-`agent_health` safety net for stale pre-PAT-1126 installs.

---

## 7. Admin dashboard surfaces

### Deploy agent tab (per tenant)

Two delivery paths presented to the admin; MDM surfaced first as the preferred option.

**Path 1 — MDM:**
- Generate an enrollment token via `POST /v1/admin/tenants/{id}/enrollment-tokens`
- Emit:
  - macOS: a `.mobileconfig` Configuration Profile (or Intune Platform Script) that writes the
    token to `/etc/patched/enrollment-token` (mode 0600)
  - Windows: copyable MSI install command: `msiexec /qn /i PatchedAgent.msi ENROLLMENT_TOKEN=<token>`

**Path 2 — Email-link:**
- Generate an enrollment token
- Stamp it into the latest generic bundle (see §6)
- Mint signed ~48 h download links for macOS tarball/pkg + Windows MSI
- Display links with a **Regenerate** button (issues a new token; previous token immediately
  invalidated)
- **Email to customer** button: pre-fills email with both links and brief install instructions
- Display a warning banner if the build is unsigned (pilot) with right-click → Open instructions

**Audit log:** every token generation and link mint: `{admin_id, tenant_id, path, generated_at, expires_at}`

### Enrolled devices view (per tenant)

Accessible from the tenant detail page.

| Column | Notes |
|---|---|
| Device ID | Hardware UUID |
| Enrolled | `enrolled_at` timestamp |
| Last seen | `last_seen` timestamp (updated on every authenticated API call) |
| Status | Active / Revoked |
| Action | **Revoke** button (confirmation modal → `POST /v1/devices/{id}/revoke` → row updates inline) |

- Revoked devices remain visible (do not hide); show `revoked_at`
- "Last seen: X days ago" is the natural signal that a device may be lost/offline before formal revocation

---

## 8. Roadmap

The following surfaces reuse this enrollment primitive without changes to the agent or `/v1/enrol`:

- **Client self-serve download tab** — same stamping + link mechanism, different dashboard surface
  and authz (client-session, not admin-session)
- **Patched-built lightweight MDM** — delivers the enrollment token via MDM channel; from the
  agent's perspective identical to Path 1 today
