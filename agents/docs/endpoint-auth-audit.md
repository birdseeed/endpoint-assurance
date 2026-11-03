# Endpoint Authentication Audit — PAT-513

Audits how the Patched agent authenticates to the platform and documents gaps against
the minimum required controls. Also describes the forward-compatible device-identity
header added by this ticket.

---

## 1. Current authentication model

### Credentials provisioned at enrolment

Both platforms read three credentials at startup from a protected store:

| Credential | macOS path | Windows store |
|---|---|---|
| `tenant-id` | `/etc/patched/creds/tenant-id` | `PatchedAgent/TenantId` in Credential Manager |
| `bearer-token` | `/etc/patched/creds/bearer-token` | `PatchedAgent/BearerToken` in Credential Manager |
| `hmac-secret` | `/etc/patched/creds/hmac-secret` | `PatchedAgent/HmacSecret` in Credential Manager |

Credential files on macOS are owned root:wheel, mode 0600. Windows Credential Manager
blobs are DPAPI-encrypted at rest (CRED_PERSIST_LOCAL_MACHINE).

### Per-request auth scheme (every platform API call)

```
Authorization: Bearer <bearer-token>
X-Patched-Signature: <hmac-sha256-hex>   # HMAC(hmac-secret, request-body)
X-Patched-Timestamp: <unix-seconds>       # replay protection
X-Patched-Nonce: <uuid4-hex>              # idempotency
```

GET requests (agent-config, posture) HMAC over an empty body. POST requests (inventory,
provenance, audit events) HMAC over the raw JSON body bytes.

### Tenant binding

The client verifies `tenant_id` in the signed `agent-config` payload against the local
`tenant-id` credential. Any mismatch causes the config to be rejected. The platform is
expected to enforce the inverse — serving only the config for the tenant whose token was
presented — but no agent-side evidence of this enforcement exists in this codebase.

### Scope of coverage (as audited)

| Endpoint | macOS script | Windows class |
|---|---|---|
| GET /v1/agent-config | `patched-fetch-config.sh` | `AgentConfigFetcher.cs` |
| GET /v1/posture | `patched-fetch-posture.sh`, `patched-upload.sh` | `PostureFetcher.cs` |
| POST /v1/inventory | `patched-upload.sh` | `InventoryPoster.cs` |
| POST /v1/provenance | `patched-update.sh` | `ProvenancePoster.cs` |
| POST /v1/events (PAT-499) | `patched-update.sh` | `AuditEventShipper.cs` |

---

## 2. Gap analysis

### Gap 1 — bearer-token is per-tenant, not per-device

**Current state:** The `bearer-token` is provisioned once per tenant (via MDM profile /
installer) and is the same for every device enrolled in that tenant. Any device that
knows a tenant's bearer token can poll `GET /v1/agent-config?tenant_id=<id>` and retrieve
that tenant's configuration.

**Risk:** A bearer token extracted from one device grants access to the full tenant
config. Tenant isolation holds only while no device is compromised.

**Minimum required control:** One unique token per enrolled device. The platform issues
a device-scoped token at enrolment time; the server validates `device_token → tenant`
binding before returning config.

### Gap 2 — no hardware binding

**Current state:** The `bearer-token` is a plain opaque string. There is no mechanism
to bind it to the enrolling device's hardware identifier (serial number, TPM, Secure
Enclave). A token extracted from a credential file can be replayed from any machine.

**Minimum required control:** Credential binding to the device hardware identifier
(macOS: `IOPlatformUUID` via `ioreg`; Windows: `Win32_ComputerSystemProduct.UUID`) as
a secondary check. Ultimate goal: client certificate or key sealed to the TPM / Secure
Enclave that cannot be extracted.

### Gap 3 — no server-side device→tenant enforcement (agent cannot verify)

**Current state:** The agent verifies that the config it receives is for its own tenant
(by comparing `tenant_id` in the signed payload to the local credential). The agent has
no visibility into whether the platform also enforces that the requesting device belongs
to the tenant before serving the config.

**Minimum required control (platform):** Server rejects `GET /v1/agent-config` when the
bearer token's tenant does not match the requested config. Server additionally rejects
when a per-device token is presented by a device that is not enrolled in that tenant.

### Gap 4 — no token rotation

**Current state:** Tokens are written by the installer and never rotated. If a tenant
changes their HMAC secret or bearer token, every device must be re-enrolled manually.

**Minimum required control:** A token rotation protocol — the agent requests a fresh
token by presenting the current token and a device challenge; the server issues a
replacement. Rotation should be possible without re-MDM-enrolment.

### Gap 5 — no device revocation

**Current state:** Decommissioning a device does not invalidate its credentials. If a
device is sold, lost, or stolen, its bearer token remains valid until the tenant
administrator manually rotates the entire tenant secret (impacting all devices).

**Minimum required control:** Server-side per-device revocation. When a device is marked
decommissioned in the platform, the server stops serving config to its token and returns
403. The agent interprets 403 as a terminal state and stops running.

---

## 3. Interim control — X-Patched-Device-Id header (this ticket)

While per-device token issuance is designed and implemented in the platform, this ticket
adds a forward-compatible `X-Patched-Device-Id` header to every platform API call:

```
X-Patched-Device-Id: <hardware-uuid>
```

The hardware UUID is the same identifier included in the inventory payload body:
- **macOS:** `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice`
- **Windows:** `Win32_ComputerSystemProduct.UUID` via WMI

**Current effect:** The server ignores this header (no enforcement yet). It is present
so that once server-side per-device binding is implemented, no agent release is required
to start sending the identifier — the header is already in every request.

**Windows:** Added via `DeviceIdentityHandler` (`DelegatingHandler` on the "patched"
named HttpClient) — applies automatically to every outgoing platform request.

**macOS:** Added to the `curl` calls in `patched-fetch-config.sh`,
`patched-fetch-posture.sh`, `patched-update.sh` (provenance), and
`macos/patched-upload.sh` (inventory + posture). Uses `${HW_UUID:+-H "..."}` so the
header is omitted if `ioreg` fails (fail-open).

---

## 4. Recommended implementation path

### Phase 1 — per-device token (server side, ~2 weeks)

1. Platform issues a unique `device_token` at MDM enrolment (or first successful
   inventory POST). Stored in the same credential location as the current bearer token.
2. Server validates `device_token → tenant_id` binding on every API call.
3. Token is opaque — the agent treats it as a bearer string; no protocol change needed.
4. Existing shared bearer tokens can be migrated: on first inventory POST with a shared
   token, the server issues a device-scoped replacement and returns it in a
   `X-Patched-Device-Token` response header.

### Phase 2 — hardware binding (agent + platform, ~1 week each)

1. At token issuance, the server records `(device_token, hw_uuid)` pair.
2. The server validates `X-Patched-Device-Id` against the registered `hw_uuid` for that
   token on every request. Mismatch → 403.
3. Prevents extracted token replay from a different device.

### Phase 3 — revocation (platform, ~1 week)

1. Admin marks device decommissioned in the platform. Server adds token to revocation
   list.
2. On next agent check-in with revoked token: server returns 403.
3. Agent logs `PATCHED_POSTURE_WARNING reason=device_revoked` and stops running.
4. MDM profiles should separately unenrol the device (agent revocation is a belt, not
   the only safety net).

### Phase 4 — token rotation (agent + platform, ~2 weeks)

1. Token carries a `not_after` timestamp in the server-side registry (not exposed to
   the agent).
2. Server returns `X-Patched-Token-Expires-At` response header on config fetches.
3. Agent detects upcoming expiry and triggers a rotation request (`POST /v1/device/rotate`)
   presenting the current token + HW UUID challenge.
4. Server issues replacement; agent writes it to the credential store (macOS: direct file
   replace under root; Windows: `CredWrite` to Credential Manager).

---

## 5. Platform repo tasks (out of scope for this PR)

These require changes to `Patched-LTD/patched.im`:

- [ ] `GET /v1/agent-config` — validate `Bearer` token against tenant; return 403 if mismatch
- [ ] Enrolment flow — issue per-device token on first inventory receipt
- [ ] `X-Patched-Device-Id` header enforcement (Phase 2)
- [ ] Revocation endpoint + agent decommission flow (Phase 3)
- [ ] Token expiry + rotation endpoint (Phase 4)
