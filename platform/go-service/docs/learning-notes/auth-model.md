# Auth model

**Subsystem:** authentication and request integrity
**Code:** `internal/auth/`, `internal/handlers/`

---

## Overview

Every request to the public API (`/v1/inventory`, `/v1/provenance`, `/v1/agent-config`, `/v1/posture`) is authenticated before any JSON parse or DB write. There are two auth contexts:

| Context | Token type | Used by |
|---|---|---|
| Tenant auth | Per-tenant bearer + HMAC | macOS/Windows endpoint agents for inventory, provenance |
| Device auth | Per-device bearer + HMAC | `/v1/posture` only — returns this specific device's compliance posture |
| Agent-config | Ed25519-signed response (no client auth) | `GET /v1/agent-config` — response is signed, not the request |

---

## Tenant auth (bearer + HMAC)

The two-layer auth model for tenant-level endpoints:

### Layer 1 — bearer token

```
Authorization: Bearer <token>
```

The service stores `sha256(token)` as a `bytea` in `tenant_credentials` — the plaintext is only ever shown once (on `POST /admin/tenants`) and cannot be recovered. The lookup is:

```sql
SELECT tc.id, tc.tenant_id, tc.hmac_secret, tc.expires_at, t.revoked_at
FROM tenant_credentials tc
JOIN tenants t ON t.id = tc.tenant_id
WHERE tc.bearer_token_hash = sha256($1::bytea)
  AND (tc.expires_at IS NULL OR tc.expires_at > now())
  AND t.revoked_at IS NULL
```

Multiple rows per tenant are valid (enables zero-downtime rotation — old credential continues to work until `expires_at`).

### Layer 2 — HMAC-SHA256

```
X-Patched-Signature: <hex-encoded HMAC>
```

`HMAC-SHA256(per-tenant-key, request-body)` computed over the raw body bytes. The `hmac_secret` is stored as a `bytea` in `tenant_credentials`. The verification:

```go
mac := hmac.New(sha256.New, hmacSecret)
mac.Write(body)
expected := mac.Sum(nil)
if !hmac.Equal(expected, sigBytes) { return 401 }
```

The HMAC binds the request body to the credential. A bearer token alone is not enough — an attacker who intercepts a valid token still cannot forge valid requests without the HMAC key.

### Layer 3 — Timestamp freshness

```
X-Patched-Timestamp: <unix-seconds>
```

Must be within ±300 seconds of server time. Prevents replay attacks using old captured requests.

### Layer 4 — Nonce replay rejection

```
X-Patched-Nonce: <random-uuid>
```

The nonce is checked against the `seen_nonces` table with a TTL of 600 seconds (the skew window doubled). A nonce seen twice within the window → 401. This makes the ±300s timestamp window non-exploitable: even if you capture a request within the window and replay it, the nonce is already consumed.

```sql
-- seen_nonces schema
CREATE TABLE seen_nonces (
  nonce      text PRIMARY KEY,
  tenant_id  uuid REFERENCES tenants(id),
  seen_at    timestamptz DEFAULT now()
);
-- Pruned periodically: DELETE FROM seen_nonces WHERE seen_at < now() - interval '10 minutes'
```

---

## Device auth (/v1/posture)

Device-specific credentials are stored in `device_credentials` (migration `0029`). Same bearer + HMAC + timestamp + nonce pattern as tenant auth, but scoped to a specific device rather than a tenant. This allows `GET /v1/posture` to return exactly that device's compliance posture without exposing other devices in the same tenant.

Device credentials are issued during device onboarding and rotated via `POST /admin/tenants/{id}/devices/{deviceId}/rotate-credentials`.

---

## Agent-config signing (Ed25519)

`GET /v1/agent-config` returns a JSON body signed with an Ed25519 key (`key_id=ecd47f2c5b3d5705`). The response is not authenticated per-request (no bearer/HMAC on the request); instead the response itself is unforgeable by anyone without the private key. Endpoints verify the signature before consuming the config.

The Ed25519 key is loaded at startup from the env file (`/etc/patched-api/env`). It is NOT rotated automatically — rotation is a manual operational step (PAT-499 roadmap item to move to an HSM).

---

## Admin API (internal :8081)

The admin API on `:8081` has **no application-layer auth**. It listens only on the Tailscale interface; Tailscale membership is the auth gate. This is an explicit design choice (transport-layer trust = Tailscale WireGuard) to keep the admin surface simple.

---

## Credential lifecycle

```
POST /admin/tenants
  → generates: bearer_token (random 32 bytes, base64), hmac_secret (random 32 bytes)
  → stores: sha256(bearer_token), hmac_secret in tenant_credentials
  → returns: bearer_token (plaintext, ONCE ONLY), hmac_secret_b64
  → deploy to endpoint: /etc/patched/{bearer-token,hmac-secret}

POST /admin/tenants/{id}/rotate-credentials
  → generates new credential pair
  → sets expires_at on old credential (default 24h grace)
  → returns new plaintext credential pair (ONCE ONLY)
  → deploy new credentials to endpoints BEFORE grace expires
```

---

## Key files

| File | Role |
|---|---|
| `internal/auth/auth.go` | Bearer lookup, HMAC verify, timestamp + nonce checks |
| `internal/handlers/inventory.go` | Calls auth; entry point for tenant-auth check |
| `internal/handlers/posture.go` | Device auth flow |
| `internal/handlers/agent_config.go` | Ed25519 signing of the response |
| `migrations/0017_tenant_credentials.sql` | `tenant_credentials` schema (multi-credential, bearer hash) |
| `migrations/0029_device_credentials.sql` | `device_credentials` schema |
