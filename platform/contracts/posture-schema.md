# Posture schema — GET /v1/posture

Server-owned wire format for the device posture read endpoint. The macOS and
Windows endpoint agents consume this contract; the platform authors it.

Companion to [`agent-config-schema.md`](./agent-config-schema.md). Posture reuses
that endpoint's signing scheme verbatim — same Ed25519 key, same
`{signed_payload, key_id, signature}` envelope, same verify-over-transmitted-bytes
rule. There is deliberately no second signing scheme (PAT-910).

## Purpose

A device polls this route to read its own posture: device identity, tier,
compliance scoring, evidence, CVE findings, available updates, and per-app policy
(including `user_removable`). The server signs the response with the same Ed25519
key it uses for agent-config so the endpoint can detect tampering in transit and
reject a forged or stale posture **before** any root-privileged decision reads it.

The endpoint's `patched-uninstall.sh` gates root-privileged app removal on
`app_policy.apps[].user_removable`. Before PAT-910 that field arrived over TLS
only, unsigned — a MITM, a compromised edge, or a substituted cache could flip a
mandatory app to removable and drive the daemon to delete a security control.
Signing closes that: the endpoint verifies the signature, the tenant binding, and
anti-rollback fail-closed, and refuses to read `user_removable` from any posture
it did not verify.

## Request

Same device-scoped auth as `GET /v1/agent-config`, except posture **requires** a
per-device credential (a `tenant_credentials` row with `device_id IS NOT NULL`):

- `Authorization: Bearer <token>` — device credential; a tenant-wide or staff
  credential is rejected at the bearer lookup step with a uniform 401.
- `X-Patched-Signature: <hex>` — HMAC-SHA256 over the (empty) GET body.
- `X-Patched-Timestamp` / `X-Patched-Nonce` — replay protection.

The device is resolved from the credential, never from a request parameter — a
device can only read its own posture.

## Response — 200 OK

The response is the same **envelope** as agent-config. The server signs the
canonical posture bytes and returns *those exact bytes*, base64-encoded, as
`signed_payload` — the endpoint does **not** reconstruct anything:

```jsonc
{
  "signed_payload": "eyJzY2hlbWFfdmVyc2lvbiI6...",  // base64-std of the canonical posture JSON below — the exact bytes that were Ed25519-signed
  "key_id":         "65b60673d6ed884b",             // first 8 bytes of SHA-256(pubkey) as hex — same key as agent-config
  "signature":      "base64-std-encoded Ed25519 signature over the raw signed_payload bytes"
}
```

Base64-decoding `signed_payload` yields the **canonical posture JSON**. Field
ordering is Go struct declaration order (not alphabetical); the endpoint verifies
the bytes as received and never needs to reproduce the ordering. The two fields
that carry the security guarantees are `tenant_id` and `issued_at`:

```jsonc
{
  "schema_version": 1,
  "tenant_id":      "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", // PAT-910 — tenant binding; stamped from the authenticated credential, not the request
  "issued_at":      "2026-07-16T12:00:00Z",                 // PAT-910 — RFC3339 UTC server sign time; the monotonic anti-rollback value
  "generated_at":   "2026-07-16T12:00:00Z",                 // when the posture data was assembled (display)
  "device":     { "id": "...", "serial": "...", "os": "macOS", "os_version": "...", "...": "..." },
  "tier":       "report_deploy",
  "app_count":  12,
  "compliance": { "platform": "macOS", "benchmarks": [] },
  "evidence":   { "coverage_window_days": 30, "scans_logged": 5, "last_signed_report_digest": null, "recent_scan_times": [] },
  "findings":   [],   // CVE findings for installed apps
  "updates":    [],   // available app updates from the catalog
  "app_policy": {
    "apps":  [        // resolved per-app policy; user_removable gates root-privileged removal
      { "app_name": "Zoom", "identifier": "us.zoom.xos", "label": "zoom", "policy": "mandatory", "user_removable": false, "enforcement_tier": "report_deploy" }
    ],
    "drift": []       // advisory policy-violation findings
  }
}
```

`tenant_id` is set from the authenticated device credential inside the handler,
never from the fetch data or any request parameter, so the signed binding always
reflects the credential that was presented. `issued_at` is stamped at sign time on
every response; because each fetch is signed fresh, `issued_at` is non-decreasing
across legitimate fetches and serves as the anti-rollback value.

## Signature verification (endpoint implementation guide)

Identical to agent-config — the endpoint verifies over the **transmitted
`signed_payload` bytes as received** and does not rebuild anything:

1. Parse the envelope; extract `signed_payload`, `signature`, `key_id`.
2. Base64-std-decode `signed_payload` to the raw canonical bytes.
3. Verify `ed25519.Verify(pinnedPubKey, decodedBytes, base64.StdDecode(signature))`.
   Do **not** re-marshal.
4. Only after the signature verifies, JSON-parse the decoded bytes. Ignore unknown
   keys — the server may add posture fields without breaking deployed endpoints.
5. **Reject** the posture (fail closed — keep last-known-good, never fall back to
   unsigned or stale posture) if:
   - the signature does not verify
   - `key_id` does not match the pinned key ID
   - `tenant_id` does not match the locally-configured tenant ID
   - `issued_at` is older than the last accepted `issued_at` (anti-rollback)
   - `issued_at` is missing or not a valid RFC3339 UTC timestamp
   - `PATCHED_TENANT_ID` is empty (tenant binding cannot be verified — a hard
     failure, not a skip)

**Reference implementation (Patched-LTD/updater):** `endpoint/verify-posture.py`,
mirroring `endpoint/verify-agent-config.py`. It verifies the Ed25519 signature over
the raw signed bytes with no client reconstruction, checks the tenant binding and
anti-rollback, and writes only the verified inner posture to its output file. The
verifier derives its effective anti-rollback floor as max(version-file value,
issued_at of the currently cached posture), so no posture older than the cache can
ever be accepted regardless of crash timing. The caller (`patched-fetch-posture.sh`)
writes and fsyncs the version file *first* and then atomically commits the cache, so
the sidecar floor is >= the cached issued_at at every instant; a crash between the
two writes fail-safes under the verifier's accept-equal semantics (PR #319 round 3).

## Key management

Posture is signed with the **same** key as agent-config — one key, one rotation.

| Item | Detail |
|---|---|
| Algorithm | Ed25519 (RFC 8032) |
| Private key store | `AGENT_CONFIG_SIGNING_KEY` env var in `/etc/patched-api/env`; base64-std-encoded 32-byte seed (shared with agent-config) |
| Public key distribution | Printed at startup as `pubkey_b64=<base64>`; the endpoint pins this value in both `verify-agent-config.py` and `verify-posture.py` |
| Key ID | First 8 bytes of `SHA-256(pubkey)` as lowercase hex — matches `key_id` in the response |
| Rotation | Update `AGENT_CONFIG_SIGNING_KEY`, restart service; ship a new endpoint agent with the updated pinned key. One rotation covers both agent-config and posture |

## Anti-rollback

The endpoint persists the last accepted `issued_at` in a version file and rejects
any posture whose `issued_at` is older. An equal `issued_at` (a same-second
refetch) is accepted as idempotent, matching agent-config's same-version handling.
Because `issued_at` is inside the signed bytes, an attacker cannot forge a newer
timestamp, and a replayed older posture is rejected.

## Deploy ordering (PAT-910)

The server must be deployed (serving the signed envelope) **before** any endpoint
agent that ships `verify-posture.py` reaches a customer estate. An endpoint that
verifies against an old server serving the bare (unsigned) posture object will find
no `signed_payload` and reject fail-closed — which is safe, never fail-open. This
is currently dormant because `posture-poll` is not bootstrapped (deliberately
excluded in PAT-860 / PR #317); wiring `posture-poll` is the follow-up once both
the server and endpoint changes have merged and the server is live.

## Security review gate

This endpoint feeds a root-privileged decision on the customer endpoint
(`user_removable` gates app removal), so it is part of the agent status/auth
contract and must be reviewed by a non-author before the first customer ship
(GitHub-Non-Author-Review). Ed25519 signature verification, tenant binding, and fail-closed
anti-rollback are the primary mitigations; the endpoint must enforce all three.
