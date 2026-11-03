# Agent config schema — GET /v1/agent-config

**Status:** Implemented (PAT-281, PAT-286, PAT-601, PAT-296, PAT-1108, PAT-1136)  
**Route:** `GET /v1/agent-config` — public listener (`api.patched.im`)  
**Auth:** Bearer + HMAC-SHA256. The platform verifies the v3 signing form (method + stable endpoint identifier + timestamp + nonce + body bound into the signature, see [Request signing (v3)](#request-signing-v3)). During the transition it also accepts targetless v2, then legacy body-only signatures.
**Platform:** macOS and Windows (same route and schema — PAT-276)  

---

## Purpose

PAT-2004 adds response-only `device_channel_overrides` to the canonical signed
payload for tenant-wide credentials, mapping owned device UUIDs to `beta`.
Clearing an override restores tenant policy. It is omitted when empty and ordered before `device_id`; map keys are
lexically ordered by the canonical Go JSON encoder. Existing payload bytes are
unchanged when the field is absent. Device credentials instead receive their
effective `update_channel`. Beta retains the tenant's `pinned_version` ceiling
and must not advance beyond it. Holds and approvals
project the effective stable `pinned_version`; a due staff P0 schedule forces
stable with a minimum version floor even against a hold or beta override; a
newer approved stable pin may advance beyond that floor. Channel writes and
P0 activation advance `config_version`. Agents must verify the exact signed
bytes before applying the map for their own authenticated device identity.
For device-scoped credentials the signed `update_channel_source` is `tenant`
when no device override exists and `device_override` only when the tenant-bound
device override is active. Tenant-wide credentials retain the map and omit the
scalar source. An active P0 floor forces stable but has no source in this
two-value vocabulary, so the server omits the source rather than mislabeling
it. Agents report channel, source and config_version from the exact verified
signed response in the optional `agent_health.update_channel` object. See [release control](agent-release-control.md)
for APIs, evidence gates, CI stable envelopes and operating requirements.

The agent polls this route to receive its per-tenant runtime configuration. The server signs the response with an Ed25519 key so the agent can detect tampering in transit. The agent pins the server's public key and rejects any response whose signature does not verify.

PAT-1921 adds response-only `windows_installation_evidence`, exclusively derived
from the validated embedded PAT-1874 catalogue. Its first publication has an
empty target array and activates no probes. The complete schema, canonical
hash, expiry, immutable delivery ledger, mixed-version handling and rollback
runbook are in [Windows installation evidence](windows-installation-evidence.md).
Older agents ignore this additive field after verifying the exact signed bytes.

---

## Request

```
GET /v1/agent-config HTTP/1.1
Host: api.patched.im
Authorization: Bearer <tenant-bearer-token>
X-Patched-Signature: <hex(HMAC-SHA256("", hmac-secret))>
If-None-Match: "<config_version>"     (optional — omit on first fetch)
```

- **Body:** empty. The HMAC is computed over an empty byte sequence (not the response body).
- **`If-None-Match`:** send the `ETag` value from the last successful 200 response. The server returns `304 Not Modified` when the config version has not changed. Auth runs before the ETag check — there is no unauthenticated fast path.

---

## Request signing (v3)

**Status: ACTIVE server-side (PAT-1154).** The platform verifies v3 on every
agent-facing POST/GET route. The server must deploy before agents: it accepts
v3 first, then the existing PAT-1136 targetless v2 form during an explicit
transition, then the separately-gated legacy body-only form described in
[Request](#request) above. This section supersedes the "Proposed request-auth
hardening" section further down, which described a different (METHOD+PATH
based, GET-only) canonical scheme that was never implemented; that section
is kept below for history only.

**Problem this closes:** the timestamp and nonce headers were sent but not
covered by the legacy signature, so a captured signed body could be replayed
indefinitely by pairing it with a fresh timestamp+nonce — the freshness and
single-use checks ran, but against values the signature never actually
committed to.

**Canonical signing input:**

```
signing_input = b"patched-hmac-v3\n" + METHOD + b"\n" + ENDPOINT_ID + b"\n" + TS + b"\n" + NONCE + b"\n" + BODY
signature_hex = lowercase_hex( HMAC_SHA256(secret_bytes, signing_input) )
```

- `b"patched-hmac-v3\n"` — literal ASCII domain-separation prefix, including
  the trailing `\n` (0x0A). 16 bytes total.
- `METHOD` — uppercase HTTP method sent on the wire.
- `ENDPOINT_ID` — stable server-owned operation identifier, never the URL or a
  caller-provided path. `GET /v1/agent-config` uses `agent_config`; the server
  publishes the complete identifier set in `internal/auth/hmac.go`.
- `TS` — the exact ASCII bytes of the `X-Patched-Timestamp` header value,
  verbatim (the decimal Unix-seconds string). Never reparse or reformat it;
  sign the same bytes you send.
- `NONCE` — the exact ASCII bytes of the `X-Patched-Nonce` header value,
  verbatim.
- `BODY` — the raw request body bytes exactly as sent. Empty (zero bytes)
  for GET routes, same convention as the legacy scheme.
- `secret_bytes` — the same per-tenant/per-device HMAC secret already used
  today. Secret derivation is unchanged by this scheme.

Send the result as `X-Patched-Signature`, same header as before. `TS` and
`NONCE` are still sent as their own headers (`X-Patched-Timestamp`,
`X-Patched-Nonce`) exactly as today — this scheme only changes what the
signature is computed *over*, not the header set.

**Authoritative test vectors** (`secret_bytes` = ASCII `"patched-test-secret"`,
a literal 19-byte string, NOT base64-decoded; `ts` = `"1730000000"`;
`nonce` = `"abc123nonce"`):

| Method | Endpoint ID | Body | v3 signature | targetless v2 signature | v1 signature (legacy, body-only) |
|---|---|---|---|---|---|
| `POST` | `inventory` | `{"hello":"world"}` | `e4825ff7d3d56103fb9904615eebb2a317cef582256f066a443bc66974cd75d4` | `f537f9764d38d0cd9b08cb53e451d86b83f25f69b528aaeffcaacd4f4cbfb13e` | `222b3a159945641dd1b04edd3cb18e8feba8b8e619534d9dcb639294f76566cc` |
| `GET` | `agent_config` | *(empty)* | `868b6e53c5c2ba9cbf72d0af25e06157eed1fff7ca68148412c2dd0952295d3f` | `7705fc67c585db5ba3dbc35dbafa587a4d79532dafb68b33d8fcda9f6846e983` | `770a0355717c0a38c8183dc30ed47c03bced834ddd314d02c1dabbf4326f3620` |

Every v3 implementation, on either side of the wire, must reproduce the v3
column exactly. The targetless v2 and v1 columns are server compatibility
proof only. `go-service/internal/auth/hmac_test.go` pins all three forms.

For compatibility only, targetless v2 is
`b"patched-hmac-v2\n" + TS + b"\n" + NONCE + b"\n" + BODY`; it does not
contain `METHOD` or `ENDPOINT_ID` and agents must never emit it after the v3
release.

**Transition window and rollout:** deploy the server first with
`auth.AllowTargetlessV2HMAC` at its default `true`. It verifies v3 first and
then accepts PAT-1136 targetless v2, preserving already-installed agents.
Then deploy the macOS and Windows agents that sign v3. Once telemetry confirms
no targetless v2 agents remain, set `AllowTargetlessV2HMAC` to `false` and
remove that branch in a follow-up. This flag is independent of
`auth.AllowLegacyBodyOnlyHMAC`, which remains the final compatibility fallback
for pre-PAT-1136 body-only agents.

While either compatibility flag is true, those old forms remain unable to
bind method or endpoint ID. The legacy form additionally remains exposed to
the PAT-1136 replay hole because it never covered timestamp or nonce. These
are deliberate, bounded rollout compromises, not target-state behaviour.

**Sunset:** after the targetless-v2 retirement above, retire
`AllowLegacyBodyOnlyHMAC` on its own evidence-based schedule. Once both are
removed, update the `Auth:` line and this section's status to reflect that
only v3 is accepted.

---

## Proposed request-auth hardening (NOT YET ACTIVE — coordinated rollout required)

> **Superseded by [Request signing (v3)](#request-signing-v3) above, which is
> the scheme actually implemented (PAT-1154). This section is retained for
> history only and describes a different canonical form that was never
> built.**

> **Status: PROPOSED. The server still verifies the empty-body HMAC described
> above. Do not change agent behaviour until this section is marked Active and
> the platform endpoint has shipped the dual-accept window below.**

**Finding (security review):** because this is a bodyless `GET`, the request
HMAC is `HMAC-SHA256("", hmac-secret)` — a **static, per-tenant value**. The
`X-Patched-Timestamp` / `X-Patched-Nonce` headers are validated for freshness
and single-use, but they are **not part of the signed bytes**, so the signature
proves possession of the secret but does not *bind* the request to a particular
time or nonce. A signature captured from a log or proxy is a constant that can
be paired with a freshly-minted timestamp+nonce.

**Change:** sign a canonical request string instead of the empty body. The agent
computes:

```
canonical = METHOD + "\n" + PATH + "\n" + X-Patched-Timestamp + "\n" + X-Patched-Nonce
          = "GET\n/v1/agent-config\n<unix-seconds>\n<nonce>"
X-Patched-Signature = hex(HMAC-SHA256(canonical, hmac-secret))
```

- `METHOD` — uppercase HTTP method (`GET`).
- `PATH` — request path only, no query string (`/v1/agent-config`).
- `X-Patched-Timestamp` — Unix seconds; must be sent and echoed exactly into the
  canonical string. Freshness window unchanged (`REPLAY_SKEW_SECONDS`, default 300s).
- `X-Patched-Nonce` — unique per request; stored server-side in `seen_nonces`
  (PAT-338) within the skew window, so a canonical string can be used only once.

Now the signature is unique per request and bound to a single-use nonce, so a
captured header cannot be replayed with a different timestamp/nonce.

**Rollout (must be coordinated with `Patched-LTD/updater`):**
1. Platform ships a **dual-accept** window: verify the new canonical signature,
   and fall back to the legacy empty-body HMAC, for one agent-release cycle.
2. Agents (macOS `patched-*`, Windows service) switch to the canonical signature.
3. Platform drops the legacy fallback once fleet telemetry shows agents have
   migrated. This section is then marked **Active** and the `Auth:` line at the
   top of this document is updated.

The same canonical-string scheme should be applied to the other bodyless/GET
agent routes (`/v1/posture`, `/v1/allowlist/pending-removals`, `/v1/agent/artifact`)
in the same rollout. POST routes (`/v1/inventory`, `/v1/provenance`) already sign
a non-empty body that carries the timestamp/nonce, so they are lower priority but
should converge on the same canonical scheme for consistency.

---

## Response — 200 OK

The response is a small **envelope**. The server signs the canonical config bytes
and returns *those exact bytes*, base64-encoded, as `signed_payload` — the agent
does **not** reconstruct anything (see [Signature verification](#signature-verification-agent-implementation-guide)):

```jsonc
{
  "signed_payload": "eyJhcHBfY29udHJvbCI6...",  // base64-std of the canonical JSON below — the exact bytes that were Ed25519-signed
  "key_id":         "65b60673d6ed884b",         // first 8 bytes of SHA-256(pubkey) as hex
  "signature":      "base64-std-encoded Ed25519 signature over the raw signed_payload bytes"
}
```

Base64-decoding `signed_payload` yields the **canonical config JSON**. Its fields
are serialised in strict alphabetical key order with no extra whitespace (that
ordering is how the server produces deterministic bytes — the agent never needs
to reproduce it, it verifies the bytes as received):

```jsonc
{
  "app_control": {                  // PAT-601 — Application Control policy; always present, never null
    "app_allowlist":   [],          // bundle IDs (macOS) / process names (Windows); empty = allowlist disabled
    "approved_admins": [],          // usernames permitted in local admin group; empty = no admin enforcement
    "enabled":         false,       // master switch; false = no AC enforcement
    "extension_blocklist": [],      // reviewed extensions blocked by managed browser policy
    "extension_removals": []        // observation-bound destructive directives; normally empty
  },
  "app_control_authority": "report", // PAT-1481 — signed runtime-only authority for retained application-control paths; "report" | "block" | "enforce"
  "blocked_versions": {},            // PAT-1238 — per-label kill switch; KEY OMITTED when no tenant has ever set it (see §blocked_versions). {} shown here is illustrative of "no versions blocked"; on the wire the key is simply absent in that case, same as blocking_process_policy.
  "blocking_process_policy": null,  // PAT-296 — close-to-update policy; KEY OMITTED when the tenant has no policy (see §blocking_process_policy). Safe defaults apply when absent.
  "catalog_scope":    null,         // reserved — PAT-273 scope selector
  "config_version":   1,            // monotonic int; anti-rollback counter
  "decommission": {                 // PAT-1108 — tenant-wide agent-decommission directive; always present, never null
    "mode":       "none",           // "none" (default, inert) | "expiry" | "immediate"
    "expires_at": null,             // RFC3339 UTC; required (non-null) when mode="expiry"
    "purge":      false,            // also remove locally cached artefacts; default false
    "reason":     null              // operator-supplied context; its VALUE is recorded/surfaced only and NEVER a control-flow input, but changing it still bumps config_version (PAT-1138) — see §decommission below
  },
  "device_id":        "",           // PAT-1026 — requesting device's own platform device id (devices.id). Injected at GET time from the resolved credential, same as ring. Empty string for tenant-wide credentials (no single device to attribute it to). Never client-supplied.
  "issued_at":        "2026-12-10T12:00:00Z",  // RFC3339 UTC
  "legacy_app_execution_enabled": false, // PAT-1481 — always-present permanent false gate for quarantined legacy execution
  "log_request":      null,         // PAT-286 — on-demand log collection directive; null when no request pending
  "os_update_policy": null,         // reserved — PAT-273
  "per_app_patch":    null,         // reserved — PAT-167
  "pinned_version":   null,         // PAT-108: updater version pin. null = always latest; string = pin the agent to a specific version. Present in every signed payload (defaults to null).
  "proxy": {
    "auth_ref":             null,   // Keychain/secret ref for proxy creds (PAT-278)
    "bypass_when_off_corp": false,  // bypass proxy when not on corporate network
    "host":                 null,   // proxy host (required when mode="manual")
    "mode":                 "system", // "system" | "manual" | "off"
    "pac_url":              null,   // PAC URL (alternative to host/port)
    "port":                 null,   // proxy port (integer)
    "type":                 null    // "http" | "https" | "socks5"
  },
  "report_user_attribution": "off", // PAT-116 — "off" | "local_part" | "full_upn". PII guardrail: default "off". See PAT-112 DPA.
  "ring":             3,            // PAT-117 — per-device patching ring (0=internal,1=canary,2=early-adopter,3=GA). Injected at GET time. Default 3.
  "ring_promotions":  null,         // legacy PAT-117 label-only conservative projection
  "ring_promotions_scoped": {},     // PAT-1134 authoritative platform-aware projection. See §ring_promotions below.
  "scan_cadence":     null,         // reserved — future scan interval override
  "tenant_id":        "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
  "tier":             "report_deploy", // "report_deploy" | "patch"
  "update_channel":   "stable"        // PAT-108: updater release channel. "stable" | "beta". Present in every signed payload (defaults to "stable").
}
```

> **`blocking_process_policy` is `omitempty`.** When a tenant has no policy the key
> is **omitted entirely** from the canonical bytes (not emitted as `null`), so a
> policy-less tenant's canonical bytes and signature are **byte-identical** to how
> they signed before this field existed — existing signatures never change. The
> `null` shown above is illustrative of "no policy"; on the wire the key is simply
> absent in that case.

> **Forward compatibility.** Because agents verify the transmitted bytes as-is and
> then ignore JSON keys they do not recognise, the server can add new canonical
> fields without breaking deployed agents: an older agent verifies the signature
> successfully and skips the unknown field; an updated agent reads it. New fields
> therefore roll out safely and take effect only once agents are built to consume
> them — no coordinated flag-day signature break is required.

**ETag:** `"v<config_version>-r<ring>"` (e.g. `"v5-r3"`). Encodes both the tenant config version and the device's effective ring so a ring change delivers a fresh config even when the tenant config has not changed. Send back in `If-None-Match` on subsequent polls.

---

## Response — 304 Not Modified

Returned when `If-None-Match` matches the current `config_version`. Body is empty; `ETag` header is present. The agent should continue using its cached config.

---

## Signature verification (agent implementation guide)

The agent verifies the signature over the **transmitted `signed_payload` bytes as
received** — it does **not** rebuild or re-serialise a canonical struct. This is
the single most important property of the scheme: verification is independent of
which fields the payload happens to contain, so it is robust to the server adding
new canonical fields.

1. Parse the response envelope and extract `signed_payload`, `signature`, `key_id`.
2. Base64-std-**decode** `signed_payload` to the raw canonical bytes. These are the
   exact bytes the server signed.
3. Verify: `ed25519.Verify(pinnedPubKey, decodedSignedPayloadBytes, base64.StdDecode(signature))`.
   Do **not** re-marshal — verify over the decoded bytes exactly as received.
4. Only after the signature verifies, JSON-parse the decoded bytes into your config
   type. **Ignore any unknown keys** — an older agent that does not recognise a
   newer field (e.g. `blocking_process_policy`) simply skips it; the signature has
   already been validated over the complete byte string.
5. **Reject** the config if:
   - signature does not verify
   - `config_version` is lower than the last accepted version (anti-rollback)
   - `tenant_id` does not match the locally-configured tenant ID
   - `key_id` does not match the pinned key ID (wrong key — rotate in progress)

**Reference implementations (Patched-LTD/updater):**
- macOS: `endpoint/verify-agent-config.py` — "The server returns the exact bytes it
  signed as base64(signed_payload). Verify the Ed25519 signature over those raw
  bytes — no client reconstruction", then `json.loads` the verified bytes.
- Windows: `windows/src/Service/AgentConfigFetcher.cs` — "Ed25519 verify over the
  raw signed bytes — no client reconstruction", then deserialize; unknown JSON
  members are ignored by the deserializer.

> **Note (historical):** earlier revisions of this document described the agent
> "rebuilding the canonical struct from a fixed field list" and returning the
> canonical fields flat alongside `key_id`/`signature`. That never matched the
> shipped code: the wire response is the `{signed_payload, key_id, signature}`
> envelope above and both reference verifiers check the transmitted bytes as-is.
> Any remaining "agents that predate field X will fail signature verification"
> phrasing below is superseded by this section — such agents verify successfully
> and simply do not *act* on the unrecognised field until they are updated to read
> it; the feature is gated on that agent build, not on a signature break.

---

## Key management

| Item | Detail |
|---|---|
| Algorithm | Ed25519 (RFC 8032) |
| Private key store | `AGENT_CONFIG_SIGNING_KEY` env var in `/etc/patched-api/env`; base64-std-encoded 32-byte seed |
| Public key distribution | Printed at startup as `pubkey_b64=<base64>` in the structured log; agent pins this value |
| Key ID | First 8 bytes of `SHA-256(pubkey)` as lowercase hex — matches `key_id` in the response |
| Rotation | Update `AGENT_CONFIG_SIGNING_KEY`, restart service. New `key_id` appears immediately. Agents with a mismatched pinned key will reject the response — coordinate with PAT-282 agent update |

**Security invariant:** The private key never appears in the response body, in a DB column, or in any log line. `pubkey_b64` in logs is the *public* key — safe to log.

---

## Config fields

### `app_control` (PAT-601)

Application Control enforcement policy. Always present in every signed payload (never null). The agent MUST verify the Ed25519 signature before acting on any field in this block.

| Field | Type | Meaning |
|---|---|---|
| `enabled` | bool | Master switch. `false` (default) = no AC enforcement. Agents skip admin-list and app-allowlist checks entirely. |
| `approved_admins` | `string[]` | Usernames permitted in the local admin group. macOS: short username (e.g. `alice`). Windows: `DOMAIN\user` or bare local name. When `enabled=true` and the list is non-empty, agents remove any member not on this list at each collection run. |
| `app_allowlist` | `string[]` | Bundle IDs (macOS, e.g. `com.apple.Safari`) or process names (Windows, e.g. `chrome.exe`) permitted to run. Empty array = allowlist enforcement disabled. |
| `extension_blocklist` | object[] | Browser and extension-ID pairs to restrict through managed browser policy. Empty array = no extension blocklist enforcement. Since PAT-2007 the server sends an empty array for every tenant without App Control (`tenants.app_control_enabled` false), whatever the extension policy rows say; unapproved extensions reach this list only on an App Control tenant, and since PAT-2089 only the operator's (`tenant_extension_policies.source = 'operator'`): a customer's portal Unapproved never does. |
| `extension_removals` | object[] | Explicit destructive removal directives. The server delivers only exact `one_observation` directives to a device credential; tenant-wide credentials receive an empty array. |

Each `extension_removals` entry has `browser`, `extension_id`, `user_account`,
`profile`, `scope: "one_observation"`, and `approved_before` (RFC3339). Agents
MUST ignore any `one_observation` entry with missing or invalid context. Before
deleting, they MUST verify that the on-disk extension artifact's modification
time is not later than `approved_before`; a later timestamp represents an update
or reinstall that was not approved by this request. Completion audit details
MUST echo the exact `approved_before` value so the platform can bind evidence to
the request that produced the directive. Older agents do not recognise
`one_observation` and therefore safely ignore it.

**Safe defaults:** `enabled: false`, all lists empty. All existing tenants receive this default until Application Control is explicitly provisioned (requires `app_control_enabled = true` in the `tenants` table).

**Agent behaviour:** agents MUST treat a missing `app_control` block identically to `{enabled: false, approved_admins: [], app_allowlist: []}`. When `enabled: false`, no removal or alerting occurs regardless of list contents.

**Signing note:** `app_control` is the first field alphabetically ("app" < "catalog"), inserted before `catalog_scope`. Agents that predate PAT-601 verify the signature normally and simply ignore the unknown block until updated; AC enforcement is gated on an agent build that reads the field (see [Signature verification](#signature-verification-agent-implementation-guide)).

### `decommission` (PAT-1108)

Tenant-wide agent-decommission directive. **Always present in every signed payload, never omitted and never null** — unlike `blocking_process_policy`, "no directive" and "mode=none" are the exact same signed bytes by construction, because this is the only irreversible directive in the whole contract: once an agent removes itself there is no channel left to correct a mistake.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mode` | string | `"none"` | `"none"` = inert, agent takes no action. `"expiry"` = the agent may remove itself once `expires_at` has passed. `"immediate"` = the agent may remove itself on the next successful verification of this directive. |
| `expires_at` | string \| null | `null` | RFC3339 UTC timestamp. **Required (non-null) when `mode="expiry"`.** Ignored when `mode` is `"none"` or `"immediate"`. |
| `purge` | bool | `false` | When `true`, the agent also removes locally cached data/artefacts as part of decommission, not only its own uploader/daemon. |
| `reason` | string \| null | `null` | Free-text, operator-supplied context, recorded and surfaced for audit/operator visibility only. Its *value* never drives removal behaviour, but a change to it still bumps `config_version` like any other field in this block (PAT-1138) — see the fail-closed contract below. |

**Fail-closed contract — read this twice:**

- **Absent means inert, and this is enforced twice.** A tenant with no `tenant_decommission` row signs `mode="none"` (see `dbGetAgentConfig`). A malformed or corrupted stored row — an unrecognised `mode`, or `mode="expiry"` with a missing/unparseable `expires_at` — is independently coerced to the fully inert default at the moment of signing (`agentconfig.safeDecommissionPolicy`), so a bad database row can never reach the wire as anything actionable.
- **The agent must never guess a removal date.** An unparseable, missing, or obviously-wrong-clock `expires_at` when `mode="expiry"` must be treated as a fault: do not remove, record the fault.
- **Verification is not optional here of all places.** `decommission` is inside the same Ed25519-signed canonical payload as every other field — the agent MUST verify the signature over the raw transmitted bytes, exactly as described in [Signature verification](#signature-verification-agent-implementation-guide), before acting on `mode`. There is no separate delivery path for this directive that could bypass that check.
- **`reason`'s *value* is never a control-flow input, but changing it still bumps `config_version` (PAT-1138).** `reason` is recorded and surfaced to operators only — neither the platform nor the agent may branch on *what it says*. That is a distinct question from whether *changing* it moves the anti-rollback counter: `reason` lives inside the same signed `decommission` block as `mode`/`expires_at`/`purge`, so a reason-only edit changes the signed bytes exactly as any other field in that block would, and `PUT /admin/tenants/{tenantID}/decommission` bumps `config_version` on any change to the signed payload — a reason-only edit included — not on branching over reason's contents. (An earlier revision of this directive deliberately excluded reason-only edits from the bump, to minimise device churn; that traded away deliverability of a corrected reason to any agent that had already accepted the previous `config_version` — anti-rollback would reject the correction as a same-version replay. PAT-1138 reversed that: correctness beats churn. An exactly-identical repeat `PUT`, including an unchanged `reason`, still does not bump anything — there is no signed-byte change to propagate.)
- **No decommission field is exposed on any customer-facing surface.** This directive and the per-device state below are staff/admin-only (`/admin/*`, Tailscale-internal listener). The portal never reads or writes this data.

**Write path:** `PUT /admin/tenants/{tenantID}/decommission` — an explicit, audited action, **never** a side effect of `DELETE /admin/tenants/{tenantID}` (soft-revoke) or `DELETE /admin/tenants/{tenantID}/purge` (hard delete). Every call records `actor` and a server-assigned timestamp in an append-only audit log (`tenant_decommission_audit`), whether or not the resulting directive differs from the previous one.

```jsonc
// PUT /admin/tenants/{tenantID}/decommission
{
  "mode":       "expiry",                   // required; "none" | "expiry" | "immediate"
  "expires_at": "2026-09-01T00:00:00Z",     // required (RFC3339) when mode="expiry"; the write path returns 400 if missing/unparseable in that case; ignored (not stored) for any other mode
  "purge":      false,                      // optional; default false
  "reason":     "tenant offboarded",        // optional
  "actor":      "andy@patched.im"           // optional; defaults to "system"
}
```

The response echoes the stored directive (`tenant_id`, `mode`, `expires_at`, `purge`, `reason`, `set_by`, `set_at`).

**Read paths:**
- `GET /admin/tenants/{tenantID}/decommission` — the current tenant-wide directive (defaults to `mode="none"` when none has ever been set).
- `GET /admin/tenants/{tenantID}/decommission/devices` — per-device state for the tenant, **including devices that have never reported anything** (a LEFT JOIN from `devices`, not an INNER JOIN from the state table) — so "12 of 40 removed, 28 pending" is directly expressible. Each entry's `status` is one of `pending` (never reported; the default for an absent row) | `acknowledged` | `removed` | `failed` | `expired_unreachable`. Each entry also carries `terminal_without_acknowledgement` (bool, PAT-1108 fifth-round finding P1-E): true when `status` is a terminal outcome that arrived with no step-1 `"acknowledged"` ever observed for that directive generation — see the two-phase reporting section below for why this is flagged rather than rejected. Always false for a non-terminal status.

**Status reporting is two-phase — this is not optional and not a style choice (PAT-1108 fourth-round finding P1-B).** `POST /v1/agent-decommission-status`. Device-scoped bearer + HMAC-SHA256 + replay (timestamp + nonce), identical to the other agent-facing POST routes; a tenant-wide credential cannot call it, and the device is resolved exclusively from the authenticated credential, never from the request body.

The agent MUST call this endpoint **twice** per removal attempt, in this order, and MUST NOT collapse it into one call:

1. **Report `"acknowledged"` BEFORE attempting removal, and WAIT FOR ITS RESPONSE — this is the authorisation point (PAT-1108 sixth-round finding P1-F).** Persistence and authorisation are separate questions here: the server PERSISTS an `acknowledged` report whenever the directive is live (any `mode` other than `"none"`) and current, regardless of whether it yet authorises removal — a `mode="expiry"` directive whose `expires_at` has not yet passed is still live and still gets its `acknowledged` report recorded. But `decommission` in the response is gated on the SAME authorisation check as the terminal report: `mode="immediate"`, or `mode="expiry"` with `expires_at` genuinely passed by the server's own clock. **The agent MUST NOT proceed to step 2 unless this response says `"proceed"`.** This is not a formality: the removal attempt (step 2) happens BETWEEN this call and the terminal report (step 3), so THIS is the only response the server ever sends the agent before it would take the irreversible step — a later refusal, on the terminal report, arrives after removal has already happened and prevents nothing. A device with a wrong or advanced system clock does not get to decide the removal window has opened; only this response, driven by the server's clock, does.
2. **Attempt the removal.** Do not report a terminal status before or during this step, no matter how confident the agent is that it will succeed.
3. **After the attempt finishes — succeeded or not — report the GENUINE outcome:** `"removed"` only if removal actually succeeded, `"failed"` (or `"expired_unreachable"`, where applicable) if it did not. This is the platform's only durable record of what actually happened, so retry this call a bounded number of times if it does not reach the server on the first attempt.
4. **Only after step 3's call has gone through (or its retries are exhausted) may the agent destroy its own uploader/reporting mechanism.** This ordering is the entire point: an earlier revision of this contract had the agent report `"removed"` immediately **before** removing itself — i.e. before removal was even attempted — which meant a removal that subsequently failed left the platform holding a durable, sticky `"removed"` record for a device that was never actually removed, with **no channel left to correct it** (terminal-status stickiness, below, means nothing short of a materially new directive can undo a wrong terminal report). Reporting the genuine outcome only after it is known, and only destroying the ability to ever report again after that call, is what keeps the record honest. **Do NOT report `"removed"` before attempting removal, and do NOT destroy the uploader before the terminal report has gone through (or its retries are exhausted).**

**Phase 1 is mandatory, not advisory — but the server does not enforce it by rejection (PAT-1108 fifth-round finding P1-E).** A compliant agent always sends step 1 before step 3. The server, however, will still ACCEPT a step 3 terminal report (`"removed"`/`"failed"`/`"expired_unreachable"`) even if no step 1 `"acknowledged"` was ever recorded for that directive generation — deliberately, not as a gap: rejecting an unacknowledged terminal report would also reject the case where step 1 genuinely happened but was lost in transit (a dropped response, a network blip) and step 3 is a device's real, final word before it disappears forever. Refusing that report would trade a false `"removed"` for a permanently lost true one, which is worse — an agent that silently disappears is indistinguishable from one that crashed, and losing its last word is strictly worse than recording it with a caveat. So the server always accepts the report, but does not treat "arrived with no observed acknowledgement" as equivalent to "arrived via the normal two-phase sequence": it records, alongside the outcome, whether phase 1 was actually observed for that directive generation, and `GET /admin/tenants/{tenantID}/decommission/devices` surfaces that as `terminal_without_acknowledgement` so an operator can see a terminal report that skipped step 1 as visibly anomalous rather than indistinguishable from a clean removal. **This is not something the agent needs to do anything about** — it is a server-side bookkeeping distinction for operator review, not a wire-contract field the agent sends or reacts to. It exists precisely because compliant agents are expected to always send step 1 first; skipping it is the exceptional case this flag is for.

```jsonc
// Phase 1 — POST /v1/agent-decommission-status, BEFORE removal starts
{
  "status": "acknowledged",                                   // required; one of acknowledged | removed | failed | expired_unreachable
  "detail": "directive verified, starting removal",           // optional free text
  "directive_version": 4                                       // required; integer. The agent_config.config_version of the ENVELOPE you last verified before acting -- literally the top-level "config_version" field from the signed payload you checked signature+contents on. Do NOT try to figure out "the directive's own version" -- there isn't one you can observe; send the envelope version, exactly as verified. See "directive_version" below.
}
```

```jsonc
// Phase 2 — POST /v1/agent-decommission-status, AFTER the removal attempt finishes,
// BEFORE the agent destroys its own uploader/reporting mechanism
{
  "status": "removed",                                        // the GENUINE outcome: "removed" only if it actually succeeded, "failed" (or "expired_unreachable") otherwise
  "detail": "uploader removed, LaunchDaemon unloaded",
  "directive_version": 4                                       // same envelope version as phase 1, unless the agent re-verified in between
}
```

**`directive_version` (PAT-1108).** An integer: the `config_version` of the last signed envelope the agent verified before it acted — the **same field, same value** as the top-level `config_version` in the GET `/v1/agent-config` response you last checked. This is deliberately the ONLY version an agent is asked to send, because it is the only one an agent can actually observe: the agent has no way to know, on its own, whether the `decommission` block it saw was "the version" of the directive or just what happened to be current when an unrelated field (tier, `app_control`, anything) last changed. Send exactly what you verified; the server does the rest.

- **The server does NOT stamp its own "current" version onto your report, and does NOT validate it against the directive's own counter either.** Earlier versions of this endpoint did the former (misattributing delayed reports to whatever was current at write time); an earlier revision of this document asked for the latter and that was ALSO wrong — an unrelated `agent_config` write (an `app_control` edit, a tier change) bumps the envelope `config_version` without ever touching the decommission directive, so a perfectly valid report validated against the directive's own version could arrive looking "ahead" and get rejected for a reason that had nothing to do with decommission. The server validates your reported value against the tenant's CURRENT ENVELOPE `config_version` instead (only a value genuinely ahead of that is nonsense: `400`), then resolves it server-side to whichever directive was actually in effect at that envelope version. You never need to know or send anything about that resolution — just send the envelope version you verified.
- **Missing the field is untrusted, not current.** If your agent build predates this field, omit it — the report is still stored (so "the device made contact" is not lost), but the server can never confirm it describes the tenant's current directive, so the response is always `"decommission": "superseded"` (see below). It is safer for an unattributable report to be told to stop than to have it silently trusted.
- **A terminal outcome is scoped to the directive generation it was reported against.** `removed` (or `failed`/`expired_unreachable`) for one directive does not block a later report for the NEXT directive — a newly issued directive always gets a clean slate on that device, whatever the previous directive's outcome was. Terminal-status stickiness only suppresses a regressing report **within the same directive generation**, and it applies from the moment the FIRST terminal report for a directive generation lands — there is no path, ever, to correct a wrong terminal report except the tenant issuing a materially new directive. This is exactly why step 4 above matters: get the terminal report right, because it cannot be taken back.

**The response — READ THIS BEFORE WIRING UP EITHER PHASE.** Neither call is fire-and-forget. The agent MUST wait for the response on BOTH calls and act on the `decommission` field — never on the HTTP status code alone, and never by proceeding unconditionally once the POST completes.

**`"proceed"` means EXACTLY THE SAME THING on both calls (PAT-1108 sixth-round finding P1-F): the directive is still the tenant's current directive, AND it currently AUTHORISES REMOVAL** — `mode="immediate"`, or `mode="expiry"` with `expires_at` genuinely passed **by the server's own clock**, never the device's (a wrong or deliberately advanced device clock must never be able to shift this). There is deliberately no weaker "just live, not yet authorised" version of `"proceed"` for phase 1: since the removal attempt happens between the two calls, phase 1's response is the only one that can ever prevent an unauthorised attempt, so it must carry the full authorisation check, not a lesser one. `"superseded"` means either half is not true — cancelled, superseded by a newer directive, not yet authorised, or unattributable — and the agent MUST NOT continue on the strength of this report: do not proceed to phase 2 if this was the phase 1 response; do not treat removal as confirmed if this was the phase 2 response.

**A phase 1 report can be RECORDED while still getting `"superseded"`.** These are separate questions: whether the server persists your `"acknowledged"` report (it does, whenever the directive is live and current — see step 1 above) and whether it authorises you to proceed (a separate, stricter check). So `recorded_status` may be present alongside `"decommission": "superseded"` — it reflects what actually got persisted, independent of whether removal is authorised. As always, check `decommission` for control flow and treat `recorded_status` as informational only.

```jsonc
// 200 OK — proceed. The directive is current AND currently authorises removal.
{
  "decommission": "proceed",
  "device_id": "3f9c2e40-...",
  "recorded_status": "acknowledged"  // the TRUE persisted status; may differ from what you reported if an
                                      // earlier report for the SAME directive generation already won
}
```

```jsonc
// 409 Conflict — STOP. Do not continue (do not proceed to phase 2 removal, if this was the
// phase 1 response; do not treat removal as confirmed, if this was the phase 2 response).
// The directive has been cancelled or superseded since you last verified it, does not yet
// authorise removal, or you did not send a directive_version the server could confirm as current.
{
  "decommission": "superseded",
  "device_id": "3f9c2e40-...",
  "recorded_status": "acknowledged"  // MAY be present: a phase 1 report can persist even when
                                      // decommission is "superseded" (removal not yet authorised) —
                                      // absent only when nothing was persisted for this call at all
                                      // (e.g. a stale-version report, or an unauthorised terminal report)
}
```

Rules for the agent implementation:

- **Check `decommission`, not the HTTP status code, and not `recorded_status`'s presence.** `"proceed"` and `"superseded"` are the two — and only two — values this field takes; there is no third option and no ambiguity to guess through.
- **`"superseded"` means STOP, unconditionally, at whichever phase you were on.** The device may already have made contact (the server may still have recorded a phase 1 `"acknowledged"` report even when refusing to authorise — see above), but the platform is telling you the specific action you were about to take is no longer valid — the operator cancelled it, a newer directive superseded it, the removal window has not opened yet (either phase — phase 1's check is exactly as strict as phase 2's), or the server could not confirm which directive you meant. Do not attempt removal (if this was the phase 1 response) or continue/confirm it (if this was the phase 2 response), do not destroy your own reporting mechanism, and do not retry the same report expecting a different answer; re-fetch `GET /v1/agent-config` and re-evaluate from the current signed `decommission` block instead.
- **`"proceed"` on the phase 1 call is what licenses attempting removal (step 2); `"proceed"` on the phase 2 call is what licenses destroying your own uploader (step 4).** Neither may be skipped or inferred from the other. `recorded_status`, when present, is the true persisted status, which is NOT necessarily what you just reported (e.g. a delayed/duplicate report against an already-terminal status for the same directive is accepted as "proceed" but ignored for storage — see the terminal-stickiness note above). Only `recorded_status == your reported status` confirms your specific report was the one that stuck.

**Directive persistence:** the tenant-wide directive persists **indefinitely**. A device offline for months must still see and act on it the moment it reconnects — there is no TTL, expiry sweep, or cleanup job on the directive itself, and none may ever be added.

### `blocked_versions` (PAT-1238)

The version kill switch: a map of Installomator (macOS) / winget (Windows) label
to a list of version strings the agent must treat as blocked for that label. This
is the server-side write path for the field both agents already read — the
website markets it as halting any known-bad version estate-wide. **Optional** —
the key is **omitted** from the canonical payload when the tenant has never set
it (same omit-not-null convention as `blocking_process_policy`), and the agent
treats an absent or empty block identically to "nothing blocked."

```jsonc
"blocked_versions": {
  "google-chrome": ["139.0.7258.67", "139.0.7258.68"],
  "1password":     ["8.10.40"]
}
```

| Field | Type | Meaning |
|---|---|---|
| (map key) | string | Installomator or winget label, e.g. `google-chrome`, `1password`. Non-empty; must not contain `/`, `\`, or `..`. |
| (map value) | `string[]` | Blocked version strings for that label. Free-form — versions are not validated against any particular format because they come from many different vendor schemes. Non-empty list; every entry must itself be non-empty. |

**Incident-safe write path.** Operators add or remove one exact label/version
pair with `PATCH /admin/agent-config/{tenantID}/blocked-versions`. The platform edits
only `body.blocked_versions` under a row lock, preserves every other JSONB field
(including fields unknown to the running binary), and increments the shared
`agent_config.config_version` only when the effective set changes. Repeating an
identical add or removing an absent pair is an idempotent `200` with
`changed=false` and no version bump. This is the supported operational path for
the kill switch; it avoids the general agent-config PUT's full-replace contract.

The legacy `PUT /admin/agent-config/{tenantID}` still accepts a complete
`blocked_versions` map for compatibility. It remains a full-body administrative
write where omitting or emptying the field clears it, and must not be used to
pull the kill switch during an incident.

**Validation (write path):** each label must be non-empty and free of path
separators (`/`, `\`) or `..`; each label's version list must be non-empty, and
every version string in it must be non-empty. Malformed entries are rejected
with `400 Bad Request` before anything is stored.

**Evidence path:** an agent refusal caused by this kill switch is reported to
`POST /v1/events` with `event_type="version_blocked"`. Migration 0100 extends
the database event-type constraint so this evidence is persisted with the other
signed audit events.

**Backward compatibility:** because the field is `omitempty`, tenants who never
set it sign byte-identical canonical bytes to before this field existed; agents
that predate PAT-1238 verify normally and ignore the field until updated to read
it — same forward-compatibility guarantee as every other field in this contract.

### `blocking_process_policy` (PAT-296)

Per-tenant close-to-update policy: controls how the agent behaves when an app that
must close to install an update is still running. **Optional** — the key is
**omitted** from the canonical payload when the tenant has no policy, and the agent
applies its own built-in safe defaults in that case. Alphabetical position:
between `app_control` and `catalog_scope`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `action_on_timeout` | string | `"notify_only"` | What the agent does when `timeout_seconds` elapses and the process is still running. `"notify_only"` = surface a notification and skip this app (**SAFE DEFAULT — never force-quits**); `"prompt_then_quit"` = show a final prompt, then quit the app if the user confirms; `"skip_run"` = skip the update silently and retry next scheduled run. The agent MUST treat any unrecognised value as `"notify_only"`. |
| `timeout_seconds` | integer | `300` | Seconds the agent waits for the blocking process to exit before applying `action_on_timeout`. Safe range 30–86400. |
| `max_deferrals` | integer | `2` | Max times the user may defer the close-to-update prompt per app per update cycle. `0` = no deferrals allowed (still respects `action_on_timeout`). Resets on successful update. |
| `defer_window_seconds` | integer | `3600` | How long a single deferral postpones the prompt. Safe range 60–86400. |
| `message` | string \| null | `null` | Tenant-brandable prompt copy (max 500 chars). `null` = agent uses its built-in default message. |

**Allowed `action_on_timeout` values:** `notify_only`, `prompt_then_quit`, `skip_run`. Any other value is rejected on write and coerced to `notify_only` at sign time.

**Safety invariant (server-enforced):** an **absent, malformed, or unknown** policy
must **never** cause the agent to force-quit a running app.
- The admin write path (`PUT /admin/agent-config`) validates every field, defaults
  `action_on_timeout` to `notify_only` when unset, and rejects unknown actions and
  out-of-range numerics.
- The **signer** is the defense-in-depth boundary for stored/legacy rows: before a
  policy enters the signed bytes, if it is malformed in **any** field — action not
  in the allowed set, or a dangerous action (`prompt_then_quit`/`skip_run`) paired
  with out-of-safe-range numerics (e.g. `timeout_seconds <= 0`, `max_deferrals < 0`,
  `defer_window_seconds <= 0`) that could drive an effectively-immediate quit —
  `action_on_timeout` is coerced to `notify_only`. A dangerous-but-malformed
  directive is never signed.
- The agent independently enforces the same `notify_only` minimum-safe fallback.

**Backward compatibility:** because the field is `omitempty`, policy-less tenants
sign byte-identical canonical bytes to before this field existed; agents that
predate PAT-296 verify normally and ignore the field until updated to read it.

### `legacy_app_execution_enabled` (PAT-1481)

An always-present signed boolean for the quarantined legacy application
execution paths only. Production always emits `false`. Coordinated current
updater clients consume it on retained legacy package, install, update,
uninstall, and removal paths. Those paths require an exact boolean `true`;
absent, `null`, malformed, and `false` values deny execution. It does not
disable inventory, OS-update policy, decommission, self-update, reporting, or
advisory application-control findings. The field is runtime-derived at GET
time and must not be treated as a durable tenant preference. Every contained
API process has one random activation nonce. Its first GET for each tenant
atomically records that nonce and advances `config_version`; subsequent GETs
from the same process reuse the durable generation. If several contained
processes serve concurrently, each process advances once per tenant and its
nonce remains recorded, so alternating requests do not repeatedly advance.
A redeploy after automatic rollback therefore issues a generation newer than
any equal-version executable envelope the rolled-back binary could sign,
without turning ordinary reads into an ever-increasing counter.

This gate is deliberately separate from the durable stored `tier`, which
remains available for assurance and governance paths. While the legacy plane is
quarantined, however, every signed response projects the old-understood
`tier:"report_deploy"`: older agents ignore this unknown gate and the
scoped-ring field, but they do honour `tier` and remain contained by that
projection. The stored `"patch"` or `"managed"` policy is not changed. There
is no compatibility window or environment rollback switch. A future execution
design requires separately reviewed implementation and fresh-state scoping.

### `app_control_authority` (PAT-1481)

An always-present signed enum for retained application-control paths only. It
is derived at response time from the durable tenant `tier` before the response
projects `tier:"report_deploy"` for legacy containment: `report_deploy` maps
to `"report"`, `patch` to `"block"`, and `managed` to `"enforce"`. Missing,
malformed, or unknown durable tiers map to `"report"`. It is never persisted
as a tenant preference.

New updater clients use this field for application-control blocklist and
enforcement decisions. It never authorises legacy catalogue installs, legacy
allowlist removals, device-removal tasks, legacy rollouts, or mandatory-install
directives; `legacy_app_execution_enabled:false` remains their exact false
gate. Old clients ignore this unknown field and remain report-only because
they still receive `tier:"report_deploy"`.

### Retained application control during containment

The signed response retains `app_control` fields, including exact
browser-extension directives and approved-admin policy. New updater clients
use `app_control_authority` to retain blocklist and enforcement authority
without regaining legacy package execution. Old tier-gated clients cannot
distinguish this authority from historic package execution and therefore
remain report-only under the signed `report_deploy` projection. Advisory
app-allowlist findings remain available to both. Do not infer that the durable
`patch` or `managed` tier independently authorises legacy execution.

### `tier`

| Value | Meaning |
|---|---|
| `"report_deploy"` | Collect + report. No automated patching. Default for all new tenants. |
| `"patch"` | Collect + report + automated third-party app patching via the Updater. |

### `proxy`

| Field | Type | Meaning |
|---|---|---|
| `mode` | `"system"` \| `"manual"` \| `"off"` | How the agent routes traffic. `"system"` = use macOS/Windows system proxy. |
| `type` | `"http"` \| `"https"` \| `"socks5"` \| null | Proxy protocol. Required when `mode = "manual"`. |
| `host` | string \| null | Proxy hostname or IP. Required when `mode = "manual"`. |
| `port` | integer \| null | Proxy port. Required when `mode = "manual"`. |
| `pac_url` | string \| null | PAC file URL. Alternative to `host`/`port` when `mode = "manual"`. |
| `auth_ref` | string \| null | Keychain/secret-store reference for proxy credentials (PAT-278). **Never a plaintext password.** |
| `bypass_when_off_corp` | bool | When `true` and the device is not on the corporate network, the agent skips the proxy. |

### `device_id` (PAT-1026)

The requesting device's own platform device id — the same identifier space as `devices.id` and `tenant_credentials.device_id`, **not** any OS-level hardware identifier (e.g. macOS `IOPlatformUUID`). This is the id the agent should treat as "who am I" when evaluating any directive scoped to a specific device, such as `log_request` below.

**Server-side:** injected per-device at GET time, the same pattern as `ring` (PAT-117): a device-scoped credential yields its own resolved device id; a tenant-wide credential yields the empty string, since no single device id is correct for it. The value always comes from the authenticated credential the server already resolved — never from any client-supplied input — so one device's response can never carry another device's id.

**Agent-side:** an agent resolves its own device id with this precedence: (1) the `device_id` field of the most recently verified `agent-config` response, falling back to (2) the id persisted locally at enrolment time (from the `POST /v1/enrol` response). If neither source yields a value, the agent does not know its own identity and must not evaluate device-scoped directives as either a match or a mismatch — it should treat that as a distinct "unknown identity" condition and skip, logging accordingly.

**Update-channel authority is stricter (PAT-2351, PAT-2424).** For self-update policy the Windows agent does not use precedence (1): the config's own `device_id` is the binding being checked, so it is compared against the locally stored canonical id and never adopted from the config. A device with no stored id (enrolled on a build that discarded the `POST /v1/enrol` `device_id`, or whose stored id no longer matches its tenant and bearer) asks `GET /v1/device/identity`, authenticated with its own bearer and v3 HMAC (endpoint id `device_identity`), and stores the answer bound to its tenant id and the SHA-256 of its bearer, as enrolment does. See `go-service/docs/API.md`.

**Default:** empty string for tenant-wide credentials and for any tenant/device predating this field.

### `log_request` (PAT-286)

Optional on-demand log-collection directive. When non-null, the agent whose resolved own device id (see `device_id` above) matches collects a log bundle and uploads it to `POST /v1/agent-logs`.

| Field | Type | Meaning |
|---|---|---|
| `components` | `string[]` | Log components to collect, e.g. `["updater","collector"]` |
| `device_id` | UUID string | Target device, as a platform device id (`devices.id`). The server requires a UUID here and rejects anything else, so a directive always targets exactly one device. The agent MUST compare this against its own resolved platform device id (see `device_id` above) before collecting, and must not act on the directive if its own device id cannot be resolved. |
| `max_bytes` | integer | Maximum compressed bundle size (bytes) the agent should produce. The agent enforces this; the server applies only its hard 10 MiB cap. |
| `request_id` | UUID string | Idempotency key issued by the platform. The agent sends it in `X-Patched-Log-Request-ID` on upload; the server stores at most one bundle per `(tenant, device, request_id)`. |
| `since` | RFC3339 string | Start of log range (inclusive). |
| `until` | RFC3339 string | End of log range (exclusive). |

When the platform has no pending log request, this field is `null`. The agent should clear any prior directive once it has successfully uploaded the bundle.

**Security:** `log_request` is part of the signed canonical payload. An agent MUST verify the signature before acting on this directive. Only the device whose own resolved platform device id matches the directive's `device_id` should collect and upload. Cross-device collection is impossible via the upload path because the server resolves device from the credential, not the request body.

### `report_user_attribution` (PAT-116)

Controls whether the primary-user (last-known console/logon user) is shown in executive summary reports.

| Value | Meaning |
|---|---|
| `"off"` | Default. No user PII rendered in any report. |
| `"local_part"` | Show the local part of the UPN/username (e.g. `jsmith` from `jsmith@corp.example`). |
| `"full_upn"` | Show the full UPN or account string (e.g. `jsmith@corp.example`). |

**Privacy:** This field is PII-sensitive. Default is `"off"`. Enabling requires the DPA supplement (PAT-112) to be in place. The field is part of the signed canonical payload; agents that predate it verify the signature normally and ignore the field, so a non-`"off"` value takes effect only once agents are updated to read it (the feature is gated on that agent build, not on a signature break).

### `ring` (PAT-117)

Per-device patching ring integer. The agent installs an update only if `device.ring <= approved_ring` for that label.

| Value | Name | Meaning |
|---|---|---|
| `0` | internal | First-wave internal test devices only |
| `1` | canary | Second-wave early-adopter canary devices |
| `2` | early-adopter | Third-wave broad early-adopter fleet |
| `3` | GA | General availability — all remaining devices (default) |

**Server-side:** the ring value is **injected per-device at GET time** using `COALESCE(ring_override, ring_computed, 3)`. Tenant-wide credentials (unknown device) always receive ring `3`. Ring assignment is deterministic: `bucket = crc32(device_id bytes) % 100` mapped against the tenant's percentage bands, so the same device always receives the same ring unless an admin override is set or the tenant's percentage configuration changes.

**Default:** `3` (GA). Unknown/unassigned devices and tenants without rings enabled always receive `3`.

### `ring_promotions` (PAT-117)

Per-tenant rollout approval map. Tells the agent the highest approved ring for each label that is currently in a rolling rollout. `null` when rings are disabled for the tenant.

```jsonc
{
  "googlechrome": { "version": "125.0.6422.60", "approved_ring": 1 },
  "firefox":      { "version": "126.0",         "approved_ring": 0 }
}
```

The legacy agent checks: if `device.ring > entry.approved_ring` for this label, hold back (set `ring_gated: true` in the next provenance report). Otherwise proceed with the update.

### `ring_promotions_scoped` (PAT-1134)

Current agents use this object whenever it is present, and do not consult the
legacy projection. It removes the label-only collision between macOS and
Windows and carries an unambiguous first-ring pause:

```jsonc
{
  "macos": {
    "firefox": { "version": "130.0", "approval": "nobody" },
    "googlechrome": { "version": "125.0.6422.60", "approval": "up_to_ring", "approved_ring": 1 }
  },
  "windows": {}
}
```

`approval: "nobody"` is an explicit deny. Agents must deny an entry with that
value, an unknown approval value, or a malformed `up_to_ring` ring. A missing
label in a present platform map means no rollout gate for that label.

For PAT-1481 containment, a platform value of `null` is the explicit deny-all
representation for that platform. It is intentionally distinct from `{}`:
`{}` means the platform has no rollout gate, whereas `null` means no legacy
application execution is authorised for any label on that platform. When
`legacy_app_execution_enabled` is false, the server emits both platforms as
`{"macos":null,"windows":null}`. Agents that consume the scoped projection
must recognise this per-platform `null` form and must not treat it as
execution authority. Current scoped-projection consumers recognise this as a
defence-in-depth deny; the server does not depend on the new boolean being
consumed to contain package execution.

Historical rollout projections are neutralised in every production response.
Retained rows are not execution authority and are not progressed automatically.

**Ring-to-agent-value mapping (ring_count → agent ring values):**

| ring_count | ring 0 | ring 1 | ring 2 | ring 3 | ring 4 |
|---|---|---|---|---|---|
| 2 | 0 | 3 | — | — | — |
| 3 | 0 | 1 | 3 | — | — |
| 4 | 0 | 1 | 2 | 3 | — |
| 5 | 0 | 1 | 2 | 2 | 3 |

The last ring always maps to agent value `3` (GA) regardless of ring_count. Percentage changes only move band boundaries; devices deep in a band never move ring.

### Reserved fields

These fields are `null` in all current responses. Future workstreams will activate them without a breaking schema change.

| Field | Future use |
|---|---|
| `catalog_scope` | Scope selector for which apps the Updater manages (PAT-273) |
| `scan_cadence` | Override the default collection interval |
| `os_update_policy` | OS update enforcement policy (PAT-273) |
| `per_app_patch` | Per-application patch policy overrides (PAT-167) |

---

## Write path (dashboard → platform)

`PUT /admin/agent-config/{tenantID}` on the internal Tailscale-bound listener (`:8081`).  
Auth: network-only — Tailscale ACL restricts access to `tag:main`.

### Request body

```jsonc
{
  "tier": "report_deploy",  // required; "report_deploy" | "patch"
  "proxy": {
    "mode": "system",                // required; "system" | "manual" | "off"
    "type": null,                    // optional
    "host": null,                    // required when mode="manual"
    "port": null,                    // optional
    "pac_url": null,                 // optional
    "auth_ref": null,                // optional — Keychain ref, never plaintext
    "bypass_when_off_corp": false    // optional
  },
  "log_request": null,              // optional (PAT-286); set to a LogRequestDirective or null to clear
  "blocked_versions": {             // optional (PAT-1238); omit/empty clears any stored blocking list (full-replace)
    "google-chrome": ["139.0.7258.67"]
  },
  "blocking_process_policy": {      // optional (PAT-296); null/omit clears any stored policy (agent falls back to safe defaults)
    "action_on_timeout":    "notify_only",  // optional; defaults to "notify_only" when omitted. One of: notify_only | prompt_then_quit | skip_run
    "timeout_seconds":      300,            // optional; default 300; range 30–86400
    "max_deferrals":        2,              // optional; default 2; >= 0 (0 = no deferrals allowed)
    "defer_window_seconds": 3600,           // optional; default 3600; range 60–86400
    "message":              null            // optional; tenant-brandable copy (<=500 chars); null = agent default
  },
  "updated_by": "admin@patched.im"  // optional; defaults to "system"
}
```

### Response

```jsonc
{
  "tenant_id":      "a0eebc99-...",
  "config_version": 4,      // bumped from previous value
  "key_id":         "65b60673d6ed884b"
}
```

`config_version` increments by 1 on every successful write, invalidating any cached ETag the agent holds.

---

## Anti-rollback

The agent MUST persist the last accepted `config_version` across restarts. On
receipt of a config, reject it if `config_version < last_accepted`. Equal
versions remain accepted for retry compatibility, so every change to signed
authority must advance the server's durable counter before the changed payload
is issued. This prevents an older generation from being replayed after a newer
one has been accepted without breaking same-generation retries.

---

## Platform neutrality

The route, auth scheme, response schema, and signing algorithm are identical for macOS and Windows agents (PAT-276). The `proxy` section maps directly to system proxy settings on both platforms.

## Mandatory install intents (PAT-1399)

> **Retired.** PAT-2246 removed mandatory-install evaluation and delivery
> from `/v1/agent-config`, so the API no longer emits
> `mandatory_install_intents`. PAT-2249 then retired the catalogue review
> model this section validates against. What follows is the historical
> contract, kept until PAT-2248 marks the catalogue contracts superseded.

`mandatory_install_intents` is omitted when no device-bound work exists. It is
present only on a response authenticated with a device-scoped credential. A
tenant-wide credential never receives an intent. Each entry is part of the
exact Ed25519-signed `signed_payload` bytes:

Windows authority comes from an additive field in the same current global
signed catalogue envelope. The catalogue signer, never the API after signing,
must emit this exact platform-bound shape:

```json
{
  "platform_targets": {
    "windows": {
      "winget:example.product": {
        "product_key": "example-product",
        "platform": "windows",
        "label": "winget:example.product",
        "version": "4.2.0",
        "sha256": "64 lowercase hex characters",
        "verified_signer": "Example Software Ltd",
        "verified_at": "2026-08-21T12:00:00Z",
        "installed_identity": "winget:example.product"
      }
    }
  }
}
```

Every repeated field is binding. Windows evaluation and delivery reject a
missing entry or any product, platform, label, version, SHA-256, Authenticode
signer or verification-time disagreement with the current non-revoked
published catalogue target (the catalogue review model, retired in
PAT-2249). The reviewed signer comes only
from `last_verified_signer.authenticode_publisher`; registry `publisher`
inventory is not signing evidence. The legacy top-level `labels` map remains
the macOS authority used by PAT-1397 and is not reinterpreted as Windows
evidence.
The signed catalogue `label` is the installer/resolver key and is independent
of installed inventory identity. Signed entries optionally carry a separate
`installed_identity`: macOS accepts only `bundle:<CFBundleIdentifier>` read
from the exact codesign/notarization-accepted app; Windows accepts only
`winget:<winget_id>` carried through the Authenticode-verified runner evidence.
Both families are canonical lowercase (bundle identifiers are compared
case-insensitively and normalized on publication). An invalid identity is
omitted only for its own target with an operator-visible warning; it cannot
block publication of unrelated signed version, checksum and signer evidence.
Signed publication atomically copies that value to the matching reviewed
target's `mandatory_installed_identity`. Package-only or ambiguous artifacts
omit it and cannot authorize mandatory work. Evaluation requires the current
mandatory policy to match it exactly and snapshots it on the durable intent;
it is never inferred from a real macOS label such as `firefox` or from an app
display name.
Windows absence is eligible only after the latest authenticated schema-v3
inventory declares `inventory_capabilities.schema_version=1` and
`windows_winget_inventory_complete=true`. Every app in that snapshot carries
`identifier_kind` (`winget` for an exact case-sensitive Microsoft
PackageIdentifier-schema value, `native` otherwise). A malformed Winget row is
still retained as ordinary inventory, but loses identity authority and clears
snapshot completeness. Schema versions below 3 cannot assert either field.
Existing agents omit the capability and are excluded until
PAT-1401; registry display names/ProductCodes and mere absence never authorize
installation.

Before every check-in response, the API revalidates every unexpired active
candidate (`queued`, `delivered`, `received` or `installing`) against that same
current signed catalogue and current non-revoked published target. Invalid queued or
delivered work with no durable start evidence is cancelled and omitted. Work
already proved started is never cancelled, but is omitted so a revoked or
substituted target cannot receive renewed signed authority. Policy state,
policy tier, tenant config tier and installed identity are rechecked at this
boundary. Routine work also rechecks that its exact staged rollout remains
`rolling` and still admits the device ring. Exact intents created before a
rollout reaches `completed` remain deliverable/retryable for offline laggards,
because completion records approval of every band; paused, auto-paused,
skipped or superseded rollouts cannot mint or retry authority. Emergency intents remain a
separate reasoned and audited path. Failure to load current catalogue authority omits install directives,
rolls back their preparation transaction, and is logged as an operator-visible
error while unrelated signed configuration is still served.

```json
{
  "intent_id": "uuid",
  "delivery_id": "uuid",
  "device_id": "uuid",
  "catalogue_product_id": "uuid",
  "catalogue_target_id": "uuid",
  "platform": "macos",
  "label": "firefox",
  "version": "145.0",
  "sha256": "64 lowercase hex characters",
  "verified_signer": "TEAMID",
  "catalogue_content_hash": "64 lowercase hex characters",
  "rollout_ring": 0,
  "emergency": false,
  "reason": "mandatory policy evaluation",
  "state": "delivered",
  "attempt": 1,
  "expires_at": "2026-08-21T12:30:00Z"
}
```

The endpoint must verify the response signature before parsing or acting. It
must then reject an entry as authority to start new work unless `device_id` is
its authenticated platform device id, `platform` is its platform, the current
time is before `expires_at`, and all product, target, label, version, checksum
and signer bindings are present. These fields describe authority only. They do not carry a shell
command, executable path, privilege request or installer implementation.
The delivery authority window is deliberately limited to 30 minutes. Revoking
policy or catalogue authority prevents any subsequent directive immediately,
but an already delivered, device-bound signed directive remains usable until
its short expiry; instantaneous recall of offline signed bytes is impossible.
The endpoint persists intent ID, delivery ID, attempt and server `state` before
starting work and resumes/statuses that exact tuple after restart. A received
or installing state never authorizes a second installation. An authenticated
check-in may redeliver the same intent with a fresh delivery ID only when the
prior delivery expired and append-only history proves it was never received or
started; the old binding remains replay-invalid history.
Automatic redelivery is capped at three delivery attempts. At that ceiling the
expired snapshot is parked, omitted from check-in, and surfaced as requiring
the existing explicit reasoned admin retry; the 30-minute expiry is the
backoff between automatic attempts.

State is reported to `POST /v1/mandatory-install-status` using device-scoped
bearer authentication and the normal v3 HMAC input with endpoint id
`mandatory_install_status`. This route requires that exact v3 form regardless
of the server's compatibility settings for older routes; targetless v2 and
legacy body-only signatures are rejected. The request repeats every binding field and adds a
unique `report_id` plus `state`. The legal progression is `delivered ->
received -> installing -> succeeded|failed`; `delivered -> failed` and
`received -> failed` are also allowed. A repeated `report_id` with identical
state is idempotent. Reuse for another state, a stale nonce, or any substituted
binding is rejected. Expiry always rejects a new `received` or `installing`
transition. Every `succeeded` report, before or after expiry, requires the
complete ordered append-only device chain for that exact delivery id and
attempt: `delivered -> received`, then `received -> installing`. An isolated
installing event, a reverse-order pair, or mutable `state='installing'` alone
is not proof. An exactly bound late `failed` result may close work
from `received` or `installing`, including when those exact durable events
prove a stale mutable row had started. `received -> succeeded` is never legal.
This preserves a truthful late terminal result without letting expiry initiate
work or claim an installation that was never recorded as started. `failed`
work is retried only through the reasoned admin retry action. An expired,
provably never-started delivery is automatically redelivered on the next
authenticated check-in with a new delivery ID and attempt. The admin action refuses
stale `delivered` state when those durable start events exist, revalidates the
current signed catalogue, and creates the next delivery attempt on the same
durable intent.
An acknowledged stale-start recovery reason is retained separately from the
device-writable terminal error so a late success/failure receipt cannot erase
the operator provenance.

Removing a mandatory policy cancels only `queued` or `delivered` intent.
`received`, `installing` and terminal history remain untouched. Cancellation
never requests an uninstall. A later policy re-enable creates a new queued
intent for the same device/target/version while retaining the cancelled row
and its append-only events as independent history.

An expired `received` or `installing` intent is omitted from the active
check-in path before any catalogue resolver or renewed signing decision.
Started work remains durable for an exactly bound truthful terminal report.
An expired `delivered` attempt with no exact durable received/installing event
is atomically returned to queued and then redelivered through all current
authority checks. Check-in never renews the expired delivery ID itself.

The one-current-intent key intentionally includes `failed` and `succeeded`
rows. Routine evaluation cannot bypass a failed intent's explicit retry gate:
retry requeues the same intent and retains its attempts and events. A succeeded
same-version intent also cannot become reinstall work merely because policy is
removed and re-enabled while installed inventory is delayed. Only cancelled
history is excluded from the key because cancellation represents withdrawn,
unstarted policy authority.

The status request body limit applies to the complete byte stream. Exactly the
limit is accepted for subsequent authentication and parsing; limit plus one is
rejected before HMAC verification, so a signed valid prefix can never hide
ignored trailing bytes.

Installed detection is exact app-specific identity plus exact reviewed signer.
`device_apps.identifier` is the extractor's cross-platform primary identity
(with the legacy macOS bundle ID used only as its ingest fallback). The only
production families are macOS `bundle:` and Windows `winget:`; both compare
their stripped normalized value only to that field. Unknown identity families
fail closed. Only matching app rows feed
the exact version ordering: equal is compliant, older creates upgrade work,
newer is an explicit downgrade refusal, and missing or otherwise ambiguous
version evidence fails closed. These rules are identical for macOS and
Windows.

Signer equivalence has one platform-aware normalization everywhere: trim outer
whitespace and fold case (uppercase Team IDs, case-folded Authenticode names),
without collapsing internal whitespace or punctuation. Reviewed DB evidence,
signed evidence, policy signer and inventory signer all use that comparison.
After equivalence is proved, the exact signer spelling in the signed catalogue
is the canonical authority stored in the intent and delivered to the device;
the API never substitutes the reviewed DB spelling.

A mandatory policy is also app-specific: publisher/team/signer equality never
matches a catalogue target by itself. The policy must carry the exact bundle
or Winget identity represented by the reviewed target;
when the policy additionally pins a signer, it must match as a separate
constraint.

Expired `received` or `installing` work has an explicit two-stage operator
recovery. The first retry call requires a reason and
`acknowledge_duplicate_install_risk:true`, marks that attempt stale-failed, and
preserves its exact delivery binding so a late genuine terminal receipt can
still close it. A later reasoned retry may requeue the same durable intent.
The late-terminal exception is authorized only by the exact append-only
`source=retry` recovery event for that delivery and attempt; device-controlled
error text is never authority. Routine evaluation never performs either
action automatically.

Policy mutation uses an exclusive tenant authority lock. Evaluation, retry and
per-device delivery use the corresponding shared lock, so multiple device
check-ins can validate and sign concurrently while a policy edit waits for all
readers and cannot interleave policy-to-intent cancellation.

---

## Security review gate

This endpoint is part of the agent status/auth contract and **must be reviewed by a non-author** before the first customer ship (GitHub-Non-Author-Review). The agent will trust this config to drive patching behaviour — a tampered config could suppress patching or redirect agent traffic. Ed25519 signature verification is the primary mitigation; the agent must enforce it.
