# Audit events — platform integration contract

Agent-side implementation: PAT-499. Platform-side (patched.im repo): implement `POST /v1/events`.

---

## Transport

Same auth and signature scheme as `/v1/inventory` and `/v1/provenance`.

```
POST /v1/events
Authorization: Bearer <bearer_token>
X-Patched-Signature: <hmac-sha256-hex of request body>
X-Patched-Timestamp: <unix seconds>
X-Patched-Nonce: <uuid4 hex, no dashes>
Content-Type: application/json
```

Agents use fire-and-forget with a disk ring-buffer queue (cap 1000). Successful
POST causes the queued file to be deleted; failed POST leaves it for retry on the
next agent cycle.

## Event envelope

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

| Field | Type | Notes |
|---|---|---|
| `event_type` | string | See event types below |
| `tenant_id` | string | Tenant UUID from credentials |
| `device_id` | string | macOS: HW UUID; Windows: machine name |
| `label` | string? | Installomator / allowlist label |
| `version` | string? | Installed or attempted version |
| `verified_signer` | string? | Team ID (macOS) or Authenticode publisher (Windows) when verified |
| `reason` | string? | Failure reason code (see below) |
| `expected` | string? | Expected hash or signer (reserved for PAT-495) |
| `actual` | string? | Observed hash or signer |
| `platform` | string | `"macos"` or `"windows"` |
| `timestamp` | string | ISO 8601 UTC |

## Event types

| event_type | Emitted when |
|---|---|
| `verification_passed` | App verified and already current (no update needed) |
| `verification_failed` | Engine exited 60/61/62 (macOS) or Authenticode check failed (Windows) |
| `install_completed` | App was successfully updated to a new version |
| `install_failed` | Engine exited non-zero (not 60–62) |
| `version_blocked` | A signed `blocked_versions` policy refused the candidate version before installation (PAT-1238) |
| `posture_warning` | `PATCHED_POSTURE_WARNING` — Gatekeeper disabled, SIP disabled, etc. |
| `allowlist_tamper_detected` | Windows: Ed25519 signature on allowlist failed (PAT-511) |

## Failure reason codes

Drawn from `failure_reason` in provenance records (same vocabulary):

| Reason | Meaning |
|---|---|
| `missing_expected_signer` | exit 60 — no Team ID / publisher found |
| `signature_untrusted` | exit 61 — cert chain not trusted |
| `signer_mismatch` | exit 62 — Team ID doesn't match expected |
| `blocked_version` | Signed `blocked_versions` policy refused the candidate version before installation |
| `blocked_version_resolution_failed` | An active block could not be evaluated safely, so installation was refused |
| `engine_rc_<N>` | Non-verification engine error |
| `sig_verification_failed` | Allowlist Ed25519 tamper (Windows, PAT-511) |
| `allowlist_unsigned` | Allowlist has no .sig file (warning only) |

## Platform storage requirements

- **Append-only**: the platform MUST NOT expose a delete or update API for event records. Each event is immutable after receipt. This is the tamper-evidence guarantee — an attacker with root access on the endpoint can delete local logs but cannot retract events already delivered.
- **Idempotency**: the platform SHOULD accept duplicate events (same nonce) gracefully (200 OK, no duplicate stored). Agents may retry on network failure.
- **Retention**: retain events for ≥ 90 days (SOC 2 CC7 evidence window).

## Platform response

```
200 OK
{}
```

or `202 Accepted`. The agent ignores the response body. Any 2xx deletes the queued file; any non-2xx or network error keeps it for retry.

## Agent-side files

| File | Description |
|---|---|
| `windows/src/Shared/Contract/AuditEvent.cs` | Event DTO + event type constants |
| `windows/src/Service/AuditEventShipper.cs` | Ring-buffer + HMAC POST (Windows) |
| `endpoint/patched-update.sh` | `emit_audit_event()` + `drain_events_queue()` (macOS) |

## Queue locations

| Platform | Path |
|---|---|
| macOS | `/var/db/patched/events-queue/evt-<timestamp>-<random>.json` |
| Windows | `%ProgramData%\Patched\events-queue\evt-<timestamp>-<guid>.json` |

Ring-buffer cap: 1000 files. Oldest dropped on overflow (bounded disk use even if the platform is unreachable for extended periods).
