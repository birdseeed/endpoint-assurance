# Incident Response Runbook — Compromised or Broken Agent-Managed App Version

**Scope:** A known-bad version of an Installomator/winget-managed app has been distributed
to endpoints. The kill switch is `blocked_versions` in the signed per-tenant `agent-config`.

---

## 1. Detection

Signals that trigger this runbook:

| Source | Signal |
|---|---|
| Verifier (PAT-52) | Daily scan flags an unexpected publisher, hash mismatch, or revoked Team ID for a label |
| SIEM / audit events | `verification_failed` or `version_blocked` events from `/v1/events` for a label + version |
| Vendor advisory | CVE or supply-chain compromise affecting a specific version of a managed app |
| `PATCHED_VERIFICATION_FAILED` log | macOS endpoint log line with `reason=blocked_version` |

Once a bad version is confirmed, proceed immediately to containment.

---

## 2. Containment — push `blocked_versions`

### 2a. Build the revocation config

```jsonc
{
  "blocked_versions": {
    "<label>": ["<bad-version>"]
  }
}
```

Example: Chrome 125.0.6422.60 distributed via the supply chain with a modified binary:

```json
{
  "blocked_versions": {
    "googlechrome": ["125.0.6422.60"]
  }
}
```

Multiple labels / versions are supported:

```json
{
  "blocked_versions": {
    "googlechrome": ["125.0.6422.60", "125.0.6422.61"],
    "slack":        ["4.38.125"]
  }
}
```

### 2b. Sign and publish via the platform

The `agent-config` response is Ed25519-signed by the platform on every delivery.
Update the blocked_versions field in the platform's tenant config DB — the signing
layer picks it up on the next config delivery.

**No agent release is required.** The kill switch takes effect on the next agent run
(default: every 24 hours) or when an admin triggers a scan from Self Service.

### 2c. Verify propagation

After the signed config is live, query the SIEM for `version_blocked` events:

```sql
-- Sumo / BigQuery / equivalent
SELECT device_id, label, version, timestamp
FROM audit_events
WHERE event_type = 'version_blocked'
  AND label      = '<label>'
  AND version    = '<bad-version>'
ORDER BY timestamp DESC
```

macOS endpoints also emit `PATCHED_VERIFICATION_FAILED ... reason=blocked_version` to
system log; these are searchable in the MDM log-collection pipeline.

---

## 3. Scope assessment

Determine how many devices received the bad version:

1. Query `/v1/inventory` (or the inventory DB) for `label=<label>` and `installed_version=<bad-version>`.
2. Cross-reference with `version_blocked` audit events — devices that have checked in
   since the config was pushed should already be generating these events.
3. Devices that have not checked in in > 48 h may still have the bad version installed
   without having seen the revocation config. Flag for manual follow-up.

---

## 4. Remediation

### 4a. Automatic path (preferred — where available)

If the label's vendor has issued a clean follow-on version:

1. Add the bad version to `blocked_versions` (step 2 above) — this prevents any
   device on the bad version from being considered "up to date."
2. Push the clean version via the normal agent update flow. On the next agent run,
   each affected device will:
   - See the installed version is blocked → outcome `version_blocked`
   - Detect a newer (clean) version is available → update to it
   - Record a clean `install_completed` audit event

The agent never force-removes the bad version; it relies on Installomator / winget
upgrading over it. If the bad version has a different bundle ID or prevents upgrade,
use the manual path.

### 4b. Manual path (fallback)

If no clean version is available yet, or the bad version blocks automated update:

1. Push an MDM script to uninstall the specific version from affected devices.
2. For macOS: `sudo rm -rf /Applications/<App>.app` + run `patched-update.sh` in
   install mode to reinstall from a known-good version if one is pinned.
3. For Windows: `winget uninstall --id <winget-id>` via MDM script; then allow the
   agent to reinstall.
4. After remediation, verify `install_completed` + `verification_passed` events appear
   in SIEM for each device.

### 4c. If the vendor key / Team ID was compromised

Escalate: a compromised signing key requires updating `expected_team_id` in the label
manifest and is a higher-severity event (see `docs/signing-key-runbook.md` for the
emergency rotation procedure).

---

## 5. Version refusal on both platforms

Both agents check a signed `blocked_versions` policy before installing the candidate
artifact. On macOS, the wrapper reads `latest_verified_version` and `sha256` together
from the local signature-verified catalogue before invoking Installomator. If that
version is blocked, the wrapper emits `PATCHED_VERIFICATION_FAILED`, records
`version_blocked`, and ships a `version_blocked` audit event without downloading or
installing. It does not re-resolve the version from the vendor: vendor drift after the
catalogue was verified is refused by the paired SHA-256 pin during Installomator.

If an active policy cannot be evaluated safely, macOS refuses installation with
`blocked_version_resolution_failed` rather than bypassing the kill switch. Windows
continues to check its locally resolved candidate before handing it to winget.

**Release ordering:** apply the platform migration that accepts
`event_type="version_blocked"` before releasing an agent build that emits it. Do not
enable the endpoint rollout until the migration is recorded and a signed test event
is accepted: otherwise a correct refusal can be lost behind the server's older closed
event-type constraint. The install gate itself remains fail-closed; the durable audit
queue retries evidence delivery independently if the endpoint is temporarily unavailable.

Push the revocation config as soon as the bad version is confirmed, before the next
scheduled endpoint run. Devices that already received the version remain in scope for
remediation, but no newly evaluated candidate matching the block is installed.

---

## 6. Lifting the block

Once all affected devices are remediated and a clean version is confirmed:

1. Remove the bad version from `blocked_versions` in the tenant config.
2. Confirm via SIEM that no new `version_blocked` events appear for that label/version
   over a 24-hour window.
3. Document the incident: label, bad version, date range, device count, root cause,
   resolution. File in the post-incident log.

---

## 7. Quick reference

| Action | Where |
|---|---|
| Push `blocked_versions` | Platform tenant config → agent-config delivery |
| Query affected devices | `/v1/inventory` DB + SIEM `version_blocked` events |
| Confirm revocation live | SIEM `version_blocked` events, macOS `PATCHED_VERIFICATION_FAILED` log |
| Manual uninstall (macOS) | MDM script: `sudo rm -rf /Applications/<App>.app` |
| Manual uninstall (Windows) | MDM script: `winget uninstall --id <winget-id>` |
| Lift block | Remove version from `blocked_versions` in tenant config |
| Key compromise escalation | `docs/signing-key-runbook.md` |
