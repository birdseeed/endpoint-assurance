# Endpoint tamper-resistance threat model (PAT-782)

Status: accepted. This is the standing doctrine for how Patched talks about, designs
for, and reports on tampering against the macOS/Windows agent. It does not introduce
new engineering work by itself; it names the principle that PAT-493, PAT-507, PAT-499,
PAT-66, and the dashboard agent-health surface already implement pieces of, and sets
the acceptance bar for what's still missing (dashboard tamper-suspected visibility).

## The principle

> Against local admin/root, the agent is **tamper resistant**, not **tamper proof**.

No endpoint agent, Patched's or anyone else's, can be tamper-proof against a
principal with local admin or root on the machine it runs on. That principal already
has more privilege than the agent does. Claiming otherwise is not a defensible security
position and would not survive a competent customer security review.

The product and security goal is instead:

* detect tampering or loss of agent control, and make that detection visible
* fail closed wherever installation, config, or signature verification is concerned
* report stale, missing, or suspended agents clearly and promptly
* require signed updates and signed/verified config
* make unauthorised modification obvious in the dashboard and in reports
* never claim "impossible to tamper with" in customer-facing material

## Threat model: local admin/root on the endpoint

### What a local admin/root user can do

This is the assumed adversary capability. No control described below is designed to
prevent these actions: they are architecturally out of reach to prevent from
user-space, on an OS Patched does not control via MDM enforcement at Tier 1/2.

* Stop or disable the agent's services, LaunchDaemons (macOS), or scheduled
  tasks/services (Windows).
* Delete the agent binary, its config files, or its local queue/cache.
* Modify local configuration files or registry keys directly on disk.
* Block outbound network access (firewall rule, hosts file, proxy, DNS).
* Remove or overwrite locally stored credentials.
* Suppress, truncate, or rewrite logs that exist only on the local disk.
* Uninstall the agent entirely.

### What a local admin/root user cannot do (given the mitigations already in place)

* Cannot make the agent trust a config that isn't signed by the platform's Ed25519
  key: signature verification happens before any field is trusted (`security.html`
  § Signed agent configuration).
* Cannot roll a device back to an older, weaker config: every config carries a
  monotonically increasing version and older versions are rejected (anti-rollback).
* Cannot elevate an agent's capability tier (scan-only vs. patch mode) by editing
  local files; tier is a property of the signed config, not local state.
* Cannot retroactively erase an audit event that has already reached the platform:
  local queue files can be deleted, but append-only records already ingested
  server-side survive (PAT-499: structured audit log shipping to SIEM closes the
  on-device-log-only gap this depends on).
* Cannot make the agent silently install a binary that fails signature/Team-ID/
  notarisation verification: verification failure aborts the install rather than
  falling back to an unverified path (fail closed; PAT-493).
* Cannot forge a valid agent-config signature or a valid HMAC-signed inventory
  payload without the platform's private key material, which never leaves the
  platform.

### What a local admin/root user can do, and Patched can only detect afterwards

* Stop the agent process/service outright. Undetectable in real time from the
  endpoint's own telemetry, by definition: detection has to come from the absence
  of expected check-ins, observed server-side (see "Stale/missing/suspended
  reporting" below).
* Delete the agent's local audit queue before it's flushed, losing events that were
  generated but never reached the platform. Already-delivered events are unaffected.
* Block network egress, which looks identical server-side to "agent stopped" until
  the block is lifted or the device is otherwise investigated.

The doctrine is explicit that none of the above is a gap to be "fixed"; it's the
correctly-scoped boundary of what a user-space, non-MDM-enforced agent can promise.

## Fail-closed requirements

These already-shipped behaviours are the fail-closed baseline this doctrine expects
every future verification path to match:

* Signature, Team ID/publisher, and notarisation checks: any single gate failing
  aborts the install and leaves the existing version in place. No gate is skippable
  by config, and CI structurally rejects catalogue entries that could skip one
  (empty Team ID, non-HTTPS source URL; PAT-493).
* Agent config: an unsigned, badly-signed, wrong-tenant, or rolled-back config is
  rejected outright rather than partially applied.
* Agent self-update: the update artifact itself must be signed and hash-verified
  before it replaces the running binary (PAT-507). A new agent version that fails
  this check does not get installed.

Any new verification path added to the agent or platform must fail closed in the
same shape: verification failure blocks the action, never "warn and proceed."

## Stale / missing / suspended / tamper-suspected agent reporting

This is the requirement carried forward into dashboard and product acceptance
criteria. PAT-369 (Device & Agent Health screen) shipped check-in freshness,
agent/updater version, and cert/provenance per device, which covers **stale** and
**missing** today. It does not yet have a **tamper-suspected** state, which this
doctrine defines as a new requirement for future dashboard work:

* **Stale**: last successful check-in older than the expected interval, but within
  a grace window. Visible per-device and rolled up at estate level.
* **Missing**: no check-in beyond the grace window. Treated as loss of visibility,
  not assumed compromise, until investigated.
* **Suspended**: credentials revoked from the dashboard (operator-initiated). The
  agent enters suspended state on its next check-in per the revocation design in
  `security.html` § Revocation.
* **Tamper-suspected** *(required, not yet built)*: a distinct dashboard state,
  separate from "missing," raised when there's positive evidence of interference
  rather than mere silence: a verification-failure event received then check-ins
  stop, a device that was reporting patch-mode capability suddenly reporting
  scan-only with no corresponding signed config change, or a gap in the audit event
  sequence number for a device that is otherwise still checking in. "Missing" means
  "we don't know why it stopped talking." "Tamper-suspected" means "we have evidence
  something on this device changed outside the signed-config/verified-install path."
  These must not be collapsed into one state: the operator response differs
  (chase up a laptop vs. investigate a possible compromise).

Acceptance bar for any future dashboard work implementing this: an operator viewing
the estate list must be able to distinguish stale, missing, suspended, and
tamper-suspected without opening individual device detail pages, and tamper-suspected
devices must not silently downgrade to "missing" if the check-in gap closes. The
suspicion has to be explicitly cleared or escalated, not auto-dismissed by a
subsequent check-in.

## Signed update / config requirements

Already-shipped baseline, restated as the standing requirement any new signed-artifact
path must meet:

* Agent config is signed with a platform-held Ed25519 key; the agent pins the public
  key and verifies before trusting any field.
* Agent binary/package updates are code-signed with a dedicated signing certificate,
  independent of the delivery-chain key, with the release SHA-256 published and
  independently verifiable before deployment (PAT-507).
* Both paths carry anti-rollback (config version) or anti-downgrade (published hash
  pinning) protection: an attacker with root cannot force a return to a weaker,
  previously-valid signed artifact.

## Dashboard visibility expectations

* Per-device: check-in freshness, agent/updater version, cert/provenance, and (once
  built) tamper-suspected flag, all visible from the Device & Agent Health screen
  without drilling into raw logs.
* Estate-level: aggregate counts of stale/missing/suspended/tamper-suspected devices,
  so a stale or tampered device doesn't require an operator to already know to look
  for it.
* Verification-failure and posture-warning events (PAT-499) must be queryable
  server-side per device/tenant: this is what distinguishes "tamper-suspected" from
  "missing" and is the evidentiary basis for it.

## Customer-facing wording

Audited every customer-facing HTML page in this repo (`index.html`, `getting-started.html`,
`agent-updater.html`, `protected.html`, `faq.html`, `security.html`, `privacy.html`,
`antivirus.html`) against this doctrine: no page claims tamper-proof, unmodifiable, or
"impossible to tamper with" behaviour. Existing language already uses the correct framing:
"tamper-evident record" (`security.html`) and "an attacker with root on an endpoint can
delete local queue files but cannot erase a record that has already reached the server"
(`security.html` § Event delivery guarantee), which states the resistant-not-proof
boundary precisely and should be the template for any future copy in this space.

Standing copy rule: never write "tamper-proof," "cannot be tampered with" (unqualified),
"unhackable," or "impossible to modify" about the agent or its data on an endpoint.
Prefer "tamper-evident," "tamper-resistant," or a specific claim scoped to what's
actually true (e.g. "cannot erase a record already delivered to the platform").

## Mitigation-to-ticket mapping

| Requirement | Status | Ticket |
|---|---|---|
| Supply-chain verification gates (signature, Team ID, notarisation, hash pinning), fail closed | Done | PAT-493 |
| Agent self-update signing, hash publication, anti-downgrade | Done | PAT-507 |
| Tamper-evident audit trail (events survive local log tampering) | Done | PAT-499 |
| Non-author security review gate before first customer ship | In progress; gate itself is paused pre-production, re-enables before go-live, see root `AGENTS.md` | PAT-66 |
| Stale / missing / suspended agent visibility (dashboard) | Done | PAT-369 |
| Tamper-suspected agent visibility (dashboard), distinct from missing | Not yet built | Tracked as a follow-up under PAT-369's dashboard surface; no ticket filed yet |
| Signed agent config, anti-rollback, tenant isolation, tier-from-signed-config | Done | PAT-493 (security architecture, `security.html`) |
| Customer-facing copy avoids tamper-proof overclaiming | Verified compliant on audit (this doc) | N/A, copy review, no code change needed |

The one open gap this doctrine surfaces, a dedicated tamper-suspected dashboard
state distinct from "missing," is not implemented anywhere today and has no ticket
yet. It should be filed as a follow-up scoped to the Device & Agent Health screen
before it's treated as covered.
