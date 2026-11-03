# Installomator integration — security & architecture review

> **Historical architecture record (PAT-1474/PAT-1481):** The broad
> Installomator execution, mirror, verifier and catalogue-maintenance design
> described below is quarantined and is not current operating policy. In
> particular, Patched performs no scheduled or routine upstream Installomator
> review. This record is retained for its threat model and for evaluating a
> separately approved, bounded PAT-1481 macOS operation; it does not authorise
> the historical design.

**Status:** Draft for review
**Scope:** How Patched.im integrates the forked Installomator into the endpoint
architecture so that third-party application patching is defensible to auditors
and acceptable to heavily regulated clients.
**Audience:** Patched.im team (internal), and — in redacted form — client security
reviewers and auditors.

---

## 1. Purpose

Patched has forked [Installomator](https://github.com/Installomator/Installomator)
into `github.com/Patched-LTD/`. Installomator is a mature open-source zsh script
that installs and updates ~900 macOS applications from each vendor's own
distribution source. We want to use it as the third-party patch-remediation
engine alongside the existing CIS L1 compliance pipeline.

The concern this document answers: **a tool whose entire job is to download
executables from the internet and install them as root is, on its face, exactly
the thing an auditor will challenge.** "Removing man-in-the-middle attacks" is
the headline ask. This review sets out what Installomator's integrity model
actually guarantees, where the genuine residual exposure is, and the concrete
controls that close each gap to a standard a regulated client's security
function will accept.

The short version: Installomator's security does **not** rest on transport
encryption. It rests on verifying the downloaded artifact against Apple's code-
signing PKI *after* download. That is a cryptographic integrity check, and it is
strong — but it has specific failure modes (empty Team IDs, URL-resolution
scraping, tampering of the script/label set in delivery). Each of those is
addressed below with a control. The recommended end-state additionally re-hosts
every approved installer through a single Patched-controlled, logged chokepoint,
which removes the vendor-URL attack surface from the endpoint entirely.

---

## 2. How Installomator's integrity model actually works

For each application, Installomator has a **label** — a `case` entry defining:

- `name` — the application name
- `type` — package format (`dmg`, `pkg`, `zip`, `appInDmgInZip`, …)
- `downloadURL` — either a static URL, or one *computed at run time* by
  `curl`-ing a vendor appcast / API / redirect to resolve "the latest version"
- `appNewVersion` — the version string used for the up-to-date comparison
- `expectedTeamID` — the 10-character Apple Developer Team ID the artifact must
  be signed by
- `blockingProcesses` — running apps that must be quit before install

The install flow, reduced to its security-relevant steps:

1. Resolve `downloadURL` (static, or scraped from a vendor source).
2. Download the artifact over HTTPS with `curl`.
3. **Verify the downloaded artifact's Apple code signature and confirm the
   signing Team ID equals `expectedTeamID`.** For a `.pkg`, this is the package
   signing identity; for an `.app`, the application signature.
4. Optionally assess notarization (`spctl`).
5. If verification passes, install (to `/Applications`, as root).
6. If verification fails, discard and abort — nothing is installed.

**This is the load-bearing control.** Step 3 is a check against Apple's signing
certificate chain. An attacker who tampers with the download — by any means,
including a successful network MITM — produces an artifact that either is
unsigned, is signed by a different Team ID, or has a broken signature. All three
fail step 3 and are discarded. To defeat it, an attacker would need a binary
validly signed by the *legitimate vendor's* Apple Team ID, which means
compromising the vendor's Apple Developer signing identity — a different and far
higher bar than network interception.

### Why "is it MITM-safe?" is the wrong first question

TLS on the download (`https://`) protects against passive interception and
against an active attacker who lacks a valid certificate for the vendor domain.
That is real but it is **not** what makes Installomator safe — TLS-terminating
proxies, compromised CDNs, and DNS hijacks all exist inside the TLS boundary.

The correct framing for an auditor is: *integrity of the installed artifact is
verified cryptographically against Apple's PKI, independently of the transport.*
Transport security is defence-in-depth on top of that, not the primary control.
Stated that way, the model is straightforwardly defensible — and it lets us be
precise about the **three** places where that guarantee genuinely weakens, each
of which gets a control in §4.

---

## 3. Threat model

Assets: the client's Mac estate (each endpoint installs as root); the integrity
of the Patched control plane; the audit record we present to regulators.

Adversaries and the exposure we care about:

| # | Threat | Does Team ID verification stop it? |
|---|---|---|
| T1 | Passive network eavesdropper on the download path | Yes (TLS) and Yes (Team ID) |
| T2 | Active network MITM with a forged/mis-issued cert for the vendor domain | Yes — tampered artifact fails Team ID check |
| T3 | Compromised vendor CDN / mirror serving a malicious binary | Yes — fails Team ID check |
| T4 | **Label with empty/missing `expectedTeamID`** | **No — verification is effectively skipped** |
| T5 | **Tampering of the run-time URL-resolution step** (poisoned appcast / API response redirecting `downloadURL`) | Partially — a malicious binary still fails the Team ID check, *unless* combined with T4 |
| T6 | **Tampering of the Installomator script or label set in delivery** to the endpoint | No — this *is* the trusted code; if it is tampered, the Team ID check itself can be removed |
| T7 | Compromise of the vendor's own Apple signing identity | No — out of scope for any downloader; relies on Apple revocation |
| T8 | Local unprivileged user triggers/abuses the update mechanism | N/A — addressed by the privilege model in §5 |

T1–T3 are already handled by the model in §2. **T4, T5 and T6 are the real
work** and are the focus of §4. T7 is a residual risk shared by every patching
tool on the market (including Apple's own) and is documented as such in §7.

Beyond the per-install controls, the continuous verification agent (§4.9)
provides **detection**: a Team ID change, a download-host change, or a
signature/notarization regression on any allowlisted label — the observable
fingerprints of T2, T3, T5 and T7 — is surfaced within 24 hours, independently
of whether an endpoint happened to attempt an install.

---

## 4. Controls

### 4.1 Hard fork — Patched owns the engine

Patched takes the Installomator fork as a *starting point* and hard-forks it
into a Patched-owned update engine. Patched does **not** track upstream `main`
and does not merge from upstream.

- The engine is Patched's own codebase. It lives in the `updater` repo
  (`engine/`), alongside the endpoint wrapper and the menu bar app — hard-forking
  removes the reason to keep a separate, upstream-mergeable fork repo.
- Endpoints run a **specific reviewed, tagged commit** (`engine-vYYYYMMDD`),
  never a moving branch — the pinning discipline is unchanged, and matches the
  macOS agent: deployed code is a reviewed, tagged artifact.
- **Labels become data, not code.** Upstream's ~900-entry `case` statement is
  restructured into a structured label manifest (one record per app: name,
  type, url-resolution method, `expectedTeamID`, app path). This matches the
  platform's existing *rules-are-data* convention and lets the allowlist, the
  CI checks (§4.2) and the verification agent (§4.9) all operate on structured
  records rather than parsing shell.

The cost of a hard fork is real: Patched no longer inherits upstream's community
label maintenance, and vendor download URLs and Team IDs change constantly, so
labels rot. **That maintenance function is replaced by the continuous
verification agent in §4.9.** Upstream Installomator is not abandoned as a
*reference* — the agent diffs the public upstream label set daily as one input
signal among others. What changes is that upstream is consulted as data, never
merged as code.

### 4.2 Curate a label allowlist — do not ship all ~900 labels

Endpoints receive only an **allowlist** of labels for applications actually in
client fleets (`endpoint/labels-allowlist.txt`). Every label on the allowlist is
reviewed and must satisfy:

- `expectedTeamID` is **present and non-empty** (this is what closes T4).
- `downloadURL` is `https://`.
- The URL-resolution method is recorded as either *static* or *scraped*; scraped
  labels are flagged for the extra control in §4.3.
- The vendor and Team ID are confirmed against Apple's records.

A CI check on the fork **fails the build if any allowlisted label has an empty
`expectedTeamID`** or a non-HTTPS URL. This makes T4 unrepresentable in a
shipped configuration rather than a thing a reviewer has to remember.

### 4.3 Fail closed on verification

Patch the fork so that verification is **mandatory and fail-closed**:

- An empty `expectedTeamID` is a hard error, not a skipped step. (Upstream
  treats an empty value as "skip verification"; we remove that path.)
- A failed signature or Team ID mismatch aborts the run for that app and emits a
  provenance record marked `verification_failed` (see §4.6) — it is never
  silently retried against a different URL.
- Notarization assessment (`spctl`) is required for every install, not optional.

This is a small, well-contained diff to the fork and is the single highest-value
change. It converts "the script usually verifies" into "the script cannot
install anything it has not verified."

### 4.4 Internal mirror — the recommended end-state (closes T5)

The strongest answer to T5, and the one regulated clients respond to best, is to
**remove vendor URLs from the endpoint entirely.**

A Patched-controlled **verification-and-mirror pipeline** runs on our
infrastructure (not on client endpoints):

1. For each allowlisted app, the pipeline resolves and downloads the installer
   *once*, centrally.
2. It verifies the Apple Team ID + notarization, and records the **SHA-256** of
   the exact bytes.
3. It re-hosts the verified artifact on Patched-controlled storage
   (Cloudflare R2 — already in use for platform backups), behind `https://`.
4. It publishes a signed **manifest**: app, version, mirror URL, SHA-256,
   verified Team ID, verification timestamp.

Endpoints then run Installomator pointed at the **mirror URL**, and re-check the
**pinned SHA-256** from the manifest in addition to the Team ID check. The
endpoint's supply chain collapses to: one Patched-controlled HTTPS origin + a
Patched-pinned content hash + Apple's Team ID check.

Effect on the threat model:

- T5 (appcast/redirect poisoning) is **removed from the endpoint** — endpoints
  never resolve a vendor URL. The scraping step still exists, but only once,
  centrally, on a hardened box, where its output is logged and the result is
  hash-pinned before any endpoint sees it.
- The endpoint's egress allowlist becomes **a single domain** (§4.7), which is
  itself a strong, easily-audited control.

Trade-offs, stated honestly:

- **Redistribution licensing.** Some vendors' EULAs permit redistribution;
  some do not. Each app must be checked before it goes on the mirror. Where
  redistribution is not permitted, that app stays on the direct-download path
  with §4.1–4.3 + §4.5 applied, and that exception is documented per-app.
- **Freshness / operational burden.** The mirror must track vendor releases.
  This is automatable but is a real running cost and a new thing to monitor.

Recommendation: build the mirror for the high-value, redistribution-permitted
apps first; keep the rest on the hardened direct path. The mix is a per-app
decision recorded in the allowlist.

### 4.5 Integrity of script + label delivery (closes T6)

The Installomator script and the label allowlist are the trusted computing base.
If they are tampered in delivery, every other control is moot.

- The endpoint bundle (script + allowlist + wrapper) ships with a **manifest of
  SHA-256 hashes**. The wrapper verifies every component against the manifest
  *before* executing anything; a mismatch aborts and reports.
- The manifest hash itself is pinned in the Intune deployment configuration, so
  the chain of trust is rooted in the MDM channel.
- Intune delivery is over TLS and the Mac's MDM trust relationship — the same
  trusted channel already relied on for `patched-collect.sh`.
- **v2, gated on incorporation:** once Patched.im Ltd. holds an Apple Developer
  ID, the endpoint bundle ships as a **signed, notarized `.pkg`**. This mirrors
  the macOS agent's already-documented v1→v2 roadmap exactly — same gate, same
  packaging change, no rework.

### 4.6 Provenance logging — turn every install into an audit record

Every update action emits a structured **provenance record** and POSTs it to the
ingestion API, reusing the existing bearer + HMAC-SHA256 auth and the
file-queue/retry pattern of `patched-upload.sh`. Each record carries:

- device HW UUID + tenant ID
- app label, from-version → to-version
- the exact source URL used
- `expectedTeamID`, and the **observed** Team ID
- SHA-256 of the downloaded artifact (and, in mirror mode, the manifest hash it
  was checked against)
- notarization assessment result
- outcome: `installed` / `already_current` / `verification_failed` / `error`
- UTC timestamp, Installomator fork tag

Stored in `raw_payloads`, this becomes an **immutable, queryable audit trail**.
It directly answers the questions an auditor asks: *"Show every third-party
install on this estate last quarter, and prove each one was a genuine,
vendor-signed, notarized binary."* It also closes the loop with the dashboard's
existing CVE scanner — a CVE finding can be tied to the exact remediation event
that resolved it.

This is the control that turns Installomator from "a thing we have to defend"
into "a thing that *produces* audit evidence."

### 4.7 Endpoint egress allowlist

Regulated clients frequently want endpoints restricted to a known set of
outbound destinations.

- **With the mirror (§4.4):** the allowlist is effectively one domain (the
  Patched R2 origin) plus the ingestion API. This is trivial to state and audit.
- **Without the mirror:** Patched publishes the list of vendor domains the
  approved label set reaches, derived mechanically from the allowlist, so the
  client can configure their egress filtering precisely.

### 4.8 Privilege model

See §5 — the menu bar app must never execute the update engine itself.

### 4.9 Continuous vendor-source verification (the daily agent)

Hard-forking the engine (§4.1) means Patched owns label maintenance outright.
The mechanism that discharges that responsibility — and simultaneously turns the
supply chain into a *monitored* one — is a **daily verification agent** that runs
on Patched infrastructure, not on client endpoints.

**What it does, once per day, for every label on the allowlist:**

1. Resolves the download URL — static, or by running the label's url-resolution
   logic (the scraped-appcast step from T5), in a controlled, logged environment.
2. Downloads the artifact and verifies it exactly as an endpoint would: Apple
   code signature valid, signing Team ID equals the recorded `expectedTeamID`,
   notarization assessment (`spctl`) passes.
3. Extracts the version and computes the SHA-256.
4. Records the full result, and **diffs it against the previous day**: did the
   resolved URL change? the download host? the Team ID? the version? did the
   redirect chain or the TLS issuer change? did signature or notarization
   regress?
5. **Classifies** each label:
   - `ok` — unchanged, still verifies.
   - `new-version` — version bumped, everything else still verifies. Benign;
     this is the routine case and the trigger for a label-version update.
   - `alert` — a security-relevant change: Team ID changed, download host
     changed, signature or notarization failed, or the URL went non-HTTPS.
6. Emits a daily report; `alert` rows page a human.

**Authority — propose, never apply.** The agent does not edit labels or the
allowlist directly. On a broken URL it investigates the vendor's site to *find*
a candidate replacement; on a Team ID change it researches whether the vendor
legitimately re-organised their Apple Developer account. In every case it
**opens a PR / Linear issue with its findings for human review** — Andy approves
and merges. This matters: an agent that auto-rewrites download URLs would itself
become an injection vector if a vendor page were compromised. The deterministic
checks (signature, Team ID, notarization, hash) are what *gate*; the agent does
discovery and triage. As one input among others it also diffs the public
upstream Installomator label set daily (§4.1).

**Why this strengthens the auditor story.** It converts the §4 controls from a
point-in-time review into a *continuous* control: Patched re-verifies the entire
third-party supply chain every 24 hours, and the daily report is a dated,
retained attestation. "Show me that every download source you trust still serves
a genuine, vendor-signed, notarized artifact" becomes answerable for *any* day,
not just deployment day.

**Where it runs.** Authoritative `codesign` / `spctl` verification requires
macOS, so the agent runs on a macOS runner (a scheduled GitHub Actions macOS
job is the cheapest path; the Linux VPSes cannot do this check authoritatively).
The agent is also ~90% of the Phase 2 mirror pipeline (§4.4) — *download →
verify → hash* — so building it first makes the mirror a small addition
(*re-host + publish manifest*).

---

## 5. Privilege & execution model

Installomator installs into `/Applications` and therefore must run as **root**.
The client-facing menu bar app ("the skin") runs as the **logged-in user** and
must never be granted that privilege. The two are separated as follows:

```
  ┌─────────────────────────┐      reads (read-only)      ┌──────────────────────┐
  │  Menu bar app  (user)   │ ──────────────────────────▶ │  update-status.json  │
  │  PatchedUpdater.app     │                             │  (world-readable)    │
  │                         │ ── writes trigger file ──▶  └──────────────────────┘
  └─────────────────────────┘            │                          ▲
                                         ▼                           │ writes
                              ┌────────────────────────┐              │
                              │  trigger dir (mode 1733)│              │
                              └────────────────────────┘              │
                                         │ WatchPaths                  │
                                         ▼                             │
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  LaunchDaemon  com.patched.update   (root)                               │
  │  patched-update.sh → Installomator (verified) → writes status → POSTs     │
  │  provenance to api.patched.im                                            │
  │  runs on: StartCalendarInterval (admin-scheduled)  +  WatchPaths (trigger)│
  └──────────────────────────────────────────────────────────────────────────┘
```

- The **LaunchDaemon** (root) is the only thing that runs Installomator. It runs
  on a schedule (admin-controlled) **and** when a trigger file appears.
- The **menu bar app** (user) only ever (a) *reads* `update-status.json` to show
  state, and (b) *writes a trigger file* to request a run. It holds no privilege.
- The **trigger directory** is mode `1733` (sticky, like `/tmp`): any user can
  drop a request but cannot read or delete others'. The daemon validates and
  consumes triggers.

This satisfies the **admin-scheduled + self-service** model: admins own the
schedule; users can ask for an on-demand run via the menu bar.

**Residual risk T8, stated honestly.** A local user can drop a trigger file and
cause an update run. The blast radius is intentionally tiny: the daemon only
ever installs apps from the reviewed allowlist, each still subject to the full
Team ID + hash verification — the worst a malicious local trigger achieves is a
self-inflicted denial of service (repeated runs). The wrapper additionally
rate-limits trigger-initiated runs. **v2 upgrade:** once signed, the trigger
mechanism is replaced by a signed privileged helper using `SMAppService` + XPC,
which authenticates the calling app by code signature and removes T8 entirely.

---

## 6. Implementation phases

**Phase 1 — Hardened direct-download path (no mirror).**
Hard-fork the engine and restructure labels as data (§4.1); label allowlist with
CI enforcement (§4.2); fail-closed verification (§4.3); bundle hash-manifest
(§4.5); provenance logging (§4.6); LaunchDaemon + trigger model (§5); menu bar
app reads status. This phase alone is defensible — every installed artifact is
cryptographically verified and every install is logged.

**Phase 1b — Continuous verification agent.**
Stand up the daily vendor-source verification agent (§4.9) on a macOS runner.
Best built alongside Phase 1: it is what discharges label maintenance after the
hard fork, and it is ~90% of the Phase 2 mirror pipeline. From this point the
supply chain is monitored, not just verified at install time.

**Phase 2 — Internal mirror.**
Stand up the central verification-and-mirror pipeline (§4.4) for the
redistribution-permitted subset of the allowlist; switch those endpoints to
mirror URLs + hash pinning; collapse the egress allowlist (§4.7).

**Phase 3 — Signing (gated on incorporation).**
Signed, notarized `.pkg` for the endpoint bundle; replace the trigger directory
with a signed `SMAppService` privileged helper + XPC (removes T8). Tracks the
existing macOS-agent v1→v2 signing gate — no extra incorporation dependency.

---

## 7. Residual risks

- **T7 — vendor signing-identity compromise.** If a vendor's own Apple Developer
  identity is compromised, a malicious binary would carry a valid Team ID and
  pass verification. This is unsolvable by any downloader and is shared by Apple's
  own update mechanisms. Mitigations: Apple certificate revocation (automatic via
  notarization checks), and the provenance log, which makes the blast radius of
  any later-discovered bad version fully enumerable across the estate.
- **Mirror freshness.** In Phase 2, a mis-monitored mirror could leave endpoints
  on an outdated version. Mitigation: alerting on mirror-vs-vendor version drift;
  the provenance log surfaces stale fleets.
- **T8 (pre-v2).** Documented and bounded in §5; fully closed in Phase 3.
- **Allowlist review quality.** The model depends on the human review of label
  diffs (§4.1) and the per-app redistribution check (§4.4). This is a process
  control and should be assigned an explicit owner.

---

## 8. Auditor-facing summary

> Patched.im patches third-party macOS applications using a Patched-owned update
> engine, hard-forked from the open-source Installomator project and maintained
> in-house. Installed artifacts are verified cryptographically against Apple's
> code-signing PKI (Developer Team ID match + notarization) **after** download
> and before installation; this verification is mandatory and fail-closed.
> Transport security (TLS) is defence-in-depth on top of that check, not the
> primary control. A verification agent independently re-checks every trusted
> vendor download source **daily**, producing a dated attestation that each
> still serves a genuine, signed, notarized artifact and surfacing any change
> within 24 hours. In the target architecture, installers are additionally
> re-hosted and content-hash-pinned through a single Patched-controlled, logged
> origin, removing third-party download endpoints from client devices. Every
> install produces an immutable, authenticated provenance record (app, versions,
> source, verified Team ID, artifact hash, outcome), giving a complete and
> queryable audit trail of third-party software change across the estate.

---

## 9. Open decisions for the team

1. **Mirror scope** — which apps go on the Phase 2 mirror first (function of
   estate prevalence × redistribution licensing).
2. **Provenance transport** — new `/v1/provenance` route, or a typed payload on
   the existing `/v1/inventory` ingestion path.
3. **Schedule policy** — is the admin update schedule global, per-tenant, or
   per-device? (Suggest per-tenant, consistent with `tenant_rules`.)
4. **Repo home — decided.** A single `github.com/Patched-LTD/updater` repo holds
   the hard-forked engine (`engine/`), the endpoint wrapper, the menu bar app,
   and the verification agent (`verifier/`). Hard-forking the engine (§4.1)
   removes the earlier reason to keep a separate, upstream-mergeable fork repo.
5. **Verification-agent runner** — confirm the macOS runner choice for §4.9
   (scheduled GitHub Actions macOS job vs. a dedicated Mac). GitHub Actions is
   the suggested starting point.
