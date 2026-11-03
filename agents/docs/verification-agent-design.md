# Verification agent — design

> **Operating status (PAT-1474/PAT-1481): quarantined.** The scheduled vendor
> verifier, signed-catalogue publication, package mirrors, upstream label
> maintenance and automatic smoke-test fan-out are disabled. Selected legacy
> diagnostics remain manual and artifact-only for compatibility or incident
> diagnosis, without signing, publishing, verifier-state writes or alert
> creation. The former upstream-review workflow was deleted: neither a schedule
> nor a manual dispatch may create an Installomator maintenance issue. The
> sections below document the preserved security model and historical scheduled
> design; they are not the vNext operating model.

> **Retired 2026-09-30 (PAT-2304).** The agent itself (`verifier/verify.py`),
> its tests and the mirror pipelines are deleted. This document is history
> only. The last code is at commit `f852810b`. PAT-2308 then deleted the
> smoke-test and behavioral-analysis workflows and their scripts, plus
> `verifier/alerting.py` and the baselines and state files `verify.py` read.

**Status:** Draft for review
**Companion to:** `installomator-security-review.md` §4.9
**Scope:** The daily agent that verifies every vendor download source behind the
Patched update engine.

---

## 1. Why this exists

Hard-forking the update engine (security review §4.1) means Patched no longer
inherits the upstream Installomator community's ongoing label maintenance.
Vendor download URLs, versions and — occasionally — Apple Team IDs change
constantly. Without a replacement, the forked label set rots: URLs 404, versions
fall behind, and a Team ID change goes unnoticed.

The verification agent is that replacement. It does two jobs at once:

1. **Maintenance** — it detects when a label has fallen out of date (new
   version, moved URL) and proposes the fix.
2. **Security monitoring** — it independently re-verifies, every day, that each
   trusted download source still serves a genuine, vendor-signed, notarized
   artifact, and surfaces any security-relevant change within 24 hours.

Job 2 is the one that matters to auditors: it converts the review's §4 controls
from a point-in-time review into a *continuous* control with a dated, retained
attestation.

## 2. What it is not

- It is **not** on the client endpoint. It runs on Patched infrastructure.
- It does **not** install anything anywhere.
- It does **not** auto-edit labels or the allowlist. It proposes; a human
  approves (§5).
- It is **not** the authority on artifact integrity at install time — the
  endpoint's own Team ID + notarization check is. The agent is an *early
  warning* and a *maintenance* system layered on top.

## 3. Inputs

- **The label allowlist** (`endpoint/labels-allowlist.txt`, and the structured
  label manifest the hard-forked engine uses) — the set of labels to verify.
- **Yesterday's verification state** — a per-label record from the previous run,
  used to compute the daily diff.
- **The public upstream Installomator label set** — pulled and diffed daily as
  *one input signal among others* (review §4.1). Upstream is consulted as data,
  never merged as code.

## 4. The daily run

For each label on the allowlist, the agent performs a deterministic check
followed, only where needed, by agentic investigation.

### 4.1 Deterministic checks (every label, every day)

1. **Resolve the download URL.** Static URLs are taken as-is. "Latest"-style
   labels resolve their URL by running the label's url-resolution logic (the
   scraped-appcast / API / redirect step — threat T5) inside the controlled,
   logged agent environment.
2. **Fetch.** Record the final URL after redirects, the redirect chain, the
   download host, the HTTP status, the TLS certificate issuer, and the
   `Content-Type`. Flag any non-HTTPS hop.
3. **Download** the artifact (full, or a ranged sample sufficient for the
   signature check).
4. **Verify** exactly as an endpoint would: Apple code signature valid; signing
   Team ID equals the recorded `expectedTeamID`; notarization assessment
   (`spctl`) passes.
5. **Extract** the artifact version and compute its SHA-256.

### 4.2 The daily diff

The agent compares the result against yesterday's state for that label:

| Field | A change means |
|---|---|
| resolved URL / download host | the source moved — benign re-host, or hijack |
| Team ID | the signing identity changed — vendor re-org, or compromise |
| version | a new release — the routine, expected case |
| SHA-256 (same version) | the *same version* changed bytes — never expected; suspicious |
| signature / notarization result | regression — broken signing, or tampering |
| TLS issuer / redirect chain | transport path changed — usually benign, worth noting |

### 4.3 Classification

Each label is classified into exactly one bucket:

- **`ok`** — nothing changed, still verifies. No action.
- **`new-version`** — the version bumped and *everything else still verifies*
  (URL host, Team ID, signature, notarization all consistent). Benign; this is
  the routine case and the trigger for a label-version update proposal.
- **`advisory`** — informational only, never paged. Added 2026-07 after the
  cross-source hash check (PAT-502) produced a 4-in-7 false-alarm rate on the
  allowlisted set: a vendor's rolling "latest" URL's bytes change on every
  release, so they can never durably agree with a cross-source (e.g. a
  Homebrew cask hash) that tracks one pinned version. A cross-source hash
  mismatch is `advisory`, not `alert`, when the signing identity
  independently verified (Team ID match **and** notarization pass) — still
  recorded per-label in the report, but excluded from alerting and from the
  process exit code.
- **`alert`** — a security-relevant change: Team ID changed, download host
  changed, signature or notarization **failed**, the URL went non-HTTPS, the
  bytes of an unchanged version changed, or a cross-source hash mismatch
  where the signing identity did **not** independently verify (an
  unconfirmed identity plus disagreeing bytes is genuinely suspicious).
  Every `alert` is triaged and paged.

### 4.4 Run failure and catalogue publication are separate signals

The scheduled run remains red for any integrity or resolution alert, a
verification-error outage, a coverage-baseline failure, or a label-presence
failure. Those failures remain visible in the retained report and use the
red workflow signal; coverage regressions also retain their existing Linear
alerting path.

Catalogue publication is narrower. It blocks on an integrity-class alert, an
infra-wide verification-error outage, or when the newly emitted verified label
set is empty or retains less than the configured fraction of the previously
published set. Coverage and label-presence failures do not block publication by
themselves: they describe missing management coverage, not untrustworthy bytes
in an emitted entry. The shrink floor measures the actual endpoint impact and
still prevents a badly reduced catalogue from replacing the last good one.

This means a run may correctly finish red while signing and publishing a fresh
catalogue containing only entries that verified. Missing, malformed or absent
publication-decision output still fails closed because every workflow consumer
requires the explicit `publication_blocked == 'false'` result.

## 5. Authority — propose, never apply

This is the load-bearing design decision.

The agent **never edits a label, the allowlist, or the engine directly.** Its
only outputs are a report and a proposal:

- On a `new-version`, it opens a **PR** against the `updater` repo bumping the
  label's version metadata, with the verified evidence attached (resolved URL,
  Team ID, notarization result, SHA-256).
- On a broken URL, it **investigates** — fetches the vendor's downloads / release
  page — to find a *candidate* replacement URL, and opens a PR / Linear issue
  with the candidate and its reasoning. It does not adopt the candidate itself.
- On an `alert`, it opens a **Linear issue** in team PAT, label `supply-chain`
  (created at runtime via the API if it doesn't already exist yet), and exits
  non-zero so a scheduled runner pages. One issue per alerting label, per
  distinct finding: the issue body carries the label, what changed, expected
  vs observed (Team ID / signer, notarization result), the vendor URL, and
  the workflow run URL. If an open issue already exists for that label and
  that exact finding, the agent comments on it instead of opening a
  duplicate — see §7 for the mechanics. It does not yet establish *why* a
  change happened (vendor announcements, upstream label history); that
  triage is still a human step after the issue lands.

A human (Andy) reviews and merges. The reason is not bureaucracy: an agent that
auto-rewrites download URLs would itself become an injection vector — feed a
compromised vendor page a plausible-looking malicious URL and the agent would
"helpfully" adopt it. The deterministic checks in §4.1 are what *gate* a change
into the trusted set; the agent does **discovery and triage**, and a human makes
the trust decision. A future relaxation — auto-merging *pure* `new-version`
bumps where Team ID, signature and notarization are all unchanged — is
defensible, but propose-only is the correct starting posture.

## 6. Where the agentic reasoning earns its place

Most of §4 is deterministic and a plain script could do it. The agent adds value
specifically at the judgement steps:

- **URL rediscovery.** When a URL breaks, finding the new one means reading a
  vendor's site the way a person would. This is exactly the label-maintenance
  labour the upstream community used to absorb.
- **Benign-vs-suspicious triage.** A Team ID change is sometimes a legitimate
  vendor re-organisation and sometimes an incident. Pulling together vendor
  announcements, release notes and upstream's own label history to brief a human
  is judgement work.
- **Upstream diff interpretation.** Deciding whether an upstream label change is
  worth surfacing as a proposal is a classification task, not a string compare.

Everything security-critical stays deterministic and stays gated by a human.

## 7. Output

- **Daily report** — every label, its classification, and the evidence. Retained
  (this *is* the auditor-facing attestation). A natural fit for a live artifact
  / dashboard surface so the team and, in redacted form, a client reviewer can
  see current supply-chain state.
- **PRs** — version bumps and candidate URL fixes, evidence attached. Not yet
  implemented (§11, "later").
- **Linear issues + paging** — for every `alert` (PAT-912, implemented). The
  process exit code (non-zero on any alert) remains the primary failure
  signal a scheduled runner pages on; the Linear issue is additional,
  human-visible signal on top of it, not a replacement.

  **Idempotency.** A "finding" is a label plus the set of `changes` strings
  `classify()` attached to the alert (Team ID mismatch, host change,
  notarization failure, etc — §4.2/§4.3). The agent embeds a fingerprint of
  that pair as an HTML-comment marker in the issue description. Before
  opening an issue it searches team PAT's open issues carrying the
  `supply-chain` label for that marker: found, it comments on the existing
  issue instead of filing a duplicate; not found, it opens a new one. A
  *different* finding on the same label (e.g. yesterday's Team ID mismatch
  becomes today's notarization failure) has a different fingerprint and
  opens a new issue — it is a different problem, not a duplicate of the
  first.

  **Auth and gating.** The agent authenticates to the Linear GraphQL API
  with the `LINEAR_API_TOKEN` secret via a small stdlib-only client
  (`verifier/linear_client.py` — no SDK dependency). If the token is
  missing, alerting is skipped with a loud warning and the exit code is
  unaffected; the canonical scheduled workflow run additionally hard-fails
  in that case (a separate CI step, not `verify.py` itself), so a missing
  secret can never let a real alert pass through silently unnoticed. A
  `workflow_dispatch` or PR-context run degrades gracefully instead — see
  `.github/workflows/daily-vendor-verify.yml`.
- **State store** — the per-label record that seeds tomorrow's diff.

  **Verified-catalogue omission contract.** The signed catalogue contains only
  labels verified by the current run. An `alert`, `verification-error`, or
  `unsupported` result is omitted even if yesterday's catalogue had a valid
  entry for that label. This is deliberate fail-closed behaviour, including
  resolution-class alerts that do not block publication. Neither endpoint
  consumer understands signed per-label stale state. On macOS, a present valid
  hash pin is an install prerequisite alongside catalogue freshness, tier,
  policy, ring and artifact-verification gates. On Windows, a present pin and
  provenance are consumed as current additional integrity evidence alongside
  independent policy and Authenticode gates, not as standalone deployment
  authority. Carrying yesterday's entry forward would therefore make an
  artifact not checked today indistinguishable from a current attestation.
  The report and alert retain why the label disappeared. Carry-over is safe only
  after the envelope signs per-label verification state and both consumers
  reject or explicitly age stale entries with platform-equivalent policy.

## 8. Where it runs

Authoritative `codesign` and `spctl` verification require macOS — the Linux
VPSes (`example-prod-host`, `example-api-host`) cannot perform the notarization
check authoritatively. Options, cheapest first:

1. **Scheduled GitHub Actions macOS runner** — a daily `cron` workflow. No
   hardware to own; macOS images are maintained by GitHub. Suggested starting
   point.
2. **A dedicated Mac** (Mac mini, or a hosted Mac) — more control, a standing
   cost, one more box to keep patched.

A Linux pre-pass *can* do the non-Apple checks (URL liveness, HTTPS, redirect
chain, version extraction) and is fine as an optimisation, but the Team ID and
notarization verdicts — the security-critical ones — must come from macOS.

## 9. Relationship to the Phase 2 mirror

The agent is approximately the Phase 2 mirror pipeline (review §4.4) minus the
last step. Both *resolve → download → verify Team ID + notarization → hash*. The
mirror additionally *re-hosts the verified artifact and publishes a signed
manifest*. Build the verification agent first; the mirror then reuses its
download-and-verify core and adds re-hosting. They should share code.

## 10. The agent is itself a trust component

The agent verifies the supply chain, so the agent is part of the trusted
computing base and is treated as such:

- It runs in a controlled, logged environment; its runs are reproducible and
  retained.
- The canonical scheduled run holds `CATALOGUE_PUBLISHER_TOKEN`, limited by the
  platform to `POST /admin/catalogue/signed` over the Tailscale-only internal
  listener. It cannot use that credential on any other admin route. Publication
  happens only after a successful sweep, a successful signature, and an exact
  byte-for-byte verifier-state commit. A failed verifier, signing, commit,
  authentication, validation, or network step fails the workflow and does not
  replace the platform's last known good catalogue.
- Its own code lives in the `updater` repo under the same feature-branch → CI →
  review discipline as everything else.
- A compromised scheduled runner could submit only a signed catalogue accepted
  by the platform's independent signature, global-scope, freshness, and
  rollback checks. It cannot use the publisher credential to alter tenant,
  policy, or operational data.

## 11. Phasing

- **Phase 1b** (alongside the security review's Phase 1): deterministic daily
  checks + diff + classification + daily report + paging on `alert`. Proposals
  start as Linear issues.
- **Later:** automated version-bump PRs; agentic URL rediscovery; the upstream
  label diff; the dashboard surface.
- **Phase 2:** extend the verified-download core into the mirror pipeline.
