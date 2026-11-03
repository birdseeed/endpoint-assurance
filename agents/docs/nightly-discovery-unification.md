# Nightly discovery unification (PAT-848) — design

**Status: retired. Nothing described here runs.**

- **2026-09-30 (PAT-2299):** the S2 discovery scripts (`ci/discovery_common.py`,
  `ci/discovery_macos.py`, `ci/discovery_windows.py`) and their tests are
  deleted. See `docs/discovery-stage.md`.
- **2026-09-29 (PAT-2247):** all three workflows in the table below
  (`daily-vendor-verify.yml`, `mirror-pipeline.yml`,
  `mirror-pipeline-windows.yml`) are deleted.
- PAT-2249 removed the platform's `/admin/discovery/*` and
  `/admin/catalogue/*` routes this design reads and writes.

Earlier: superseded by the vNext boundary and quarantined under PAT-1474. This
document is retained as historical design evidence only, not an implementation
target.

Previously: design accepted 2026-07-23, implementation sequenced as PAT-848 sub-tickets.
S1 (patched.im discovery/job model) shipped (#309). S2 (this repo's
platform-neutral discovery stage) shipped report-only behind
`DISCOVERY_REPORT_ENABLED` (default off) — see `docs/discovery-stage.md`.
Read alongside `download-architecture.md`, `windows-mirror-pipeline.md`, and the
PAT-847/850/851 catalogue review model (`patched.im` `go-service/docs/API.md`,
"Catalogue review model").

## Why

Three unrelated nightly jobs each hold their own idea of "what version exists
and what have we already done about it":

| Time (UTC) | Workflow | Runner | Behavior today |
|---|---|---|---|
| 03:00 | `daily-vendor-verify.yml` | macos-latest | `verifier/verify.py --shard-count 30` (PAT-974) downloads every allowlisted artifact EVERY night plus a rotating ~1/30th shard of the rest of the manifest to learn version/hash/TeamID/notarization; signs and publishes `catalogue.json`; state to `verifier-state` branch |
| 06:00 | `mirror-pipeline.yml` | macos-14 | restores verifier state, then RE-downloads each changed approved artifact before scan/verify/publish |
| 07:00 | `mirror-pipeline-windows.yml` | windows-latest | resolves latest winget version, then downloads every eligible approved MSI EVERY night, changed or not |

Costs and defects this creates:

- Double macOS downloads (verifier then mirror) for every changed artifact; full
  nightly Windows downloads for unchanged ones. macOS runner minutes bill 10x,
  Windows 2x — this is the dominant recurring CI cost of the org.
- macOS version classification leans on a version parsed from the download
  URL/filename; a label with no working version strategy can sit `ok` forever
  (silently healthy with no change detection).
- No durable, platform-neutral discovery/job record: the dashboard and the
  PAT-847 state contract can't see why something was or wasn't downloaded.
- Three sources of truth (verifier-state branch, label JSON pins, bucket
  manifests) that PAT-846 already had to reconcile from the outside.

## Shape of the fix

One nightly **orchestration model** with three stages and a durable job record,
platform adapters at the edges. Not necessarily one workflow file on day one —
the model unifies first, the YAML consolidates last.

```
discovery (side-effect free, metadata only, any runner)
   │  normalized DiscoveryResult per (product, platform target)
   ▼
platform job creation (idempotent, keyed product+platform+version/checksum+op)
   │  jobs with state = Ready → Queued ...
   ▼
execution (native runners: macOS codesign/notarization, Windows Authenticode)
      download ONCE → scan → verify → publish/pin THE SAME BYTES (SHA-256-bound)
      → report PAT-847 states (Downloading … Published/Failed)
```

### Discovery stage (new)

Side-effect free. For each approved catalogue product, evaluate both platform
targets independently and emit one normalized record:

```
{product_id, target_id, platform, resolved_version, source_url,
 expected_signer, expected_checksum?, discovered_at, decision, reason}
decision ∈ unchanged | change_detected | needs_metadata | reverify_due | failed
```

- macOS adapter: existing `verifier/verify.py` resolution strategies
  (github-release, sparkle-appcast, http-redirect, vendor-api) used for
  metadata only — no artifact download at this stage. Where a strategy can't
  resolve a version or trusted checksum without downloading, the target is
  `needs_metadata` or `reverify_due`, never silently `unchanged`/healthy.
- Windows adapter: winget manifest metadata (version + SHA-256) and vendor
  metadata; winget's published hash counts as a trusted independent checksum.
- Comparison baseline is the platform's durable record (last published + last
  verified per target), NOT the verifier-state branch and NOT label JSON pins.

### Durable job handoff (new platform surface)

For `change_detected` / `reverify_due`: create an idempotent job on the
platform (patched.im), keyed `(product, platform, resolved_version_or_checksum,
operation)`. Re-creating the same key returns the existing job — a rerun of the
nightly can never double-publish or double-pin. Jobs transition through the
PAT-847 state contract; every transition keeps the existing "state reporting is
non-fatal" property (`report_state()` never aborts mirroring).

### Execution stage (existing pipelines, re-plumbed)

- Download at most once per job. The verified bytes and their SHA-256 travel
  from download → ClamAV → platform verification (TeamID/notarization or
  Authenticode/publisher) → R2 publish as one run-local artifact identity; the
  publish step re-checks the SHA-256 it was handed. No second vendor fetch.
- Vendor-direct targets pin the verified URL/checksum without re-hosting,
  as today.
- The signed endpoint catalogue (`catalogue.json`) becomes a product of this
  run's verified results rather than a separate full-download sweep.

## Security constraints (unchanged, restated as invariants)

Do not optimize away supply-chain monitoring. Specifically:

1. Same-version byte replacement stays detectable: use trusted independent
   checksums (winget, homebrew-cask cross-hash, vendor sha256 URLs) where they
   exist; where none exists, a **documented periodic full re-download
   re-attestation cadence** (default: every 7 days per target, configurable
   per label) — `reverify_due` exists precisely for this.
2. Alert immediately on download-host, signer/publisher, TeamID, notarization
   or hash change (extends the PAT-912 vendor-verification alerting).
3. Published bytes = scanned bytes = verified bytes, bound by SHA-256.
4. Preserve load-bearing existing properties:
   - `ADMIN_API_TOKEN` never on a CI runner — the `PIPELINE_READY_FILE` /
     `PIPELINE_STATE_SPOOL` prod-01 SSH relay pattern (PR #291) carries over
     to job creation/updates.
   - `--only` never bypasses the approval gate.
   - Mirror pipeline fails CLOSED on catalogue/approval fetch failure;
     endpoint catalogue fetch stays fail-open (last-known-good). Don't
     cross-wire.
   - Cross-source hash mismatch fails closed.

## What gets deleted

- Verifier full-download sweep as the version-discovery mechanism.
- The mirror pipeline's second download of already-verified bytes.
- Windows nightly re-download of unchanged approved MSIs.
- "Unresolved version strategy == healthy" classification.
- Verifier-state branch as a source of truth for orchestration (it may remain
  as a debug artifact until S5 retires it).

## Sub-ticket sequencing

Implement strictly in this order; each lands independently mergeable.

- **S0 = PAT-942** (precondition): `daily-vendor-verify` has failed nightly
  since ≥13 Jul. Root-cause and green it (or consciously retire it into S2)
  before building on its strategies.
- **S1 [patched.im]** Durable discovery/job model: tables + idempotent job
  endpoints keyed as above; per-target last-published/last-verified queries;
  extends (does not fork) the PAT-850 state contract. Token-safe relay
  variants of the new endpoints.
- **S2 [updater]** Discovery stage: platform-neutral `DiscoveryResult`
  emission for both adapters, metadata-only, with the five decisions; kills
  silent-healthy. Ships behind a report-only mode first (emits + records,
  changes no downloads).
- **S3 [updater]** Change-only downloads + verified-bytes handoff: mirror
  pipelines consume S1 jobs, download once per job, SHA-256-bound handoff to
  publish/pin; Windows stops unconditional downloads.
- **S4 [updater]** Re-attestation + byte-replacement alerting: cadence
  scheduling, cross-source checksums, drift alerts (builds on PAT-912).
- **S5 [updater]** Workflow consolidation: single orchestration workflow
  fanning out to native runners; retire the triple schedule and the
  verifier-state orchestration role; unify automations run-records.

Rollout: S2 report-only runs alongside the current pipelines for ≥3 nights;
compare its decisions against what the old sweep actually did before S3 flips
download behavior. A rerun after any failure must resume idempotently (S1 keys
guarantee this).

## Test matrix (acceptance)

unchanged / new version / same-version-changed-hash / missing metadata /
retry-idempotency / handoff integrity — each on both platforms, at the
adapter-contract level (mocked HTTP, real hashing), plus one end-to-end
dry-run per platform in CI.
