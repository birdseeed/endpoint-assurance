# Mirror Infrastructure Spike — PAT-54

> **SUPERSEDED:** This document records a "Go" decision on the mirror infrastructure. As of [ADR-001: Vendor-direct delivery is the default; the mirror is dormant](./adr/ADR-001-vendor-direct-delivery.md) (2026-07-25), that decision has been reversed: mirroring is no longer the default end-state but kept dormant as a narrow, earned exception. This document is retained as the historical record of the cost model and infrastructure analysis.

**Status:** Complete  
**Author:** Andy Bridson  
**Gates:** PAT-500 (Phase 2 mirror pipeline — top-30 labels)  
**Companion to:** `docs/download-architecture.md`, `installomator-security-review.md` §4.4

---

## Purpose

This document is the one-page costed go/no-go for building the Phase 2 internal mirror
pipeline. Phase 1 (direct-from-vendor, endpoint-verified) is already live. Phase 2 moves
verification upstream — the pipeline fetches each installer once, verifies it centrally,
and re-hosts the signed, hash-pinned artifact on Patched-controlled storage. Endpoints
never contact a vendor URL. The question is: is the cost model sound enough to build on?

---

## 1. Storage choice — R2 confirmed

Cloudflare R2 is the storage layer. Patched already uses R2 for Restic platform backups,
so the account, credentials, and operational familiarity exist. The deciding factor is
**zero egress fees** — which eliminates the cost that dominates every S3/GCS comparison
at estate scale. No other storage option offers this without a CDN layer in front.

Decision: **R2. Not a variable.**

---

## 2. Version-retention policy and storage sizing

Recommended retention: **current version + 2 prior = 3 versions per label.**

This covers rollback for the two most recent update cycles without accumulating unbounded
storage. Older versions are deleted by the pipeline after the window slides.

| Variable | Value |
|---|---|
| Labels in Phase 2 scope | 30 (top-30 by prevalence) |
| Versions retained per label | 3 |
| Average installer size | ~150 MB |
| **Total storage** | **~13.5 GB** |
| R2 rate | $0.015 / GB-month |
| **Monthly storage cost** | **~$0.20** |

Storage cost is negligible. The retention policy is the only lever worth revisiting if
scope grows beyond ~200 labels.

---

## 3. Ingress/egress projection at expected estate size

Target estate: IoM SME customers — 50–200 endpoints per tenant, 10–20 tenants initially.
That is **500–4,000 managed endpoints** worst-case at early scale.

Worst-case scenario: all endpoints update Chrome on the same day (coordinated rollout).

| Path | Per-endpoint | Total (4,000 endpoints) | Cost |
|---|---|---|---|
| Mirror egress (R2) | 150 MB | 600 GB | **$0** |
| Equivalent S3 egress | 150 MB | 600 GB | ~$54 |

Ingress to the mirror (the pipeline pulling from vendors) is a few GB/day per app
update cycle. R2 ingress is free. No meaningful cost.

**At expected estate scale, R2 egress savings vs S3 are $40–60/month in the worst
coordinated-update case. The saving scales linearly with estate growth.**

---

## 4. macOS runner cost — self-hosted Mac mini recommended

The pipeline runs on a macOS host (required for `codesign` and `spctl` verification).
It runs once daily: download + verify + upload ~30 apps.

| Option | Setup | Monthly | Notes |
|---|---|---|---|
| GitHub Actions macOS runner | $0 | ~$72 | $0.08/min × 30 min/day × 30 days |
| **Self-hosted Mac mini** | **~$800 one-time** | **~$0** | Shared with PAT-51 (verification agent runner) |

The verification agent (PAT-52) already needs a macOS runner. The mirror pipeline
shares that host — the incremental cost of adding the mirror job to an already-running
Mac mini is near zero. The GitHub Actions cost compounds over time; a dedicated Mac
mini pays for itself in ~11 months and is already justified by PAT-52 alone.

Recommendation: **self-hosted Mac mini, shared with the verification agent.**
If PAT-52 ships first on GitHub Actions, mirror pipeline joins it there at ~$72/month
until hardware is procured — acceptable as a temporary state.

---

## 5. Redistribution-licensing review

Re-hosting a vendor's installer binary is redistribution. Not every EULA permits this.
The review must happen per-label before `patched.mirror` is set to `true`.

**Process:**
1. Andy reviews vendor EULA for "redistribution to managed devices" or equivalent clause.
2. If permitted: set `patched.mirror: true` and add `mirror_eula_approved: true` to the
   label's `patched` block. (This field needs to be added to `contracts/label.schema.json`
   as part of PAT-500 work.)
3. If not permitted: label stays on the direct-download path (Phase 1) indefinitely.
4. Track review date in the existing `reviewed_at` field; update notes with EULA outcome.

**Top-5 apps — initial EULA assessment:**

| App | Redistribution verdict | Basis | Action |
|---|---|---|---|
| **Google Chrome** | Likely permitted for internal managed deployment | Chrome ToS silent on enterprise redistribution; Google's enterprise deployment guides explicitly support MDM/Intune distribution of the DMG to managed devices — redistribution for internal management is the documented use case | Confirm with Google Chrome Enterprise ToS; set `mirror_eula_approved: true` |
| **Mozilla Firefox** | Conditional — open-source license permits; executable ToS ambiguous | Source code: MPL-2.0 permits redistribution. Firefox executable ToS grants "personal, non-exclusive" use and does not explicitly authorise bulk redistribution. Mozilla's enterprise deployment docs (CCNA) sanction managed deployment but do not address re-hosting | Seek written confirmation from Mozilla legal or use direct-download path |
| **Slack** | Unclear — user ToS does not cover software redistribution | Slack User ToS covers workspace access, not installer distribution. Main Services Agreement (enterprise contract) likely covers this; Slack explicitly supports MDM deployment via their own CDN link | Contact Slack enterprise team; likely permitted under enterprise agreement |
| **1Password** | Conditional — enterprise contract required | Standard ToS restricts redistribution beyond authorised users. Enterprise Order Form likely grants managed device distribution rights. Patched tenants using 1Password will have an enterprise agreement | Confirm with 1Password enterprise sales; requires per-tenant order form check |
| **VS Code** | Proceed with caution — binary EULA restricts redistribution | Microsoft binary EULA (not MIT source) prohibits "sharing or providing the software for others to use." Internal corporate network deployment is permitted (§1.1) but formal re-hosting as a mirror is ambiguous. VS Code is also available as OSS builds (VSCodium) under MIT | Use direct-download path for Microsoft-signed binary until Microsoft legal clarity obtained; or evaluate VSCodium |

**Initial mirror-eligible candidates** (safe to proceed): Google Chrome (confirm first),
Firefox (proceed under enterprise deployment interpretation), Zoom, Slack (under enterprise
agreement), Microsoft Teams (covered by Microsoft volume licensing for managed devices).

---

## 6. Mirror-freshness monitoring

**Risk:** if the daily pipeline fails to fetch or upload an updated label, endpoints
silently fall back to the Phase 1 direct path (or stall). The failure is invisible without
monitoring.

**Monitoring design:**
- The pipeline writes a `mirror_last_updated` timestamp to the manifest JSON for each label.
- The PAT-52 verification agent (already runs daily) adds a freshness check: alert if
  `mirror_last_updated` is **> 25 hours old** for any mirror-enabled label.
- Alert destination: existing Patched ops channel (same as PAT-52 alerts).
- No new infrastructure required — this is a one-function addition to the verifier's
  output path.

Owner of freshness monitoring: PAT-52 verifier. No separate monitoring service needed.

---

## Summary cost model

| Item | Monthly cost |
|---|---|
| R2 storage (~13.5 GB) | ~$0.20 |
| R2 egress | $0.00 |
| macOS runner (shared Mac mini, amortised) | ~$7 (≈$800 / 12 months) |
| Licensing review (Andy, one-time per label) | n/a — sunk into label review process |
| **Total recurring** | **~$7–$8 / month** |

Comparison: same pipeline on S3 + GitHub Actions = ~$126/month at early estate scale,
scaling upward with endpoints. R2 + self-hosted saves ~$118/month from day one.

---

## Decision

**Superseded by ADR-001:** The "Go" decision below has been reversed as of ADR-001 (2026-07-25). Mirroring is no longer the default end-state; vendor-direct download is. This infrastructure remains dormant and available as an earned exception only.

**Go** *(recorded decision, superseded)*

The infrastructure cost is negligible (~$8/month steady-state). R2 is confirmed as the
storage layer — zero egress fees are the decisive factor and Patched already operates R2.
The version-retention policy (3 versions, ~13.5 GB) is safe and revisable. The macOS
runner cost is justified and shared with the verification agent already in build.

The only substantive constraint is per-label redistribution-licensing review, which is
bounded (30 labels, Andy as reviewer, one-time per label), and the schema extension
(`mirror_eula_approved`) which is a small PAT-500 task. Neither blocks starting the
pipeline build.

**PAT-500 (Phase 2 mirror pipeline) is cleared to proceed** *(superseded by ADR-001)*.

Pre-conditions before enabling `patched.mirror: true` for any label:
1. `mirror_eula_approved: true` recorded in the label JSON (Andy review).
2. `contracts/label.schema.json` updated to include `mirror_eula_approved` field.
3. Freshness monitoring wired into PAT-52 verifier output.
