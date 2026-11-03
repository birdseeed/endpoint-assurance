# Download architecture — direct vs. mirror

> **SUPERSEDED:** This document describes an earlier architectural direction. As of [ADR-001: Vendor-direct delivery is the default; the mirror is dormant](./adr/ADR-001-vendor-direct-delivery.md) (2026-07-25), vendor-direct download is the default delivery path, and mirroring is kept dormant as a narrow, earned exception rather than the target architecture. The daily verifier and upstream-maintenance references below are historical as well: no routine Installomator upstream review operates. This document is retained as the historical record of why the mirror was built.

**Status:** Draft for review
**Companion to:** `installomator-security-review.md` §4.4, §4.9, §5, §6

This doc answers one question precisely: **when a client Mac updates an app,
does the installer come through Patched servers, or directly from the vendor?**

The answer depends on the phase. There are two architectures, and the recommended
end-state is the mirror.

![Patched Updater download architecture — Phase 1 direct vs Phase 2 mirror](download-architecture.svg)

## Phase 1 — direct download, verified on the endpoint

The endpoint downloads the installer **straight from the vendor**. Patched
servers are *not* in the download path — they only receive the provenance record
afterwards.

Verification happens **on the endpoint, after the download**: the update engine
checks the artifact's Apple code signature, confirms the signing Team ID matches
the value in the label record, and confirms notarization — all mandatory and
fail-closed (security review §2, §4.3). There is no pre-download gate; integrity
comes entirely from this on-device check.

The daily verification agent (security review §4.9) does independently re-check
every vendor source — but on Patched infrastructure, as a parallel monitoring
flow. It is *not* something the endpoint's download passes through.

Phase 1 is auditor-defensible on its own: every installed artifact is
cryptographically verified against Apple's PKI and every install is logged.

## Phase 2 — internal mirror (recommended end-state)

**Superseded by ADR-001:** Mirroring is no longer the recommended end-state architecture. See banner above.

Verification happens **first, centrally, on Patched infrastructure.** The mirror
pipeline downloads the installer once from the vendor, verifies it (Team ID +
notarization), records its SHA-256, and re-hosts the verified artifact on
Patched-controlled storage (Cloudflare R2) behind a signed manifest.

The endpoint then downloads the **already-verified, hash-pinned** copy from the
Patched mirror — and still re-checks it locally. The endpoint never resolves or
contacts a vendor URL.

What Phase 2 buys, and Phase 1 cannot:

- The endpoint egress allowlist collapses to a **single domain** (the Patched
  mirror), which is trivial to state and audit.
- The run-time URL-resolution attack surface (threat T5 — poisoned appcasts /
  redirects) leaves the client device entirely; it exists only once, centrally,
  on a hardened box, where its output is logged and hash-pinned before any
  endpoint sees it.
- The central pipeline is one logged chokepoint an auditor can inspect.

## It is a mixed model, not a switch

Re-hosting means redistributing a vendor's installer, and not every vendor's
licence permits that. So the realistic target is **mixed**:

- Apps whose licence permits redistribution → moved onto the mirror (Phase 2).
- The rest → stay on the hardened direct path (Phase 1).

That per-app decision is the `patched.mirror` flag in each label record
(`contracts/label.schema.json`). `resolved`-type labels — the ones that scrape a
vendor source at run time, and therefore carry threat T5 — are the priority
candidates for the mirror; `1password` in the starter manifest is one such.

The mirror pipeline is tracked as PAT-49; its verify-and-hash core is shared
with the verification agent (PAT-52), which is why the agent is built first.

## Cost & infrastructure profile

The mirror ("the Patched software repo") has a deliberately small infrastructure
footprint. A costed go/no-go is tracked as PAT-54 and gates PAT-49; the outline:

- **Storage** — macOS installers are ~50–300 MB. An allowlist of ~30–50 apps,
  each keeping the current plus a few prior versions, is ~20–40 GB. On
  Cloudflare R2 (~$0.015/GB-month) that is a few dollars a month. Trivial; the
  version-retention policy is the only real lever.
- **Egress** — normally the cost that bites: every endpoint pulls installers
  from the mirror, and at estate scale that is the dominant variable cost on
  S3/GCS (~$0.09/GB). **Cloudflare R2 has zero egress fees** — which is exactly
  why R2 was chosen, and Patched already runs R2 (Restic platform backups). On
  R2 the mirror's egress cost is effectively zero.
- **Ingress** — the pipeline pulls each app once, centrally; tens of GB a month;
  ingress is free. Negligible.
- **Compute** — there is no always-on, estate-facing server to spec. The mirror
  is serverless object storage plus the macOS verification runner (PAT-51),
  which is intermittent (daily) and billed by the minute.

The costs that actually matter are not infrastructure spend: the per-app
redistribution-licensing review (legal effort, and what gates whether an app can
be mirrored at all), and ongoing ownership of mirror-freshness monitoring.
