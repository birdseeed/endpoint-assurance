# ADR-001: Vendor-direct delivery is the default; the mirror is dormant

**Status:** Accepted
**Date:** 2026-07-25
**Author:** Andy Bridson
**Supersedes (in effect, not by edit):** `docs/download-architecture.md` §"Phase 2 — internal mirror (recommended end-state)", `docs/mirror-infrastructure-spike.md` (PAT-54 go/no-go), `docs/network-egress.md` §5 "Mirror mode roadmap impact"
**Related:** PAT-960 (vendor-permission classification workflow), PAT-500/501 (macOS mirror), PAT-823/840 (Windows mirror/pin-vendor), PAT-900 (Windows publisher-string confirmation), PAT-495 (signed catalogue)

## Context

Patched set out to re-host vendor installer binaries on Patched-controlled
storage — the "mirror" (Cloudflare R2, served from `mirror.patched.im`) —
as the intended end-state for both platforms (`docs/download-architecture.md`
called it "the recommended end-state"; `docs/mirror-infrastructure-spike.md`
gave it a costed go/no-go and a "Go" decision).

Re-hosting a vendor's installer is redistribution of their copyrighted binary.
Not every vendor's licence permits that, so the mirror was always going to be
a per-app decision gated on legal review (`mirror_eula_approved` in the label
schema). PAT-960 exists to work that gate at scale: classify all ~174
catalogue apps and reach out to vendors individually for redistribution
permission.

Two things have become clear since:

1. **The mirror has essentially no live usage.** Of 1,108 macOS label files
   in `engine/labels/`, only 2 (`ghostty`, `microsoftvisualstudiocode`) carry
   a real, non-empty `pinned_sha256`, and only 9 carry `cross_hash_sources`.
   4 labels have `mirror_eula_approved: true` at all (`docker`, `ghostty`,
   `microsoftvisualstudiocode`, `vmwarefusion`); of those, only 2 have
   `"mirror": true` set. On Windows, 2 of 20 live allowlist entries
   (`1password`, `zoom`) are on the mirror — a legacy holdover from before
   the vendor-pinned migration (PAT-840), predating and outside this ADR's
   stated macOS-only earned-exception list, not a deliberately-cleared
   exception under it (see `docs/network-egress.md`). The dashboard's own
   catalogue view shows single-digit hosted /
   vendor-pinned counts against 174 rows. After roughly two months of build
   effort, the mirror is not the delivery path for the estate — it is a
   handful of hand-cleared exceptions.
2. **The redistribution-permission programme does not scale the way the
   verification programme does.** Classifying 174 apps and soliciting
   individual vendor permission (PAT-960) needs legal judgement per vendor,
   depends on vendor goodwill and response time, and for copyleft licences
   (GPL, etc.) additionally obliges Patched to engineer and serve
   corresponding source alongside every mirrored binary. None of that is a
   one-time cost — it recurs per app, per licence change, per vendor
   relationship. By contrast, the control that actually makes vendor-direct
   downloads safe — verifying the vendor's cryptographic signature on the
   endpoint immediately before install — already exists, is already
   mandatory and fail-closed on both platforms, and needs nobody's
   permission to operate or extend to app #175.

Industry signal points the same way: Patch My PC — a long-established
commercial patch-management vendor operating at far larger scale than
Patched — ships macOS/Intune patching on top of Installomator, i.e. the
vendor-direct model, not a re-hosted mirror. Patched's own macOS label set is
already built the same way: 1,092 of 1,108 labels carry
`"reviewed_by": "installomator-import"`.

The verification chain this decision leans on (confirmed by reading the
code, not asserted) is documented in full in `docs/VERIFICATION.md`. In
summary:

- **macOS:** every one of the 1,108 labels carries an `expected_team_id`.
  Download URLs must be HTTPS (`engine/Installomator.sh` `assert_https_url`,
  ~line 420) or the run aborts. After download, `spctl -a -vv` must pass and
  the observed Team ID must equal `expected_team_id`, or the run aborts
  before install (exit 60/61/62 — see VERIFICATION.md for the full table).
- **Windows:** the allowlist itself is signature-checked and fails closed if
  it can't be verified (`AllowlistLoader`); installers are staged into a
  trusted staging directory or the install is refused; `InstallRunner`'s
  `AuthenticodeCheck()` runs `AuthenticodeVerifier.Verify()`
  (`WinVerifyTrust`) before install, explicitly fail-closed (PAT-305);
  `.msix` packages get the AppX-SIP/`AppxSignature.p7x` equivalent
  (`VerifyMsix()`, PAT-844); publisher matching is an exact,
  case-insensitive string compare against the cert's Organization (or
  Common Name) RDN; and the install is pinned to the exact artifact that
  passed verification (no post-check substitution).

That mechanism does not care whether the bytes came from `dl.google.com` or
`mirror.patched.im` — it verifies the artifact itself. The mirror was never
the thing making installs safe; the on-device signature check was, and is.

## Decision

**Vendor-direct download, verified cryptographically on the endpoint
immediately before install, is the default delivery path for both macOS and
Windows.** The mirror pipeline, the R2 bucket, and `mirror.patched.im` are
kept **dormant**, not deleted, as a narrow, earned exception — not the
target architecture.

PAT-960 stops being a backlog to clear to 174/174. It becomes the **audit
record for the apps already cleared** (currently 4: `docker`, `ghostty`,
`microsoftvisualstudiocode`, `vmwarefusion`) — reviewed, permissioned, and
mirrored on their own merits — rather than a queue every catalogue app is
expected to pass through.

## Consequences

### Positive

- **The safety story stops depending on legal throughput.** Signature
  verification is already built, already mandatory, already fail-closed, and
  already covers 100% of macOS labels (`expected_team_id` on 1,108/1,108).
  It scales to app #175 exactly as it scaled to app #1 — no vendor email, no
  counsel review, no EULA reading.
- **No more copyleft corresponding-source obligation.** Mirroring GPL/LGPL
  binaries (e.g. VLC, LibreOffice, Notepad++ — all on the Windows allowlist)
  carries a corresponding-source engineering obligation that direct
  vendor-download never triggers, because Patched isn't the one
  redistributing the binary.
- **Removes a standing legal-exposure surface.** Every mirrored binary is a
  redistribution decision Patched is on the hook for if a vendor disputes it
  later. Zero net-new redistribution decisions per default install removes
  that exposure from the common path.
- **Matches where the effort was already going.** The label set is already
  Installomator-derived vendor-direct data (1,092/1,108 `reviewed_by:
  "installomator-import"`); this decision stops fighting that grain.
- **PAT-960's completed work isn't wasted.** The classification already done
  for the 4 cleared apps stands as the model for the dormant exception path,
  not thrown away.

### Negative

- **Loses version-availability insurance.** The mirror's actual value
  proposition was never "verification" (the endpoint check does that either
  way) — it was that a centrally-retained prior version survives a vendor
  pulling or replacing a build mid-rollout. Under vendor-direct, if a vendor
  removes the exact version an endpoint is mid-update against, that
  installer is simply gone until the vendor republishes something. This is
  accepted as a low-frequency risk, not eliminated.
- **Loses the single-domain enterprise egress story as a default.** A
  fully-mirrored estate could tell an enterprise customer "allowlist
  `mirror.patched.im` and nothing else" instead of ~150 vendor domains
  (`docs/network-egress.md` §5 previously framed "single Patched CDN origin"
  as the long-term goal). That story is now available only per-customer, per
  app, as an earned exception — not a property every tenant gets by default.
  A paying enterprise customer who needs strict single-domain egress
  allowlisting is exactly the case the dormant path exists for.
- **Sunk build cost.** The mirror pipeline (PAT-500/501 macOS, PAT-823/840
  Windows), the R2 infrastructure decision (PAT-54), and the schema fields
  (`mirror`, `mirror_eula_approved`, `pinned_sha256`, `cross_hash_sources`,
  `redistribution_notice`) represent real engineering time that will now see
  only narrow use. It is not wasted — it is the mechanism the dormant path
  runs on — but it will not pay for itself at the scale originally modelled
  in `docs/mirror-infrastructure-spike.md`.
- **Coverage is not actually uniform yet, and this decision doesn't fix
  that on its own.** Windows has only 13 allowlist entries live (of which 9
  carry a pinned hash) against macOS's 1,108 — see "Known gaps" in
  `docs/VERIFICATION.md`. Vendor-direct-by-default raises the bar on getting
  Windows allowlist coverage and `expected_publisher` accuracy (PAT-900)
  right, since there is no mirror safety net underneath it.

## What stays dormant

Nothing described below is being deleted or reverted. It remains in the
codebase and infrastructure, inactive by default:

- **The mirror pipeline** — `ci/mirror_pipeline.py` (macOS),
  `ci/mirror_pipeline_windows.py` (Windows) — continues to exist and can be
  re-run per label. *Superseded 2026-09-30 (PAT-2304): both scripts are
  deleted, along with the Windows allowlist they pinned into.*
- **The R2 bucket and `mirror.patched.im` CDN** — infrastructure stays live;
  it already serves the 2 macOS labels with `"mirror": true` and would serve
  a Windows label the moment one is flipped to `mirror: true` /
  `install_mode: vendor_pinned`.
- **The label schema fields** — `patched.mirror`, `mirror_eula_approved`,
  `pinned_sha256`, `cross_hash_sources`, `redistribution_notice` — remain in
  `contracts/label.schema.json` and continue to validate.
- **PAT-960** — reframed from "classify all 174 apps for permission" to "the
  audit trail for the apps that are actually mirrored". It documents *why*
  `docker`, `ghostty`, `microsoftvisualstudiocode`, and `vmwarefusion` were
  cleared, and is the template a future case-by-case mirror candidate
  follows.

## Re-activation criteria

Mirroring a given app (or extending mirror coverage generally) is justified
again, on a case-by-case basis, when either is true:

1. **Redistribution rights are already established for that app** — the
   licence is unambiguous (MIT/Apache/BSD source with a permissively-licensed
   binary, or an explicit vendor grant), matching the bar already cleared for
   the 4 current exceptions. This is the "already earned" path, not a new
   programme.
2. **A paying enterprise customer requires single-domain egress
   allowlisting** as a condition of deployment, and the specific apps in
   their estate are legally clear to re-host. In that case the mirror is
   switched on for that customer's app set, not for the catalogue at large.

Re-activating the *programme* (i.e. going back to PAT-960-at-scale,
classify-everything) would require a change in the underlying economics —
e.g. counsel capacity becoming cheap/available, or a customer segment large
enough that single-domain egress is a hard requirement across many tenants
rather than a one-off ask. Absent that, this ADR stands.

## Alternatives considered

**A. Delete the mirror entirely.** Rejected. The mirror is genuine
infrastructure, already earning its keep for 4 legitimately-cleared apps, and
is the correct answer for the specific enterprise single-domain-egress case.
Deleting it would mean rebuilding it from scratch the next time either
condition in "Re-activation criteria" arises, for no benefit today — the
dormant infrastructure costs ~nothing to leave in place (R2 storage for a
handful of pinned artifacts, no egress fees per `docs/mirror-infrastructure-spike.md`
§1).

**B. Push through the full PAT-960 classification and counsel programme as
planned.** Rejected as the default path. This was the status quo ADR-001
reverses. It was rejected because: (a) it does not scale — each of the
remaining ~170 apps needs its own vendor outreach and legal read, with no
guarantee of a permissive answer; (b) it does not make anything safer that
isn't already safe — the endpoint signature check is the actual integrity
control, and it applies identically whether the byte source is the vendor
or the mirror; (c) two months of build effort produced 2 apps with a real
pinned hash out of 1,108 labels, which is the empirical result of trying to
scale a permission-gated process; (d) copyleft apps on the path (VLC,
LibreOffice, Notepad++) would add a corresponding-source obligation with no
corresponding safety benefit over vendor-direct.

**C. Keep mirroring as the default only for a curated "top-N by prevalence"
subset (the original PAT-500 top-30 plan), vendor-direct for the rest.**
Rejected as the default, for the same reason as B at smaller scale: it still
requires an ongoing per-app legal-review programme to keep the top-N set
current, for a security benefit (redundant verification) the endpoint check
already provides. It remains available as an instance of the "earned
exception" path in "Re-activation criteria" above, just not as a standing
default tier.
