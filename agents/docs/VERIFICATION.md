# Verification — how Patched trusts a vendor artifact

> **vNext quarantine (PAT-1474):** scheduled package verification, catalogue
> publication, mirrors, upstream-label maintenance and automatic package smoke
> testing are disabled. The package workflows remain manual-only diagnostics,
> and mirror dispatches default to dry-run. This document preserves the legacy
> verification and incident-response contract for compatibility; it does not
> describe an active vNext package-maintenance service. References below to
> nightly verification or a current verifier state are historical observations,
> not a claim of a running service. The Installomator upstream-review workflow
> has been removed, so it cannot schedule or manually create maintenance issues.

> **Windows allowlist retired (PAT-2304, 2026-09-30):** `windows/windows-allowlist.json`,
> its `.sig`, `sign-windows-allowlist.yml`, `windows/sign-allowlist.py`,
> `windows/verify-allowlist-signature.py`, the allowlist validator and schema,
> the release workflow's signature re-verify step, the mirror pipelines and
> `verifier/verify.py` are deleted. The allowlist only fed the Windows install
> path, which is patching, and Patched does not patch (Andy, 2026-09-28). The
> Windows sections below that describe the allowlist, its signing and
> `InstallRunner` are history; the C# sources they name remain in the tree,
> uncompiled into the shipped Service, until a separate cleanup removes them.

> **Smoke and behavioral probes retired (PAT-2308, 2026-09-30):** the manual
> `smoke-test.yml` and `behavioral-analysis.yml` workflows installed catalogue
> apps on hosted runners (winget on Windows, the Installomator engine on macOS)
> to gate catalogue promotion. They, their probe and merge scripts, and
> `verifier/analyze-behavior.py` are deleted. References below to smoke or
> behavioral testing are history.

> **Shipped assurance-only bundle:** Self Service is browse-only. App
> installation and removal are unavailable in this release, so Self Service
> never creates install, deploy, or uninstall triggers on macOS or Windows.
> The separately quarantined legacy macOS Deploy window retains its distinct
> `deploy-window` trigger path; it is not a Self Service capability.

**Status:** Canonical reference
**Date:** 2026-07-25
**Audience:** engineers working on the agent/engine; security questionnaires;
pentest scoping; customer assurance / compliance conversations.
**Companion to:** `docs/adr/ADR-001-vendor-direct-delivery.md`,
`docs/installomator-security-review.md`, `docs/audit-events-contract.md`

This document is the single place that describes, precisely, why it is safe
for a Patched-managed endpoint to download a third-party installer over the
open internet and run it as an administrator. It is written to be handed to
an auditor or customer security team without redaction.

---

## 1. The security model, in one paragraph

**Patched does not trust the network, and does not trust its own mirror.
Patched trusts the vendor's cryptographic signature, verified on the
endpoint, immediately before install, every time.** Transport (HTTPS) is
enforced and mandatory, but it is not the control doing the work — it only
stops passive eavesdropping and protects against a class of downgrade
attack. The control that actually makes an untrusted download safe to run as
root/SYSTEM is a fail-closed check of the vendor's own code-signing identity
(Apple Team ID + notarization on macOS; Authenticode publisher on Windows)
against the identity recorded for that app in the signed label/allowlist. If
that check does not pass, the artifact is never executed — full stop, no
override. Where the artifact came from — a vendor CDN or the Patched mirror
— is irrelevant to this check; it runs identically either way.

---

## 2. Legacy macOS execution reference — quarantined Deploy window only

### macOS

1. **Request.** The separately quarantined legacy macOS Deploy window (or an
   admin policy) may trigger an install for a label. Its `deploy-window`
   trigger path is distinct from Self Service. An admin-scheduled run uses the full allowlist
   (`endpoint/patched-update.sh`, header comment, step 2).
2. **Bundle self-check.** Before touching any label, the daemon verifies its
   own bundle (`Installomator.sh` + the allowlist + itself) against a pinned
   SHA-256 manifest (`endpoint/patched-update.sh` §4.5 reference). A tampered
   local bundle is caught here, before step 3 ever runs.
3. **Policy / allowlist gate.** The label must be present in
   `endpoint/labels-allowlist.txt` (generated from `engine/labels/*.json` by
   `ci/validate-labels.py --emit-allowlist`) and carry a non-empty
   `expected_team_id`. A label with an empty/missing `expected_team_id`
   aborts **before any download is attempted** — exit code 60 (closes threat
   T4, "empty Team ID").
4. **Resolve source.** The download URL is either static (from the label) or
   resolved at run time (e.g. scraping a vendor appcast/API — `resolved`
   labels carry residual threat T5 until moved to the mirror). Either way,
   the resolved URL must be `https://` or the run aborts immediately
   (`assert_https_url()`, `engine/Installomator.sh` ~line 420, exit code 63,
   log line `PATCHED_VERIFICATION_FAILED ... reason=non_https_url`).
5. **Transport.** `curl` fetches the artifact over HTTPS on port 443.
6. **Staging.** The artifact lands in the engine's working directory prior
   to verification; nothing is installed from it yet.
7. **Verify.** `spctl -a -vv` runs against the downloaded artifact.
   - Non-zero exit from `spctl` → notarization/Gatekeeper assessment failed
     → exit code 61, log line `PATCHED_VERIFICATION_FAILED ...
     reason=spctl_assessment_failed`. Install aborts.
   - `spctl` passes → the Team ID is parsed out of its `origin=` field and
     compared to the label's `expected_team_id`. Mismatch → exit code 62,
     log line `PATCHED_VERIFICATION_FAILED label=... expectedTeamID=...
     observedTeamID=... reason=teamid_mismatch`. Install aborts.
   - **Signed-catalogue SHA-256 (secondary, when present).** If a
     `PINNED_SHA256` is supplied from the signed catalogue (PAT-495), the
     downloaded bytes are hashed and compared; a mismatch aborts with exit
     code **64**, `PATCHED_VERIFICATION_FAILED ... reason=sha256_mismatch`.
     This check is **fail-open by design**: if no catalogue hash is available
     the check is skipped (`engine/Installomator.sh` ~line 12900) and the
     install proceeds on the Team ID + notarization result alone — the same
     secondary-control posture as Windows' `pinned_sha256` (see §5).
8. **Install, pinned to the verified artifact.** Only the exact file that
   passed steps 7 is installed (`.dmg`/`.pkg`/`.zip` extraction and install
   operate on the verified artifact in place — there is no second
   resolve/fetch between verify and install).
9. **Audit report.** `patched-update.sh` writes a provenance record (verified
   Team ID, version, outcome) and POSTs it to `/v1/provenance`
   (bearer + HMAC auth, same scheme as inventory). On any verification
   failure it also emits an audit event (`event_type: verification_failed`,
   `docs/audit-events-contract.md`) queued at
   `/var/db/patched/events-queue/` and shipped to `/v1/events`. It then
   writes `/Library/Application Support/Patched/update-status.json`
   atomically — the contract the menu bar / Self Service UI reads to show
   the user the outcome.

### Windows

1. **Request.** This legacy Windows runner reference is not exposed by the
   shipped Self Service UI. A scheduled run may process the pending-installs queue fetched from the platform.
   `InstallRunner.RunAsync()` filters the queue to winget-sourced items (mas
   and vendor sources are macOS-only) and processes each in turn.
2. **Policy / allowlist gate.** `InstallRunner` resolves the package against
   the **signed** local Windows allowlist. `AllowlistLoader` fails closed: an
   unsigned or invalid allowlist file is refused outright and never falls
   back to an empty/unsafe list. A package absent from the signed allowlist
   is blocked — "not in the signed Windows allowlist — blocking install
   (fail-closed)" — before any download happens.
3. **Resolve source (three mutually-exclusive modes, schema-enforced).** Per
   [ADR-001](adr/ADR-001-vendor-direct-delivery.md), vendor-direct delivery
   is the default for both platforms and the mirror is kept dormant,
   activated only per-app as a narrow, earned exception (redistribution
   rights already established, or a paying customer's single-domain-egress
   requirement — see ADR-001 "Re-activation criteria"). These modes are not
   used in equal measure: as of this writing, 18 of the 20 live Windows
   allowlist entries are vendor-pinned, 2 are on the dormant mirror path,
   and 0 use the plain winget path.
   - **Vendor-pinned** (`install_mode: vendor_pinned`) — the agent downloads
     directly from the label's own `pinned_url` (a first-party vendor
     domain, e.g. `dl.google.com`), never via winget/Chocolatey, no unpinned
     fallback (PAT-840). This is the default mode in practice today.
   - **Mirror** (`mirror: true`) — the agent downloads from
     `mirror.patched.im` instead of the vendor, again never via
     winget/Chocolatey (PAT-823). This is the dormant path per ADR-001. It
     is not literally unused on Windows: `1password` and `zoom` were pinned
     to the mirror early in the PAT-823 build-out (mid-July 2026, before
     most other entries were migrated to vendor-pinned mode) and have not
     since been converted. ADR-001's "earned exception" list (`docker`,
     `ghostty`, `microsoftvisualstudiocode`, `vmwarefusion`) is macOS-only
     and has no stated Windows counterpart, so these two are a legacy
     holdover from before the ADR, not a deliberately-cleared exception
     under it.
   - **Neither** — the standard path: winget resolves and stages the
     installer from Microsoft's winget infrastructure. No live allowlist
     entry currently uses this path; every entry so far has been given an
     explicit vendor-pinned or (legacy) mirror source.
4. **Transport.** HTTPS in all three modes (winget's own CDN resolution for
   the standard path; direct HTTPS fetch for vendor-pinned/mirror).
5. **Staging.** The installer is staged into a trusted staging directory
   before anything touches it. If a trusted staging directory can't be
   prepared, the install is refused outright (`ChocolateyEngine`,
   `WingetCliEngine` both log "Refusing to ... could not prepare a trusted
   staging directory" and stop).
6. **Verify.**
   - **Authenticode (primary, mandatory, fail-closed).**
     `InstallRunner.AuthenticodeCheck()` calls
     `AuthenticodeVerifier.Verify()` (PE/.exe/.msi) or `.VerifyMsix()`
     (`.msix`, PAT-844 — an MSIX is a signed ZIP container, not a PE image,
     so the publisher is extracted from the AppX SIP + `AppxSignature.p7x`
     PKCS#7 blob instead). Both call into `WinVerifyTrust` via P/Invoke to
     confirm the file has a valid signature that chains to a trusted root,
     then compare the certificate's publisher (Organization RDN, falling
     back to Common Name) against `expected_publisher` from the allowlist
     with `string.Equals(..., StringComparison.OrdinalIgnoreCase)` — an
     **exact**, case-insensitive match, not a substring or fuzzy match. Any
     failure blocks the install; there is no bypass path (PAT-305).
   - **SHA-256 pin (secondary, when present).** If the allowlist entry
     carries `pinned_sha256`, the downloaded bytes are hashed and compared;
     a mismatch is a hard failure (`PATCHED_VERIFICATION_FAILED
     label=... reason=sha256_mismatch`). If no hash is pinned, this is
     logged as a posture warning (`PATCHED_POSTURE_WARNING ...
     reason=no_pinned_sha256`) and the install proceeds on the strength of
     the Authenticode check alone — this is intentional (§5 below).
7. **Install, pinned to the verified version.** `IPackageEngine.InstallAsync`
   is called with `pinnedVersion` set to the exact version that was resolved
   and verified in steps 3–6 (the "H6 contract" — see
   `windows/src/Engine/IPackageEngine.cs`). The engine cannot resolve or
   install a different (e.g. newer) artifact than the one that passed
   verification.
8. **Audit report.** The install outcome, verified publisher, and any
   failure reason are recorded and shipped via the same
   `/v1/provenance` + `/v1/events` contract as macOS
   (`windows/src/Shared/Contract/AuditEvent.cs`,
   `windows/src/Service/AuditEventShipper.cs`), queued at
   `%ProgramData%\Patched\events-queue\` if the platform is briefly
   unreachable.

### Self Service install outcome readback

Both endpoints write the terminal result to the platform-neutral
`contracts/install-status.schema.json` contract. macOS writes
`/Library/Application Support/Patched/install-status.json`; Windows writes
`%ProgramData%\Patched\install-status.json`. Self Service reads this historical
outcome evidence and shows
`Completed`, `Already installed`, `Install failed`, `Verification blocked`, or
the terminal `Not authorised` state. The terminal execution-authority refusal
never offers Retry because a fresh signed policy decision, rather than another
package attempt, is required. Raw engine detail stays in the endpoint status/audit
path. Install outcome is separate from catalogue freshness and provenance,
which retain their existing gates and presentation.

---

## 3. macOS vs Windows — control comparison

| Control | macOS | Windows |
|---|---|---|
| Signing identity checked | Apple Developer Team ID (`expected_team_id`) | Authenticode signer (`expected_publisher`, Organization/CN RDN) |
| Verification call | `spctl -a -vv` (Gatekeeper/notarization assessment) | `WinVerifyTrust` via P/Invoke (`AuthenticodeVerifier.Verify` / `.VerifyMsix`) |
| Match semantics | Exact string equality on parsed Team ID | Exact, case-insensitive string equality (`OrdinalIgnoreCase`) |
| Container-specific handling | N/A (`.dmg`/`.pkg`/`.zip` all expose a standard code signature) | `.msix` needs a distinct path — AppX SIP + `AppxSignature.p7x` extraction, since it's a signed ZIP, not a PE image (PAT-844) |
| Transport enforcement | `https://` required or abort (`assert_https_url`) | HTTPS in all three source modes |
| Policy source | Per-label `expected_team_id` in `engine/labels/*.json`, compiled into `endpoint/labels-allowlist.txt` | `windows/windows-allowlist.json`, loaded by `AllowlistLoader`, itself signature-checked |
| Allowlist integrity | Bundle SHA-256 manifest, pinned at build time | Ed25519 signature on the allowlist file; CI re-signs after allowlist changes, the release gate re-verifies it, and the MSI packages both files; `AllowlistLoader` fails closed if the signature is missing or invalid |
| Secondary hash pin | `pinned_sha256` (mirror-published artifacts only; verified when set) | `pinned_sha256` on the allowlist entry (9/20 entries as of this writing); secondary to Authenticode, not primary |
| Version pinning after verify | Verified artifact is installed as-is (no re-resolve between verify and install) | `pinnedVersion` passed explicitly into `InstallAsync` (H6 contract, `IPackageEngine.cs`) |
| Failure posture | Fail-closed — every rejection aborts the run, no partial install | Fail-closed — every rejection blocks the install, no partial install |
| Bypass path | None | None (PAT-305: "There is NO bypass path") |
| Coverage today | 1,108 / 1,108 labels carry `expected_team_id` | 20 allowlist entries live, 9 with a pinned hash (see Known gaps) |

---

## 4. Failure modes

| Failure | Platform | Trigger | Exit code / log line | What the operator sees |
|---|---|---|---|---|
| Missing/empty expected signer | macOS | `expected_team_id` empty or missing for the label | Exit **60**; run aborted before download (T4) | `install_failed` / event reason `missing_expected_signer` in the console's device timeline |
| Non-HTTPS download URL | macOS | Resolved/static URL does not start with `https://` | Exit **63**; `PATCHED_VERIFICATION_FAILED label=... url=... reason=non_https_url` (`assert_https_url`, ~line 420) | `install_failed`, engine error surfaced in provenance record |
| Notarization/Gatekeeper assessment failed | macOS | `spctl -a -vv` returns non-zero | Exit **61**; `PATCHED_VERIFICATION_FAILED label=... expectedTeamID=... observedTeamID=... notarizationResult=failed reason=spctl_assessment_failed` | `verification_failed` event, reason `signature_untrusted` |
| Team ID mismatch | macOS | `spctl`'s `origin=` Team ID ≠ `expected_team_id` | Exit **62**; `PATCHED_VERIFICATION_FAILED label=... expectedTeamID=... observedTeamID=... notarizationResult=passed reason=teamid_mismatch` | `verification_failed` event, reason `signer_mismatch` |
| Signed-catalogue SHA-256 mismatch | macOS | `PINNED_SHA256` supplied from the signed catalogue (PAT-495) and the downloaded bytes hash differently | Exit **64**; `PATCHED_VERIFICATION_FAILED label=... expected_sha256=... observed_sha256=... reason=sha256_mismatch` | `verification_failed` event. Note: **fail-open** when no catalogue hash is available — the check is skipped, not failed (see §5) | 
| Package not in signed allowlist | Windows | `InstallRunner` finds no allowlist entry for the package ID, or the allowlist itself failed to load/verify | "not in the signed Windows allowlist — blocking install (fail-closed)" | Install outcome `Failed` in device install history |
| Trusted staging directory unavailable | Windows | `ChocolateyEngine` / `WingetCliEngine` cannot prepare a staging directory | "Refusing to ... could not prepare a trusted staging directory" | Install outcome `Failed` |
| Authenticode/publisher check failed | Windows | `WinVerifyTrust` fails, or publisher string doesn't exactly match `expected_publisher` | `AuthenticodeCheck()` / `VerifyMsix()` returns a failure `VerificationResult`; logged as "Authenticode FAILED for {PackageId}: {Error}", install blocked | `verification_failed` event; reasons map to macOS's vocabulary — `missing_expected_signer` (no signature), `signature_untrusted` (chain not trusted), `signer_mismatch` (publisher mismatch) |
| Pinned SHA-256 mismatch | Windows | `pinned_sha256` is set and the downloaded bytes hash differently | `PATCHED_VERIFICATION_FAILED label=... packageId=... expected=... actual=... reason=sha256_mismatch` | Install outcome `Failed` |
| No pinned SHA-256 (posture only) | Windows | `pinned_sha256` is unset on the allowlist entry | `PATCHED_POSTURE_WARNING label=... packageId=... reason=no_pinned_sha256`; install **proceeds** on Authenticode alone | Posture warning surfaced, install still completes if Authenticode passes |
| Allowlist tamper | Windows | Ed25519 signature on `windows-allowlist.json` fails | `allowlist_tamper_detected` event (PAT-511); `AllowlistLoader` refuses to load, falls back to an empty allowlist, not a stale/unsafe one | Every subsequent install blocked ("not in the signed Windows allowlist") until the allowlist is fixed |
| Allowlist present but unsigned (dev opt-out only) | Windows | No `.sig` file alongside the allowlist | `PATCHED_POSTURE_WARNING reason=allowlist_unsigned_dev_optout path=...` | Warning only, in dev configurations |

All of the above, on both platforms, land in the platform's audit trail via
`POST /v1/events` (`event_type: verification_failed` for the signature
failures, `posture_warning` for the two warning-only cases) — see
`docs/audit-events-contract.md` for the wire format, retention (≥90 days,
SOC 2 CC7 evidence window), and the append-only guarantee.

---

## 5. Why signature verification, not hash pinning

A SHA-256 pin only proves "this is the exact byte sequence I saw before." It
says nothing about whether that byte sequence was ever legitimate, and it
breaks on **every vendor release** — a hash pinned against version 125.0
means nothing the day the vendor ships 126.0, so a hash-only gate either
blocks all normal updates or has to be re-pinned continuously by an
automated pipeline that itself becomes a target.

A code signature, by contrast, verifies **identity**, not a specific byte
sequence. `expected_team_id` / `expected_publisher` says "this artifact was
signed by the same cryptographic identity as every previous version of this
app" — a claim that stays true release after release without any pipeline
re-pinning it. That is why signature verification is the mandatory,
fail-closed gate on both platforms, and hash pinning is kept as a
**secondary**, best-effort control: useful when present (it catches
same-version tampering that somehow carries a valid signature, or lets a
mirror assert exactly which bytes it published), but never required for an
install to proceed, because requiring it would make routine vendor releases
break the update pipeline by design.

This is explicit in the Windows engine: `ChocolateyEngine` treats a missing
`pinned_sha256` as a posture warning (`no_pinned_sha256`) and proceeds,
while a *mismatched* hash — meaning a pin exists and the bytes disagree with
it — is a hard failure (`sha256_mismatch`). The asymmetry is the point:
absence of a hash pin is normal and expected for most apps; presence of a
wrong hash never is.

---

## 6. Known gaps

Stated plainly, not smoothed over:

- **Coverage asymmetry between platforms.** The verification *mechanism* is
  at parity (see §3) — both platforms fail closed on missing/mismatched
  signing identity. The *catalogue* is not: macOS has `expected_team_id` on
  1,108 / 1,108 labels; the live Windows allowlist
  (`windows/windows-allowlist.json`) has only **20** entries, of which **9**
  carry a real `pinned_sha256`. Vendor-direct-by-default (ADR-001) makes
  closing this gap more, not less, important, because there is no mirror
  fallback underneath it.
- **The signed catalogue is not currently being produced, so the macOS
  secondary hash check (exit 64) is inert in practice.** The
  `CATALOGUE_SIGNING_KEY_B64` / `CATALOGUE_SIGNING_KEY_ID` secrets have been
  absent since ~2026-07-17 (removed as part of a cost-driven disable of the
  security stack), so `daily-vendor-verify` fails at its "Assert catalogue was
  signed" step and no signed catalogue is published. With no `PINNED_SHA256`
  available the check fails open and is skipped. This is a **defence-in-depth
  regression, not an integrity hole** — the primary control (Team ID +
  notarization, §2) is unaffected and still fail-closed on every install —
  but it should be restored (tracked under PAT-941/PAT-942).
- **Nightly vendor verification's alerting path is not wired.**
  `daily-vendor-verify` asserts a `LINEAR_API_TOKEN` that is not present in
  org secrets, so supply-chain alerts cannot currently be raised as Linear
  issues. (Its cross-source hash comparison producing false alarms against
  rolling-latest vendor URLs — 4 of 7 labels alerted on 2026-07-25 purely on
  hash drift while Team ID and notarization both passed — was fixed
  2026-07-25: identity-verified hash drift is now `advisory`, not `alert`;
  see §5 for why hash drift is expected and not, on its own, evidence of
  compromise.)
- **Nightly vendor verification coverage (PAT-974, fixed 2026-08-10):**
  previously `daily-vendor-verify` ran `verify.py --allowlisted-only`, which
  checked only 7 of 1,113 labels — nothing detected a vendor-side change
  (URL hijack, signing-identity change, notarization revocation, TLS
  downgrade) on any label outside that set. It now runs `verify.py
  --shard-count 30`: the 7 allowlisted labels are still verified every
  night, and every other label is verified once every 30 nights via a
  deterministic, stable-hash shard rotation (`verifier/verify.py`'s
  "Nightly shard selection" section; `verifier/README.md` §"Nightly coverage
  rotation"). `resolved`-type labels are not treated specially by the shard
  hash, so they are neither over- nor under-represented in the rotation.
  The full 1,108-label manifest is now covered once every 30 nights instead
  of never; the shard width is retunable via the
  `VENDOR_VERIFY_SHARD_COUNT` repo variable without a code change.
- **Nightly vendor verification scope now targets the dashboard catalogue,
  not the full manifest (PAT-1296, 2026-08-13):** `engine/labels/` is a
  resolver pool, not itself a verified surface — the dashboard's Software
  Catalogue (`catalogue_apps`) is the definitive app list. `verify.py` now
  accepts `--catalogue-labels FILE` (a dashboard `/admin/catalogue` JSON
  dump, fetched by `daily-vendor-verify.yml`'s `verify` job via the same
  prod-01 relay used elsewhere in that workflow); when it parses, this
  REPLACES `--shard-count` selection for the run — only labels in the
  catalogue (macOS-verifiable rows only: `platform` `both`/`macos_only`)
  plus allowlisted labels are verified, rather than spreading effort evenly
  across every label in the 1,108+ manifest including apps nobody has
  chosen. A relay failure or a malformed fetched file falls back to the
  `--shard-count` rotation above, unchanged. Selection scope only —
  `patched.allowlisted`, `ci/validate-labels.py --emit-allowlist`,
  `endpoint/labels-allowlist.txt`, and `windows/windows-allowlist.json` are
  untouched (see `verifier/README.md` §"Catalogue-driven selection").
- **Retired 2026-09-30 (PAT-2304); kept as history.** None of the signing,
  re-verification or packaging described in this bullet runs any more.
  **Windows allowlist signing and delivery were operating; endpoint tamper
  refusal still needed an end-to-end acceptance check.** When
  `windows/windows-allowlist.json` changes on `main`,
  `sign-windows-allowlist.yml` signs it with the repository-held Ed25519 key,
  verifies the result against the public key pinned in `Ed25519Verifier.cs`,
  and opens a PR containing only `windows-allowlist.json.sig`. PR #431
  (`162d267f`, 2026-08-10) is direct evidence that an allowlist change invokes
  this automatic re-signing path. `windows-agent-release.yml` independently
  verifies the committed signature immediately before the build, and
  `Product.wxs` packages the JSON and its 64-byte signature together into
  `%ProgramData%\Patched`.

  WIN-STAGING has loaded the packaged signature repeatedly through the real
  `AllowlistLoader` and reported all 13 entries, proving the valid installed
  path. **PAT-976 closed 2026-08-11**: a standalone harness built from the
  real production `AllowlistLoader`/`AllowlistSignatureVerifier`/
  `Ed25519Verifier` sources was run directly on WIN-STAGING (a real ARM64
  Windows endpoint) against the box's actual currently-deployed
  `windows-allowlist.json` + `.sig`, isolated from live service state:

  1. The real signed allowlist (13 entries) loaded and verified cleanly.
  2. A copy with the JSON content deliberately tampered (a malicious entry
     appended) but the original, unmodified `.sig` left in place — the exact
     attacker model this control defends against, write access to the file
     but not the private signing key — was refused: `AllowlistLoader` threw
     `InvalidOperationException: Allowlist Ed25519 signature verification
     failed`.
  3. A copy with the `.sig` removed entirely (no dev opt-out) failed closed
     to an empty allowlist.

  The unit suite already covered this logic with synthetic keys; this run is
  the missing piece, the same code path exercised against the real pinned
  production key and the real deployed file, on a real endpoint, not a
  synthetic fixture.

  Separately (not a PAT-976 gap): WIN-STAGING's `InstallRunner` has never
  processed a real winget-source pending install for any tenant — tenant-zero
  currently has zero winget-source apps enabled, so `GET
  /v1/allowlist/pending-installs` always returns nothing installable. The
  allowlist/signing gate is proven to permit lookups correctly (the loaded
  13 entries include ordinary packages like `notepadplusplus`); what's
  missing is a tenant ever having a mandatory Windows app configured to
  install, which is PAT-1162's remit, not allowlist signing.

  Authenticode publisher verification (§2) remains the independent primary
  package-identity control and fails closed regardless of allowlist-signature
  state.

- **PAT-900 — Windows `expected_publisher` strings are not yet all
  confirmed against real signing certificates.** Because the publisher match
  is exact (§3), a wrong string in the allowlist **blocks** the install
  rather than silently passing it — a false negative (safe-but-broken), not
  a false positive (unsafe-but-working). That fails safe, but it still means
  every `expected_publisher` value needs to be derived from an actual signed
  installer (e.g. via `osslsigncode verify` against a real downloaded
  artifact — see the Notepad++ and 7-Zip entries in
  `docs/windows-mirror-pipeline.md` for worked examples of this process,
  including a case where the real vendor binary turned out to carry no
  signature at all), not hand-authored from a vendor's marketing name. Until
  every entry is confirmed this way, a currently-blocked install may simply
  need its allowlist string corrected rather than indicating an actual
  supply-chain problem — but this must be verified per entry, not assumed.
