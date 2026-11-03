# Agent release runbook

Covers: macOS collector agent, macOS endpoint daemon, Windows agent.
Ticket: PAT-507.

## Release authority

Release approval is currently a **process convention, not a platform-enforced gate** (PAT-1092). The `release-gate` GitHub Environment referenced by each release workflow exists but has zero protection rules configured, so nothing pauses a publish for review: anyone with push access to a release tag can trigger a publish today. Andy Bridson remains the intended sole release approver by convention and discipline, not because the platform enforces it.

This is a billing-plan limitation, not a config oversight: private repos need GitHub Enterprise for the "required reviewers" environment protection rule, and this repo is on a Team plan (confirmed by a 422 - "Please ensure the billing plan supports the required reviewers protection rule" - when attempting to configure one). GitHub Enterprise would restore platform enforcement here; upgrading is Andy's cost decision, tracked under PAT-1092. Restoring non-author review gates estate-wide more broadly is tracked under PAT-941.

## Release triggers

| Agent | Tag pattern | Workflow |
|---|---|---|
| macOS agent (collector + endpoint bundle) beta | `macos-agent-vX.Y.Z-beta.N` | `macos-agent-release.yml` |
| macOS endpoint daemon (standalone rebuild) | `endpoint-v*` | `release-endpoint.yml` |
| Windows agent beta | `windows-agent-vX.Y.Z-beta.N` | `windows-agent-release.yml` |
| macOS or Windows beta to stable | manual `agent-release-promote.yml` dispatch | `agent-release-promote.yml` |
| macOS endpoint PKG (signed, future) | `endpoint-v*` | `sign-notarize.yml` |
| macOS endpoint PKG, signed (future, additional asset) | `macos-agent-v*` | `macos-agent-release.yml`'s `sign-pkg` job |

**PAT-1073:** `macos-agent-release.yml` now has a third job, `sign-pkg`, alongside `build` and
`publish`. It attempts to build a Developer-ID-signed, notarised `.pkg` for the endpoint
component (same `dist/patched-updater` layout and `tools/build-pkg.sh` tool `sign-notarize.yml`
already uses for `endpoint-v*`) and, when it succeeds, attaches it to the same
`macos-agent-v*` release as a bonus asset alongside the interim unsigned tarball. It does **not**
yet cover the collector — only `sign-notarize.yml`'s and `sign-pkg`'s narrower endpoint-only
`.pkg` scope is wired up; packaging the full agent (collector + endpoint) as one signed `.pkg`
needs `tools/pkg-scripts/postinstall` extended to also lay down the collector, which is a
packaging-semantics decision left for Andy rather than guessed at here.

Unlike `sign-notarize.yml` (which quietly skips signing and ships an unsigned `.pkg` with a
`::notice::` when certs are absent — a deliberate, reviewed choice for its own pipeline), the
`sign-pkg` job **fails loudly** when `DEVELOPER_ID_INSTALLER_CERT_P12_B64` (or the notarisation
secrets) are missing, and never uploads or publishes a `.pkg` in that case. It is independent of
`build`/`publish`: its failure never blocks the interim unsigned tarball release, which remains
the working, needed-today release path. Until Andy's Apple Developer ID enrollment (PAT-6/7/9)
lands, `sign-pkg` is **expected** to fail red on every `macos-agent-v*` run — that is the honest,
visible status of "scaffolded, gated on cert enrollment," not a bug.

**PAT-1126:** `macos-agent-v*` is the only tag that produces a deployable, decommission-capable
macOS install — its tarball always bundles the endpoint/ update + decommission daemons alongside
the collector (built via the same `tools/build-bundle.sh` as `endpoint-v*`, so the two stay
byte-for-byte consistent on the endpoint half). `endpoint-v*` still exists and still publishes
its own tarball — deploying it standalone is a real, supported path when the endpoint bundle
alone needs a point release (e.g. a `patched-update.sh` fix that doesn't touch the collector) —
but it is never sufficient on its own for a fresh macOS install: it has no collector, so it
never uploads inventory. There is no longer a `macos-agent-v*` artifact that omits the endpoint
bundle; collector-only is not a supported end state for any macOS install (see
`macos/README.md`).

**PAT-1777:** the Windows MSI is also built on every pull request, and push to `main`, that
touches `windows/installer/`, `windows/src/`, the solution, `requirements.txt`, the release
workflow or the shared build action. `windows-msi-build.yml` runs the same build as the release
through `.github/actions/windows-agent-msi`, a composite action with two phases: `prepare`
(Setup .NET, publish Service, Python dependencies) and `package` (credential guard,
Build MSI, MSI File table assertion). `windows-agent-release.yml` calls the same two phases,
back to back, so a WiX error such as WIX0012 fails the pull
request rather than the release. The PR check is build only: fixed `0.0.0` and `0.15.1-beta.1` versions through
`resolve-release-version.sh`, a read-only token, no secrets, no signing and nothing uploaded or
published. Change the build steps in the action, not in either workflow; the trust key gate,
HMAC and Ed25519 signing and their assertions stay in
`windows-agent-release.yml` (`ci/test_windows_msi_build_workflow.py` locks that order).

**PAT-2350:** the shared action accepts the resolver's three-part stable/build-only
identity or four-part numeric beta identity with revision `1..99`. InformationalVersion
must use that exact identity plus a full 40-hex commit SHA; MSI ProductVersion and
FileVersion keep their existing three-part and four-part-with-final-zero guards.
The regression runs the actual action validation under Bash with real resolver output,
including beta boundaries and malformed or shell-injection inputs. Both matrix entries
compile Service and the MSI on Windows; a stable-only build cannot prove beta release inputs
work. Headless upgrade verification covers service continuity and fresh inventory; verify
that the first-party tray binary, process and exact startup Run values are absent. See
`windows/installer/README-install.md`. Periodic cleanup checks offline user hives after
a later logon loads them; never load them offline solely for cleanup.

Windows beta tags use `X.Y.Z-beta.N` with `N=1..99`; their installable and wire
identity is numeric `X.Y.Z.N`. Channel is separate registration metadata. The
stable promoter retains that exact four-part identity and bytes. The MSI has
only three ProductVersion fields, so the resolver maps base `X.Y.Z` to
`(X+2).Y.(Z*100)` and beta revision `N` to `(X+2).Y.(Z*100+N)`. That mapping
orders successive beta revisions and keeps the next base patch greater than
every beta revision. To fit MSI's 16-bit third field while reserving 100 values,
beta semantic patch is bounded to 654, the next stable base patch (655) remains
representable, and beta sequence is bounded to 99; major is bounded to 253 and
minor to 255. The legacy MSI epoch remains `+2`; AssemblyVersion and
FileVersion use the same numeric mapping with a fourth `.0` field. Thus
`0.13.2-beta.2` has installable identity `0.13.2.2`, MSI ProductVersion
`2.13.202`, and FileVersion `2.13.202.0`. InformationalVersion carries the
four-part identity plus commit SHA.
Although Windows ARP derives DisplayVersion from the epoched MSI ProductVersion,
the running service reports its own installed-app entry with the semantic release
parsed from that informational ProductVersion. Other installed-app entries retain
their registry DisplayVersion unchanged.

Menu-bar tags must also use strict numeric `X.Y.Z` versions. Release CI sends
that resolved value to PatchedUpdater as its `CFBundleShortVersionString` and
`CFBundleVersion`, then reads the staged app's plist before creating the
release zip. Local builds retain project defaults and do not require release
arguments.

## What happens when a tag is pushed

1. CI builds the release artifact (tarball or MSI).
2. CI computes SHA-256, signs the artifact with HMAC-SHA256 using the `ARTIFACT_SIGNING_KEY` secret, and uploads the artifact + SHA256SUMS + `.hmac` signature as a workflow artifact.
3. CI runs the `publish` job immediately, with no pause and no approval notification - the `release-gate` environment has no protection rules configured (see "Release authority" above, PAT-1092).
4. By convention, Andy reviews the build log (confirm build is clean, no unexpected file changes) before or shortly after a tag push, since nothing technical blocks publishing on that review happening.
5. CI publishes the GitHub Release with the artifact, `SHA256SUMS`, and the `.hmac` signature asset attached.

## Beta publication and stable promotion (PAT-2003)

Push `macos-agent-vX.Y.Z-beta.N` or `windows-agent-vX.Y.Z-beta.N` (N=1..99).
Both workflows build a numeric `X.Y.Z.N` artifact, upload it to the authenticated
per-device API artifact store, register it on `channel=beta`, and publish a GitHub
prerelease whose notes state channel, installable version and SHA-256. GitHub
Releases are an audit/download record, not the endpoint delivery path. Stable
releases are not built or registered directly.

The manual `agent-release-promote` workflow takes platform, exact four-part
identity and the expected lowercase SHA-256. It downloads the existing beta
asset, verifies SHA256SUMS and HMAC, stages those exact bytes in a draft stable
release, and signs a new `channel=stable` metadata envelope
(the metadata signature changes because it binds channel/URL; the binary SHA
and HMAC do not). Both platforms upload those same bytes to the stable API
artifact route before calling `POST /admin/agent-releases/promote`, so the
authenticated download is available before stable activation. Only after that
gate accepts the candidate does the workflow publish the staged release; a
refusal leaves it as a non-public draft. A retry rejects an existing public
release and verifies a draft's target, artifact, SHA256SUMS and HMAC before
reusing it. The endpoint call remains behind the
existing Tailscale-to-SSH path; admin token extraction remains on
`example-prod-host`. Any failed verification, artifact conflict, missing soak
evidence or non-2xx API result fails the job.

Safe dry run: use a fork or test-only environment and a generated non-production
artifact signing key; dispatch the beta release with `build_only=true` on
Windows to test the build/version boundary, run the static workflow tests, and
review the promotion workflow YAML without dispatching it. A real promote
dispatch is an external release operation, not a dry run; it requires an
existing registered beta artifact and PAT-2004 soak evidence.

Windows self-update requires verified effective channel policy before requesting
an artifact (PAT-2351). A missing signed cache envelope, failed cache verification
or rejected tenant/device binding records `self_update` / `artifact` /
`update_policy_unverified` and leaves the installed agent running. The reporting
default of stable does not authorise a download or restart. Config polling
continues independently; once it accepts verified policy, the normal hourly
self-update check uses that policy and clears this degraded reason after artifact
verification succeeds. A valid signed cache can authorise the startup check
without waiting for the network. Signed stable, beta and version-pin selection
remain intact, including requests for an intentionally older pinned artifact;
the pending-update applier's existing refusal to install an older version remains
in force.

Before the Windows applier launches a staged MSI it also checks who can write the
staged files (PAT-2400). The updates root, the version directory, the installer and
the marker must each be owned by SYSTEM or Administrators, carry no write-capable
Allow ACE for any other principal, and not be a reparse point. This is the rule
`SecureStagingDirectory` already applies when staging. A failure records
`self_update` / `apply` / `staged_<object>_<why>`, where the object is `updates_root`,
`version_dir`, `installer` or `marker` and the reason is `untrusted_owner`,
`untrusted_acl`, `reparse_point`, `wrong_type`, `acl_unreadable` (the owner or DACL
could not be read, which is what a DACL denying SYSTEM produces) or `unverifiable`.
Nothing is launched and the installed agent keeps running.

The untrusted object is then taken off its path so the next check can restage. A
file, a link or an empty directory is unlinked. Any other directory is renamed whole
to `updates-untrusted-<random>` under `%ProgramData%\Patched` and is never read or
deleted, because its contents may still be writable by whoever planted it. When the
rename or delete is refused, as it is for an object owned by a standard user whose
DACL denies SYSTEM, the service enables SeTakeOwnership, SeBackup and SeRestore on
its own thread for that one call, makes SYSTEM the owner of that single object, gives
it a SYSTEM and Administrators only DACL, and retries. Children are not touched and a
reparse point is only ever unlinked. The updates root gets this check on every
service start, with or without a marker, so a directory planted before the state root
was repaired no longer leaves staging stuck on `stage_directory_untrusted`.

If the object cannot be removed the reason gains `_removal_failed` and is recorded
again on every start. At most eight quarantined directories are kept. With eight
present nothing more is moved aside, the reason gains `_quarantine_full` instead, and
the path stays failed closed until an operator inspects and deletes the
`updates-untrusted-*` directories; the agent never deletes them itself. A
`staged_updates_root_*` reason is withdrawn on the first start that finds the root
trusted or absent, and any `staged_*` reason once nothing is pending or the pending
update passes the check. Other `apply` reasons are left alone. An untrusted staged
directory that is not the pending update and cannot be removed is reported separately
as `self_update` / `staged_cleanup` / `untrusted_child_<removal_failed|quarantine_full>`.

The applier binds the release channel only when verified channel policy is available
at apply time, which in practice means a valid signed config cache from an earlier
run. Then a staged envelope signed for another channel is discarded with
`marker_envelope_channel_mismatch` and restaged under the current policy. With no
verified policy the applier logs that the channel is not bound and applies a validly
signed newer release as before. That limitation is deliberate: it does not relax the
download rule above, since nothing is requested or staged without verified policy.

This applies to Windows only. macOS has no self-update apply path yet (PAT-2002).

## Pre-release checklist (before pushing a tag)

- [ ] All CI checks green on `main` (CodeQL, Semgrep, label validation, dep scan)
- [ ] `CHANGELOG` or commit history reviewed for security-relevant changes
- [ ] No open PAT-493 blockers that affect this agent
- [ ] `ARTIFACT_SIGNING_KEY` is set on the canonical repo - the build's "Assert artifact was signed when expected" step hard fails if it is not
- [ ] SHA-256 and the `.hmac` signature will both be published - confirm `SHA256SUMS` and `<artifact>.hmac` both appear in the release assets
- [ ] Windows: the install directory ACL has been read on a device, after a fresh install and after an upgrade over a real prior version (see below)

### Windows install directory ACL (PAT-2399)

The MSI sets a protected ACL on `%ProgramFiles%\Patched` and `Patched.Service.exe`. A green
build proves the ACL is in the package, not that a device ends up with it, so read it on an
installed device. From an elevated PowerShell:

```powershell
$dir = "$env:ProgramFiles\Patched"
(Get-Acl $dir).Sddl                       # must contain D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)
(Get-Acl $dir).AreAccessRulesProtected    # True
icacls $dir; icacls "$dir\Patched.Service.exe"   # SYSTEM (F), Administrators (F), Users (RX); no (I) on any line
(Get-Service 'Patched Agent').Status      # Running
(Get-Content "$env:ProgramData\Patched\agent-health.json" | ConvertFrom-Json).Active.install_integrity   # empty
```

Do this twice: on a clean device, and after upgrading a device that had the previous release
(whose directory shows the inherited Program Files ACL, every line marked `(I)`). Then check
that uninstall still removes the directory. `windows/installer/README-install.md`, "Install
directory ACL", has the expected output in full and what the service reports when the ACL is
wrong.

## Verifying a release before deploying

Use `tools/verify-agent-release.py` (stdlib only, no dependencies). It fetches
the `.hmac` signature asset for the release and recomputes HMAC-SHA256 over
the downloaded artifact using `ARTIFACT_SIGNING_KEY` - this is the primary
check (PAT-892). The SHA256SUMS check is kept as a secondary check that
catches transport corruption, but SHA256SUMS alone is generated by the same
CI run that produced the artifact, so it is not a signature: an attacker who
can push a tampered release asset can also regenerate a self-consistent
SHA256SUMS to match it. Do not rely on `shasum -a 256 -c SHA256SUMS` alone.

You must supply the `ARTIFACT_SIGNING_KEY` value to the tool, via the
`ARTIFACT_SIGNING_KEY` environment variable or `--key-file PATH`. Never pass
it as a plain command-line argument - it would be visible to other processes
on the host via `ps` and often ends up in shell history. Ask Andy for the key
out of band; it is not committed anywhere in this repo.

```sh
# macOS - verify a downloaded tarball
ARTIFACT_SIGNING_KEY=... python3 tools/verify-agent-release.py \
  --release macos-agent-v0.6.0 \
  --file patched-agent-macos-0.6.0.tar.gz

# macOS - download and verify in one step, key from a file instead of env
python3 tools/verify-agent-release.py \
  --release macos-agent-v0.6.0 \
  --file patched-agent-macos-0.6.0.tar.gz \
  --download \
  --key-file /path/to/signing.key

# Windows - verify the MSI
ARTIFACT_SIGNING_KEY=... python3 tools/verify-agent-release.py \
  --release windows-agent-v0.3.0 \
  --file PatchedAgent-0.3.0.msi
```

Exit 0 = verified (HMAC signature and SHA-256 both match). Exit 1 = signature
mismatch, missing `.hmac` asset, missing signing key, checksum mismatch, or
error - do not deploy on a non-zero exit. The tool fails closed: it refuses
to fall back to a checksum-only check if the `.hmac` asset or the signing key
is missing.

## MDM deployment (Intune)

1. Download the release asset and run `verify-agent-release.py` before uploading to Intune.
2. In Intune, set the package hash in the LOB app configuration where supported (Win32 apps support SHA-256 detection rules).
3. For macOS, deploy via a shell script assignment; no silent PKG path until PAT-7 / PAT-9 land.
   Use the `macos-agent-v*` tarball's `install.sh` — it installs the collector and the endpoint
   bundle together in one script run. Do not construct an Intune deployment that pushes only the
   collector's raw scripts (PAT-1126): a Mac with no endpoint bundle has no decommission
   mechanism and never self-removes, which matters most for time-boxed Endpoint Assurance
   assessment installs.
4. After rollout, confirm agent check-ins appear in the platform within 24 hours.

## Current signing status

| Agent | Code-signed? | Notes |
|---|---|---|
| macOS collector tarball | No | Interim unsigned. Signed .pkg pending PAT-9 / PAT-7. |
| macOS endpoint daemon | No | `sign-notarize.yml` (`endpoint-v*`) and `macos-agent-release.yml`'s `sign-pkg` job (`macos-agent-v*`, PAT-1073) are both ready; both are blocked on Developer ID certs (PAT-7) and fail loudly rather than shipping unsigned when run today. |
| Windows MSI | No | Authenticode signing blocked on OV/EV cert (PAT-50). |

Until Developer ID / Authenticode code-signing is in place, integrity depends on the `ARTIFACT_SIGNING_KEY` HMAC signature (verified via `tools/verify-agent-release.py`, PAT-892). The `release-gate` environment does not enforce an approval today (PAT-1092) - see "Release authority" above. The published SHA-256 alone is not sufficient - it is generated by the same CI run that produced the artifact, so it cannot detect a compromised release, only transport corruption. Do not deploy a release whose HMAC signature you have not independently verified.

## Signing path (future)

- **macOS:** Configure `DEVELOPER_ID_INSTALLER_CERT_P12_B64`, `DEVELOPER_ID_APPLICATION_CERT_P12_B64`, `DEVELOPER_ID_CERT_PASSWORD`, `SIGNING_KEYCHAIN_PASSWORD`, `APPLE_ASC_API_KEY_P8_B64`/`_ID`/`_ISSUER_ID`, and `APPLE_TEAM_ID` secrets in the repository. Once set, `sign-notarize.yml` activates and produces a signed, notarised `.pkg` automatically on each `endpoint-v*` tag, and `macos-agent-release.yml`'s `sign-pkg` job (PAT-1073) activates the same way on each `macos-agent-v*` tag, attaching the signed `.pkg` as an additional asset alongside the interim unsigned tarball. Until then, `sign-pkg` fails loudly by design (see "Release triggers" above) rather than shipping an unsigned `.pkg`.
- **Windows:** Add an Authenticode signing step to `windows-agent-release.yml` once an OV/EV cert is acquired (PAT-50). The `signtool.exe` call goes after the `Build and verify MSI` step (the shared action's `package` phase, which builds the MSI and checks its File table) and before `Locate MSI and compute checksum`, in the release workflow only: the PR check holds no signing material.

## Incident response

If a released agent binary is suspected to be tampered:

1. Immediately yank the GitHub Release (convert to draft or delete the release — does not delete the tag).
2. Post a security advisory in the repository.
3. Notify affected tenants via the platform (PAT-508).
4. Rebuild from a clean checkout, verify the SHA-256 matches the original, and re-release with a bump (e.g. `v0.6.1`) explaining the incident.

See PAT-508 for the full revocation and incident response runbook.
