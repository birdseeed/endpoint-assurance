# PAT-2368 endpoint technical readiness, 3 October 2026

**macOS: not ready for customer release. Windows: not accepted for customer release.**
This bounded leaf completes the report and synthetic checks, not ticket acceptance.
Base: `7302d8eb0c3b54c03ebf242469cad0d2c68145b0`; product source unchanged.
Requested tier: `gpt-6-astra`, high, fresh leaf. CLI headers confirm model `gpt-6-astra` and reasoning effort `high`.
Parent owns finding adjudication, complete NVIDIA review and ticket state. No commits,
publication, endpoint execution, credentials, permissions or retirement behaviour were changed.

## Evidence identity and limits

Evidence root `E` is workspace-root `.claude/linear-runs/evidence/`.
The complete `E/mvp-first-step-20261002/PAT-2368-body.md` defines acceptance.
The interrupted `PAT-2368-leaf.log` supplies the prior bounded source audit and Windows test receipts;
only targeted continuation excerpts were used, not another whole-source crawl.
Machine-readable hash/results receipt: [PAT-2368-checks.json](PAT-2368-checks.json).

| Platform | Exact candidate / artifact | Evidence accepted for this report |
| --- | --- | --- |
| Mac | `macos-agent-v0.19.24-beta.2`, wire `0.19.24.2`, base above; published tar 404,924 bytes, SHA256 `b0d0d4806be245058449fa5f610c9aac056b7c0fbe2e6d721ab244b06fe509aa` | Rehashed retained published tar and all 32 extracted regular files; all 86 Mac review manifest paths/deletions and 57 retained preflight evidence hashes match. |
| Windows | `windows-agent-v0.15.1-beta.4`, wire `0.15.1.4`, MSI `2.15.104`, same base; MSI 37,474,304 bytes, SHA256 `e15f3623b14e098dead929e3451736fe10bf6f0fe459818319e6e243cc5ee00d` | All 11 retained Windows source snapshots match. Prior publication receipt verifies four asset digests, pinned Ed25519 claims and server-stored bytes. MSI download/signature verification was not repeated here. |

Mac review: `E/macos-beta2-preflight-20261002/{mac-review-manifest.json,all-chunk-outcomes.json,review-adjudication.md}`.
All 22 recorded NVIDIA chunks exited 0; 46 notes were adjudicated by the parent.
That was an 86-path release-delta review, not whole-agent security clearance or a Windows review.
Windows evidence: `E/windows-beta4-{source,publication}-20261002/`; publication workflow
37021781520.
HMAC sidecar presence and CI success are not independent HMAC recomputation.

Mac installed receipt: `E/macos-beta2-local-install-20261002/accepted-installed-canary.md`
and `installed-readback.json`: owner-run installer exit 0, 23 installed file matches,
loaded collector/upload/update/config/posture jobs, subsequent real collection and HTTP 200 upload,
server observation of `0.19.24.2`. These are retained 2 October receipts, not a new installed test.
Retired catalogue jobs/cache were absent; no prior-presence/removal transition was demonstrated.
The backup exists in the prior receipt; restore was not exercised.
Windows publication explicitly leaves authenticated metadata/download and installed beta.4 unproved;
the later receipt records HOMESERVER reporting beta.4 and WINDOWS11 still at `0.0.0-dev`. Those are partial reporting observations, not a demonstrated MSI upgrade or uninstall/rollback.

## Findings for PAT-2081

All findings below belong to the PAT-2081 adversarial pass.
Identifiers are local audit references, not invented Linear tickets. Parent must deduplicate/link them.

**M1, high, confirmed command-selection defect: user-writable PATH precedes trusted tools.**
`endpoint/patched-update.sh:31,83`, `patched-fetch-config.sh:29,165` and
`patched-decommission.sh:109,159` prepend `/usr/local/sbin:/usr/local/bin` and invoke bare
`mkdir`/`dirname`/other tools as root. Update's first calls precede `verify_bundle` at line 281.
Update/config jobs remain loaded despite catalogue retirement. All three PATH statements match
the hash-verified published bundle. Read-only directory metadata on this Mac shows
`/usr/local/bin` uid 501 mode 0755 and `/usr/local/sbin` uid 501 mode 0775; `/usr/local` is root 0755.
A process controlling those directories can supply a command selected by the privileged script.
The fixture evaluates each actual PATH statement with those two prefixes mapped to scratch,
runs a harmless `mkdir` stub without privilege, and fails the secure-resolution assertion three times.
Its system-only PATH control passes. This establishes selection, not an executed root exploit.
Recommendation: use a fixed system-only PATH and absolute privileged tools before any script work;
review the shipped sibling scripts together. Hold Mac customer rollout until the regression passes
and the repaired installed daemon is checked. Manifest verification cannot protect a command called first.

**M2, high, unsafe installed entrypoint ancestry: root-owned file in a user-owned directory.**
`macos/install.sh:199-201` installs root-owned scripts under `/usr/local/bin` without securing
that existing parent; `macos/com.patched.{collect,upload}.plist` directly execute those paths.
The bootstrap plist uses the same directory. The directory metadata above and prior root-owned
installed-file receipt establish the mismatch. File ownership alone does not prevent its directory
owner replacing the name. No installed file was replaced and no privileged exploit was attempted.
Recommendation: move privileged entrypoints into an installer-verified root-owned tree, updating
plists/uninstall/migration coherently; do not seize a Homebrew-owned directory wholesale. Require a
non-admin replacement-denial test on the installed canary. M1's PATH fix alone cannot close this route.

**W1, high-impact candidate, Windows legacy-state provenance requires real Windows validation.**
`windows/src/Service/Program.cs:35` ignores the unsafe-DACL repair result from
`StateDirectoryBootstrap.EnsureHardened()`. The bootstrap intentionally repairs only the root.
`Worker.cs:254` applies the pending marker before a fresh bootstrap download.
`PendingUpdateApplier.cs:239-249,335-377,517-525` checks exact path/reparse containment and
the marker's own hash, then launches MSI; it does not reverify a signed envelope or child ACL there.
Pre-existing attacker-planted marker/MSI content under an admin-owned but formerly writable root
therefore needs explicit rejection evidence. This is conditional on an affected legacy DACL and
plantable descendants, not proof that a current clean MSI grants that access.
Recommendation: block upgrade acceptance on a real Windows fixture of that exact transition,
with a recording launcher and no real malicious MSI execution. If confirmed, discard untrusted
pending state after repair and re-stage from authenticated metadata, with child-chain trust checks.
Mac-hosted tests cannot settle Windows ACL inheritance or whether the legacy setup is reachable.

## Retained trust boundaries

| Boundary | macOS | Windows |
| --- | --- | --- |
| Request credentials / replay | `patched-upload.sh` and bootstrap use file-backed secret reads, bearer headers via stdin and HMAC v3 method/endpoint/time/nonce/body binding; synthetic helper checks pass. Root execution is still undermined by M1/M2. | Credential Manager/DPAPI and restricted fallback files; HMAC request signing, credential snapshots and host isolation have focused tests. Real ACL/DPAPI behaviour is not proved on this Mac. |
| Policy / update | Pinned Ed25519 config, tenant/device binding, durable rollback floor; bootstrap artifact HMAC requires endpoint-held `artifact-key`. HMAC authenticity is not Apple signing. | Bootstrap verifies pinned Ed25519 metadata binding version/platform/channel/URL/hash, limits download origin, uses the no-redirect artifact client and checks bytes before staging. Pending apply depends on trusted staged state, hence W1. |
| Native signing | Published tar is interim unsigned; optional endpoint-only signed pkg does not cover the full collector install. No accepted Developer ID/notarisation proof. | Published MSI is interim unsigned; Authenticode check in BootstrapUpdater is deferred. Ed25519 metadata does not establish OS publisher validation. |
| Payload / privacy | Existing usage fixtures, tooling byte budgets and incomplete-scope semantics retained; canary's partial browser/FDA state remains partial. | Same neutral contract and fail-status tooling budgets; serializer and poster tests are synthetic. No new production inventory was read. |
| Removal / recovery | Signed decommission gate, staging and purge fixtures pass. Bootstrap N-1 restores collector symlink after collect/upload failure only; full installer/daemon rollback and backup restore remain unproved. | Decommission/purge/handoff and pending-update retry tests exist. Bounded MSI retries are not rollback; actual service/binary replacement, uninstall and restore remain unproved. |

The live agent self-update/config/artifact-signing rails remain dependencies. Broad package
catalogue publishing, pollers and legacy execution stay retired; no new catalogue work is proposed.
Retained artifact HMAC, artifact metadata and server agent-config keys are distinct. Key-custody/HSM decisions remain owner gates; do not reintroduce retired catalogue keys to follow an obsolete migration plan.

## Synthetic verification

Fresh continuation commands, exact logs and hashes are in the adjacent receipt. Shell fixtures ran
under their declared zsh/bash interpreters, using scratch roots and synthetic credentials.

| Command / suite | Exit and result |
| --- | --- |
| `python3 docs/audits/pat2368-privileged-path-regression.py` | **1**, three vulnerable production-PATH subcases fail; system-only control passes. Intentionally red reproducer, outside automatic test discovery. |
| `python3 endpoint/test-verify-agent-config.py` | 0; 42 pass, including tamper, wrong key/tenant, rollback and revoked policy. |
| `python3 endpoint/test-agent-update-channel.py` | 0; 9 pass, including unverified/foreign/rollback/restart policy. |
| `zsh macos/lib/test-patched-creds.zsh` | 0; 20 pass, including secret-free argv and encoding. |
| `zsh endpoint/test-decommission-staging.zsh` / `test-decommission-gate.zsh` | Both 0; 45 / 87 pass. |
| `zsh macos/test-uninstall-purge.zsh` / `bash endpoint/test-uninstall-cleanup.sh` | Both 0; 9 / 20 pass. Scratch cleanup is not installed removal. |
| `python3 ci/test_usage_evidence_contract.py` | 0; 3 pass, 2 skip: external schema and optional payload dump not supplied. |
| `python3 verifier/test_sign_artifact_metadata.py` | 0; 9 pass with synthetic signing material. |
| `python3 ci/test_legacy_workflow_quarantine.py` | 0; quarantine assertions pass. |
| Prior leaf Shared filtered .NET suite, same source | 0; 260 pass / 1 skip; macOS net10 host. |
| Prior leaf Service filtered .NET suite, same source | **1**, aborted with 0 executed: .NET 8 runtime absent. |
| Prior leaf Service, explicit `DOTNET_ROLL_FORWARD=Major` | 0; 275 pass / 3 skip on .NET 10. Surrogate only. |

The receipt preserves complete .NET filter commands and TRX/log hashes. Windows-specific tests may
return early on macOS without being marked skipped; pass counts do not prove Windows ACLs,
WinVerifyTrust, MSI, Credential Manager or services. No new full CI, Swift build, staging VM,
live authenticated download, installed exploit, uninstall or rollback test ran in this continuation.

## Exact remaining acceptance gates

1. **Mac trust:** fix M1/M2 in a separately authorised implementation, obtain parent NVIDIA review,
   pass the reproducer plus installed standard-user replacement/command-shadow rejection checks.
   Recommend keeping the existing one-Mac canary isolated from broader rollout; no guaranteed self-heal.
2. **Mac signing/download:** owner provides signing/notarisation setup for the complete install path.
   Record exact artifact hash, expected Developer ID identity, `pkgutil --check-signature`,
   `spctl --assess --type install` and stapler validation where applicable. On one authorised synthetic
   staging Mac, exercise authenticated metadata/download and reject tampered bytes/HMAC, wrong-scope
   or downgraded policy before execution. Existing manual tar install is not bootstrap download proof.
3. **Mac removal/rollback:** on that disposable staging Mac, install over a recorded prior version,
   capture actual loaded paths/version and fresh accepted upload, exercise N-1 failure recovery,
   then signed scheduled/immediate decommission and explicit purge/retain outcomes. Verify jobs,
   files, credentials and outside sentinels; restore the prior known-good install and verify upload.
   A root-only backup receipt alone is insufficient, so recommend this before any additional device.
4. **Windows installed trust:** on one explicitly authorised Windows staging VM, validate W1 and
   run the focused suites on supported .NET 8/Windows. Install exact beta.4 over beta.3; verify every
   installed binary's ProductVersion/FileVersion, LocalSystem service start, absence of retired tray/
   Self Service launch entries, helper ACL checks, crash events, fresh payload and beta.4 server identity.
   Recommend this single-VM gate rather than inferring success from two prior beta-selected devices.
5. **Windows signing/download:** owner certificate/key installation and a signed replacement artifact
   are required for Authenticode acceptance. Verify expected publisher, chain/timestamp and installed
   signatures; exercise authenticated download, redirected/foreign origin, bad metadata/hash and
   interrupted staging rejection. Publication's server-side hash check does not satisfy this gate.
6. **Windows removal/rollback:** test signed decommission, credential/file purge versus retention,
   exact old-tray cleanup limits, MSI uninstall, failed upgrade and owner-controlled restore of the
   prior signed package; verify service/version/upload after recovery. No automatic rollback claim.
7. **Parent completion:** adjudicate/link M1/M2/W1 to PAT-2081, independently review this full audit
   and any resulting fixes with NVIDIA, and record installed receipts before closing PAT-2368.
   Signing purchases, endpoint actions, keys and release promotion remain owner gates; this report
   recommends the minimal canaries because wider rollout multiplies an unproved recovery obligation.

## Follow-up tracking, 4 October 2026

Parent deduplication records M1 as PAT-2394, M2 as PAT-2395, and the unconfirmed Windows legacy-state candidate W1 as PAT-2396. PAT-881 covers the prior bootstrap PATH fix; PAT-1338 and PAT-1339 cover related Windows staging/path checks, without proving the legacy-state transition here. The parent reran the unprivileged PATH fixture on 4 October: three failing production subcases, system-only control passing. These tickets preserve the installed and signing gates above; none is release clearance.
