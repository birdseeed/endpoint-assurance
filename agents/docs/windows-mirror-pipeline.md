# Windows mirror pipeline (PAT-823)

> **Retired 2026-09-30 (PAT-2304); history only.** `ci/mirror_pipeline.py`,
> `ci/mirror_pipeline_windows.py`, their tests and `windows/windows-allowlist.json`
> are deleted. Their workflows went earlier (PAT-2247), and the allowlist
> validator that last imported the Windows pipeline went with the allowlist.
> Patched does not patch (Andy, 2026-09-28). Nothing below describes running code.

Status: MVP machinery landed; first end-to-end mirror pending Windows-runner
secrets + a per-app Windows redistribution sign-off. This is the Windows sibling
of the macOS mirror pipeline (PAT-500, `docs/mirror-infrastructure-spike.md`).

## Design decision (Andy, 2026-07-10)

**Bypass winget/Chocolatey at fetch time; use them only as version-discovery and
cross-hash oracles in CI.** We do **not** stand up a winget REST source or a
Chocolatey NuGet/OData feed server.

Rationale — and why the "obvious" alternatives were rejected:

- **winget** has no ad-hoc "fetch from this URL" override. A real internal winget
  source means running a winget-REST-compliant service (an always-on hosted API
  with its own index), not object storage.
- **Chocolatey** `--source` points at a NuGet-protocol server (OData/V2 or V3)
  serving `.nupkg` packages — again a real server to stand up and operate.
- Both are a materially larger, ongoing-hosting commitment than the macOS model,
  which is just static objects on R2 + a CDN. Andy's framing: *"we want to host
  these apps for credibility, not use chocolatey"* — i.e. serve the actual bits
  from Patched's own infrastructure, exactly like macOS, not depend on
  Chocolatey's/Microsoft's serving layer at install time.

So the Windows pipeline mirrors the macOS shape: resolve the vendor's real
installer URL, download once, verify, re-host as a static object on the **same R2
bucket/CDN** macOS uses, pin the hash, and have the endpoint fetch from the mirror
and run the installer itself. winget/Chocolatey are consulted only in CI, as
oracles for the version, the vendor URL, and a cross-corroborating hash.

With this model the winget-vs-Chocolatey distinction largely disappears on the
fetch side (both collapse to "download an artifact from a URL"), so support is
chosen by **installer type, not engine**: MSI (and WiX-toolset-built `.msi`,
labelled `wix` by winget) first; as of PAT-842, the exe-family (`exe`, `nullsoft`,
`inno`) too — installed via a per-label `silent_args` invocation instead of
`msiexec`; and, as of PAT-844, `msix` — a signed MSIX package installed for all
users via `Add-AppxProvisionedPackage` (the delivery format of the new Microsoft
Teams).

## Two install modes (PAT-840)

Each label picks a serving mode via `install_mode` (default `mirror` for
back-compat):

| Mode | Re-hosted? | Endpoint downloads from | Needs `mirror_eula_approved`? | For |
|---|---|---|---|---|
| `mirror` | Yes — R2/CDN | `mirror_url` (`mirror.patched.im`) | **Yes** (redistribution sign-off) | Apps we may re-host (Zoom, 1Password) |
| `vendor_pinned` | **No** | `pinned_url` (first-party vendor domain) | **No** (nothing is redistributed) | Redistribution-restricted apps (Google Chrome) |

Both modes run the **identical** verification chain — resolve → download → ClamAV →
Authenticode + publisher → cross-hash — and both hard-verify `pinned_sha256` +
Authenticode on the endpoint before `msiexec`, failing closed on any mismatch. The
**only** difference is the last step: `mirror` re-hosts the bytes and serves them
from `mirror.patched.im`; `vendor_pinned` does **not** re-host and instead pins the
vendor's own versioned URL, so the endpoint fetches directly from the vendor. Pin-
vendor is strictly *more* constrained than a plain winget pull (it adds a pinned
hash + publisher gate + no-fallback), and legally clean because we never host the
bits.

**Vendor-URL-availability tradeoff.** `vendor_pinned` depends on the vendor keeping
the pinned URL serving the pinned bytes. If the vendor removes a versioned URL — or,
for an *evergreen* URL like Chrome's `googlechromestandaloneenterprise64.msi`,
rotates the bytes to a new release — the endpoint's SHA-256 check no longer matches
`pinned_sha256`, so the agent **fails closed** (no install) until the daily pipeline
re-resolves, re-verifies, and re-pins the new `pinned_sha256`/`pinned_version`. This
is the safe failure direction: a stale pin never installs unverified bytes. The
cross-hash step also fail-closes if the live vendor artifact and the winget catalog
hash disagree (e.g. mid-release), so a pin is only written when both agree.

## What runs where

| Stage | macOS (`mirror_pipeline.py`) | Windows (`mirror_pipeline_windows.py`) |
|---|---|---|
| Source of truth | `engine/labels/*.json` | `windows/windows-allowlist.json` |
| URL + version oracle | Installomator label `download` block | winget-pkgs manifest (`Zoom.Zoom.installer.yaml`) |
| Signature/publisher verify | Team ID + notarization (`codesign`/`spctl`, macOS runner) | Authenticode + publisher (`Get-AuthenticodeSignature`, Windows runner) |
| Independent cross-hash | Homebrew Cask / vendor sha256 URL | winget catalog `InstallerSha256` |
| AV scan | ClamAV (hard-fail) | ClamAV (hard-fail) |
| Publish | R2 `mirrors/manifest.json` + `<label>/…` | R2 `mirrors/windows-manifest.json` + `windows/<label>/…` |
| Pin | `pinned_sha256` + `patched.mirror` into label JSON via bot PR | `pinned_sha256` + `mirror` + `mirror_url` into allowlist entry via bot PR |

The Windows artifacts use a `windows/` key prefix and a separate
`windows-manifest.json` so they never collide with the macOS artifacts that share a
label id (zoom, slack, firefox all exist on both platforms).

## Pipeline stages (`ci/mirror_pipeline_windows.py`)

For each entry with `mirror_eula_approved=true` and not `vendor_only`:

1. **resolve** — read the newest numeric version from the winget-pkgs manifest
   directory for `winget_id`, fetch that version's `*.installer.yaml`, and select
   the installer matching `installer_type` (`msi`/`wix`; as of PAT-842,
   `exe`/`nullsoft`/`inno`; as of PAT-844, `msix`) + `architecture` (`x64`). This
   yields both the vendor
   `InstallerUrl` (winget as URL oracle) and its `InstallerSha256` (cross-hash
   oracle).
2. **download** — fetch the MSI from the vendor's own URL (e.g. `zoom.us/...`),
   never from winget's serving CDN. 2 GB size cap, HTTPS-only (shared with the
   macOS `probe`).
3. **scan** — ClamAV `clamscan`, hard-fail. A missing/broken scanner aborts the
   label rather than publishing unscanned bits.
4. **verify** —
   - **Authenticode + publisher** (primary, mandatory, Windows-runner-only). The
     pipeline refuses to publish on a non-Windows runner, mirroring the macOS
     pipeline's refusal on a non-Darwin runner.
   - **cross-hash** — the download SHA-256 must equal the winget catalog
     `InstallerSha256`; a mismatch aborts (the vendor served different bytes than
     the catalog recorded).
5. **serve** —
   - `mirror`: upload the MSI to R2 under `windows/<label>/<version>/…`.
   - `vendor_pinned`: **no upload** — the served URL is the vendor URL itself.
6. **pin** — via an auto-merged `patched-mirror-bot` PR (main is protected):
   - `mirror`: set `mirror=true`, `mirror_url`, `pinned_sha256`.
   - `vendor_pinned`: set `install_mode=vendor_pinned`, `pinned_url` (the vendor
     URL), `pinned_sha256`, `pinned_version` — never `mirror=true`/`mirror_url`.

Preflight: if `MIRROR_BUCKET_URL` is unset the pipeline exits 0 (no-op) for `mirror`
labels. `mirror_eula_approved` is a human-reviewed, **Windows-specific**
redistribution sign-off (the macOS EULA verdicts do **not** carry over) and
remains meaningful metadata, but **as of PAT-851 it is no longer the pipeline's
live eligibility gate** — see "Post-merge activation" under `v1 candidates`
below. The authoritative gate for both `mirror` and `vendor_pinned` labels is
now the platform's `GET /admin/catalogue/pipeline-ready` set, fetched
fail-closed before each run. `--only <label>` never bypasses that gate.

## Endpoint behaviour (`windows/src/Service/InstallRunner.cs`)

When an allowlist entry is `mirror=true` **or** `install_mode=vendor_pinned`, the
agent takes a verified direct-install path instead of winget (shared code, differing
only in the source URL):

1. Download the artifact over HTTPS (routed through the agent's configured egress
   proxy) — from `mirror_url` (`mirror`) or `pinned_url` (`vendor_pinned`) — saved
   with a `.msi` or `.exe` temp-file extension matching the installer family.
2. Hard-verify SHA-256 against `pinned_sha256` (mismatch → fail-closed, no install).
3. Authenticode-verify the publisher (same gate the winget path uses).
4. Run the installer: `msiexec /i <file> /quiet /norestart` for `msi`/`wix`; for
   the PAT-842 exe-family (`exe`/`nullsoft`/`inno`), run the verified EXE directly
   with its resolved `silent_args` (per-app override, else a framework default —
   `nullsoft`: `/S`, `inno`: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`; a
   generic `exe` with neither fails closed rather than guessing a flag); for the
   PAT-844 `msix` type, provision the verified package for all users via
   `Add-AppxProvisionedPackage -Online -PackagePath <file> -SkipLicense` (the
   service runs as SYSTEM, so `-Online` all-users provisioning — not a per-user
   `Add-AppxPackage` side-load — is the correct managed-endpoint install). The
   .msix publisher gate uses the MSIX signature (`AppxSignature.p7x`), since an
   .msix is a signed ZIP container rather than a PE image.

It never calls `winget install` / `choco install` for a mirrored or pinned label —
there is **no** unpinned fallback. Plain (non-mirror, non-pinned) entries keep
today's winget-CLI behaviour unchanged. Every gate is fail-closed: the installer
only runs once the bytes are proven to match the pinned hash **and** are signed by
the expected publisher.

## Supported installer types and fast-follows

- **MSI (and wix), the PAT-842 exe-family (exe/nullsoft/inno), and the PAT-844
  `msix` type.** MSI's uniform `msiexec /quiet` switch avoids per-vendor
  silent-install-flag metadata for that family; `wix` is winget's InstallerType
  label for a WiX-toolset-built `.msi` — not a distinct package format — so it
  resolves and installs through the identical `msiexec` path as `msi`. The
  exe-family is installed via a per-label `silent_args` invocation instead. `msix`
  is provisioned for all users via `Add-AppxProvisionedPackage`. The mirror-execute
  path and the pipeline both refuse any other installer type (appx, msixbundle,
  burn, portable, zip, …) fail-closed — only the single-file `msix` type is in
  scope (`appx`/`msixbundle` are not).
- **v1 candidates:**
  - **Zoom (`Zoom.Zoom`, msi).** A native MSI in winget-pkgs; live-mirrored.
  - **1Password (`AgileBits.1Password`, msi).** A clean MSI at
    `c.1password.com/dist/1P/win8/1PasswordSetup-*.msi`. Corroborated publisher:
    the winget `Publisher` is `AgileBits Inc.`, but the current Authenticode signing
    certificate — issued by *Microsoft ID Verified CS AOC CA 04* (Azure Trusted
    Signing) — has subject `CN=Agilebits, O=Agilebits, L=Toronto, ST=Ontario, C=CA`.
    "Agilebits" is AgileBits/1Password's genuine, verified signing identity (a
    Toronto-based company), not a DN-parser artifact, so `expected_publisher` is set
    to the cert's literal O/CN value `Agilebits`. Wired `installer_type: msi`,
    `mirror_eula_approved: true`.
  - **Google Chrome (`Google.Chrome`, wix, `vendor_pinned`).** Chrome's enterprise
    MSI is winget `InstallerType: wix`, served at the evergreen vendor URL
    `dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi`.
    Corroborated publisher: winget `Publisher` is `Google LLC` and the Authenticode
    signing cert is an EV cert with subject `CN=Google LLC, O=Google LLC,
    L=Mountain View, ST=California, C=US`, so `expected_publisher: Google LLC`. Wired
    `install_mode: vendor_pinned` (not re-hosted → legally clean, no
    `mirror_eula_approved` needed).
  - **Firefox (`Mozilla.Firefox`, nullsoft, `vendor_pinned`), Notion
    (`Notion.Notion`, nullsoft, `vendor_pinned`), Slack (`SlackTechnologies.Slack`,
    exe, `vendor_pinned`)** — PAT-842 exe-family candidates. Wired `install_mode:
    vendor_pinned` with `silent_args` set (`/S` for the two nullsoft apps; `--silent`
    for Slack's generic `exe`, sourced from its winget-pkgs `InstallerSwitches.Silent`
    entry). `pinned_url`/`pinned_sha256`/`pinned_version` are left absent — the
    nightly pipeline pins them on its next run; the agent fails closed until then.
  - **Microsoft Teams (`Microsoft.Teams`, msix, `vendor_pinned`)** — PAT-844 msix
    candidate. The new Teams ships as a single `.msix` (winget `InstallerType:
    msix`, architecture `x64`, resolving to
    `teamsinstaller.public.onecdn.static.microsoft/.../MSTeams-x64.msix`).
    `expected_publisher` is set to `Microsoft Corporation` (Microsoft's code-signing
    O — confirmed against the live signing cert when the pipeline first
    Authenticode-verifies it on a Windows runner). Wired `install_mode:
    vendor_pinned`; `pinned_url`/`pinned_sha256`/`pinned_version` left absent so the
    nightly pipeline pins them — the agent fails closed until then.
  - **VLC (`VideoLAN.VLC`, wix), LibreOffice (`TheDocumentFoundation.LibreOffice`,
    msi), PuTTY (`PuTTY.PuTTY`, wix) — re-host mark (PAT-823 FOSS expansion,
    Andy, 2026-07-16).** All three keep their live `vendor_pinned` state
    (install_mode + pinned_url + pinned_version + pinned_sha256) unchanged —
    the migration must never pass through an unpinned winget-fallback window
    (this exact regression was blocked by the GitHub-Non-Author-Review gate on the first cut of
    this change). The re-host intent is recorded as `mirror_eula_approved:
    true`; redistribution basis is each project's FOSS licence (VLC:
    LGPL-2.1/GPL-2.0, LibreOffice: MPL-2.0, PuTTY: MIT), which permits
    re-hosting the unmodified binary. **Known limitation:** the pipeline reads
    each entry's own `install_mode` to pick its serving path, and
    `_apply_windows_pin()`'s mirror branch does not clear the vendor-pin
    fields — so as the code stands, a `vendor_pinned` entry can never
    transition to re-hosted via a pipeline run alone (a run just refreshes the
    vendor pin, which is safe and idempotent). Actually re-hosting these
    labels needs a small pipeline enhancement: when an entry is
    `vendor_pinned` with `mirror_eula_approved: true`, run mirror mode and
    have the pin PR atomically set `mirror=true` + `mirror_url` + fresh
    `pinned_sha256` while dropping `install_mode`/`pinned_url`/
    `pinned_version` — the flip then never leaves the label unpinned.
  - **Notepad++ (`Notepad++.Notepad++`, wix) — new label (PAT-823 FOSS
    expansion, Andy, 2026-07-16).** Added directly as `vendor_pinned` and
    pre-pinned, so it is never a moment unpinned: `pinned_url` is the
    winget-attested vendor release URL for v8.9.7 x64
    (`github.com/notepad-plus-plus/.../npp.8.9.7.Installer.x64.msi`) and
    `pinned_sha256` was computed from the downloaded artifact and matches the
    winget-pkgs `InstallerSha256`. `expected_publisher: NOTEPAD++` — verified
    directly against that same MSI with `osslsigncode verify`: signed by a
    GlobalSign CodeSigning cert, Subject `emailAddress=don.h@free.fr,
    CN=NOTEPAD\+\+,O=NOTEPAD\+\+,L=Paris,ST=Île-de-France,C=FR` — the literal
    (unescaped) O value is `NOTEPAD++`, matching
    `AuthenticodeVerifier.MatchPublisher`'s exact case-insensitive match (see
    the PAT-900 fixture-vs-real-cert lesson — the fixture is evidence, not
    authority). Notepad++ moved off a self-signed cert to this
    GlobalSign-issued one as of v8.8.7; only the GlobalSign signature applies
    from v8.9 on. `mirror_eula_approved: true` — GPL-3.0-or-later permits
    redistribution; the same re-host mechanics (and the same pipeline
    limitation) as the VLC/LibreOffice/PuTTY mark above apply.
  - **7-Zip (`7zip.7zip`) — explicitly EXCLUDED, not added.** Andy's PAT-823
    triage assumed both 7-Zip and Notepad++ were "ready-now msi"; that does
    not hold for 7-Zip. Verified directly: downloaded the live 26.02 x64 MSI
    (`7z2602-x64.msi`, sha256 matching the winget-pkgs `InstallerSha256`,
    confirming it's the genuine vendor artifact) and ran `osslsigncode
    verify` — **the installer carries no Authenticode signature at all**
    ("MSI file has no signature"). 7-Zip's maintainer has explicitly declined
    to code-sign releases (cost/philosophy; see
    github.com/ip7z/7zip/issues/159). The mirror pipeline's Authenticode +
    publisher verify is mandatory and fail-closed (`verify()`,
    `authenticode_verify()`), and `expected_publisher` is a schema-required
    field with no genuine string to record for an unsigned installer — adding
    an entry here would either be permanently unmirrorable or would require
    fabricating a publisher string, both against the PAT-900 "confirm against
    a real signed installer" convention. **Policy decision (Andy, PAT-973,
    2026-08-11): 7-Zip is permanently excluded from the allowlist, not a
    pending gap.** No exception path is being built for unsigned-but-trusted
    vendor binaries — this stays a one-off exclusion rather than a general
    mechanism. Revisit only if 7-Zip's maintainer starts signing releases.
- **Post-merge activation — the local `mirror_eula_approved` flag is NOT the
  live gate.** `ci/mirror_pipeline_windows.py`'s `load_windows_labels()`
  (PAT-851) reads the authoritative eligibility set from the platform's
  `GET /admin/catalogue/pipeline-ready`, keyed by identity `pkg:<winget_id,
  lowercased>` — this REPLACES `mirror_eula_approved` as the pipeline's actual
  gate; the field is left in the schema as a historical/human record only.
  Merging this PR does not, by itself, cause VLC/LibreOffice/PuTTY/Notepad++
  to be mirrored — each identity (`pkg:videolan.vlc`, `pkg:
  thedocumentfoundation.libreoffice`, `pkg:putty.putty`, `pkg:notepad++.
  notepad++`) must also be promoted to `pipeline-ready` in the dashboard's
  `/admin/catalogue` (the PAT-850/851/852/853 operator-curation flow) before a
  workflow_dispatch of `mirror-pipeline-windows.yml` will do anything for
  them — and even then, a dispatch only refreshes their vendor pins until the
  vendor_pinned-to-mirror flip enhancement described in the re-host mark above
  lands.
- **Fast-follows (out of scope here):**
  - APPX / `.msixbundle` installers — still refused fail-closed (PAT-844 added only
    the single-file `.msix` type).
  - Restoring the Windows mirror destinations in the customer AV/EDR exclusions
    doc (PAT-822) once a label is actually live on the CDN.
