# ADR: Windows software-metering source (PAT-380)

**Status:** accepted · **Date:** · **Parity mirror of:** PAT-356 (macOS, Spotlight `mdls`) / platform ADR-0005

## Context

The metering chain (PAT-356 collector → PAT-366 aggregates → PAT-362 "installed-but-unused" screen) shipped macOS-only. On macOS, per-app usage comes from Spotlight metadata: `kMDItemLastUsedDate` and `kMDItemUseCount`, giving a **last-used timestamp** and a **lifetime launch count** per app bundle. PAT-380 must produce the same two neutral signals on Windows and write them to the same columns (`device_apps.last_used_at` / `device_apps.launch_count`) plus a device-level `metering_status`, with no upstream change.

Windows has no single Spotlight equivalent. Candidate sources:

| Source | Last-used | Launch count | Scope | Notes |
|---|---|---|---|---|
| **UserAssist** (HKCU/HKU `…\Explorer\UserAssist\{GUID}\Count`) | ✅ FILETIME | ✅ run count | per-user (interactive GUI launches) | ROT13-encoded exe paths; the **only** source with both signals |
| **Amcache** (`Amcache.hve`) | ✅ last-modified/exec | ❌ | machine-wide | execution *evidence*, no count; forensic hive, heavier to parse |
| **AppCompat / ShimCache** | ⚠️ unreliable on modern Win | ❌ | machine-wide | presence/exec evidence only; no count, no dependable time |

## Decision

Use **UserAssist as the sole source.** It is the only Windows artefact that carries **both** a last-used time and a run count — the two fields the neutral columns require. Amcache/ShimCache provide neither a count nor a reliable per-app time, so they cannot fill `launch_count` and would only ever be a partial fallback for `last_used_at`.

- The service runs as LocalSystem, so it reads **HKEY_USERS\\&lt;SID&gt;** for every loaded interactive profile (`S-1-5-21-*`) rather than HKCU, and **sums run counts across users** for a device-wide lifetime figure (mirrors the macOS lifetime-cumulative semantic).
- UserAssist values are ROT13-decoded to exe paths, `{KNOWNFOLDERID}` prefixes expanded, then correlated to installed apps by `InstallLocation` / `DisplayIcon`, keyed by the same identifier (registry Uninstall key) the inventory reports.

### Usage evidence (PAT-2328, 2026-10-01)

Null usage values never prove that software is unused, even with `metering_status=ok`.
Each app carries `usage_evidence`:

- `recorded`: a usable launch timestamp or positive count was correlated to the app.
- `no_record`: the loaded-profile source was read successfully and a usable executable hint had no matching record. This does not cover CLI launches or unloaded profiles and is not evidence of non-use.
- `unmapped`: the source was usable but the app had no usable executable mapping. A bare InstallLocation is insufficient.
- `unavailable`: the source or app hints could not establish coverage. Positive evidence from another readable hive can still be `recorded`.

The optional field is platform-neutral. Older agents omit it, which means not reported.

`metering_status` describes the loaded-profile source:

- `ok`: at least one usable launch record, with no read failure or explicitly disabled loaded hive.
- `no_user_session`: HKU enumeration succeeded and found no loaded interactive profile.
- `userassist_unavailable`: enumeration failed, a relevant read failed, a loaded profile explicitly has `Start_TrackProgs` DWORD 0, or no usable records were found. Missing `Start_TrackProgs` is not an opt-out and does not prove the source works. Wrong-type or unsupported values are unavailable.

`metering_user_hive_count` is the number of loaded interactive hives examined, and
`metering_record_count` is the number of parsed records with a positive count or valid
timestamp, before app correlation. UEME bookkeeping and zero-count/null-date rows do not
count. Unknown counts are omitted after enumeration failure; disabled-hive history is
excluded. Counts are diagnostic, never a claim about the number of users or apps covered.

### Reviewed AppID bindings

Generic launch matching uses only an explicitly bound executable path. `InstallLocation`
alone, or an executable elsewhere below that directory, cannot establish that this app
launched. Unbound helpers no longer add counts or update the app's last-used timestamp.
Microsoft Edge additionally allows versioned and unversioned `msedge.exe` paths to match
within the same canonical Program Files installation root, with the exact `Microsoft Edge`
ARP identity. Another drive, Program Files root, product identity or malformed version
folder is not equivalent. Reviewed Edge AppID and Office Word/Outlook bindings remain;
unknown AppIDs and shortcuts remain unmatched. `no_record` remains absence of a supported
record, never proof of non-use.

WINDOWS11 evidence on 2026-10-01 contained exact `MSEdge` (count 12),
`Microsoft.Office.WINWORD.EXE.15` (9), and `Microsoft.Office.OUTLOOK.EXE.15` (1).
Edge also had a TaskBar shortcut count of 11; counting both would overstate launches.
No Firefox-name record was found, which proves neither non-use nor absence of an opaque ID.

`MSEdge` maps only to the `Microsoft Edge` ARP identity with a canonical Microsoft Edge
Application executable hint, including its versioned subdirectory. The two Office IDs map
only to the observed `O365ProPlusRetail - en-us` suite and HKLM App Paths entries bound to
its Program Files `Microsoft Office\Root\Office16` directory. The Office Click-to-Run
service icon does not establish suite usage. Other suite editions/locales need their own
observed binding; Office extensibility components and WebView are not the suite/browser.

Shortcuts are never opened or resolved. Unknown AppIDs stay unmatched. AppID and executable
records for the same target in one hive use the maximum count, preserving the latest date;
counts are summed across hives and distinct executables. A shared executable claimed by
multiple apps is not attributed to either. Counts saturate at the wire integer limit.

Closed non-app executable names are OfficeClickToRun.exe, OfficeC2RClient.exe,
msedgewebview2.exe, Patched.Service.exe, uninstall.exe, unins000.exe, setup.exe,
vc_redist.x64.exe and vc_redist.x86.exe. These names are not substring heuristics.
This is not a complete service/runtime classifier: unrecognised capabilities remain
best-effort, and no_record must never be converted into an unused-software claim.

## macOS parity and abort handling

Spotlight emits the same per-app field: valid date or positive count is `recorded`,
successful `(null)`/zero reads are `no_record`, and failed/empty/malformed reads, the
1980 date sentinel, disabled indexing or no resolved user session are `unavailable`.
A failed attribute does not erase a separately read positive value, but the app's evidence
stays unavailable. The global source status is committed only after collection finishes.
`spotlight_disabled` requires a successful mdutil probe explicitly reporting disabled;
probe failure or early abort is `unavailable`.

The old collector defaulted both its pre-collection stub and function entry to
`spotlight_disabled`. Thus the 2026-09-24/28 MacBook-Pro reports cannot establish that
indexing was actually disabled without logs from those runs. The regression injects an
early mktemp failure with indexing enabled and now observes `unavailable`, not `ok` or
`spotlight_disabled`. This identifies a reporting defect, not a proven historical cause.

## Limits and verification

Only loaded hives and Explorer-mediated launches are visible. No offline hive is loaded,
no process monitoring is added, no user identity is sent, and no executable or shortcut is
opened. Per-user known-folder IDs are deliberately not expanded against LocalSystem's
profile. The mapping remains conservative and does not establish a complete observation
window. Signed-release installed proof on HOMESERVER, WINDOWS11 and a Mac remains the
release gate; unit tests and builds do not satisfy it.

## Contract mirror and checks

`contracts/inventory-payload.schema.json` is a byte-for-byte vendored copy of
`patched.im/go-service/docs/payload.schema.json`, which remains the authority.
PAT-2328 source SHA-256: `d0408b15ab3d28f5d80520941b154617a03cf252fc6756b7c718f0ce7d099ed2`.
Re-vendor the complete file when the platform contract changes; do not author it here.
`contracts/inventory-usage-evidence.fixtures.json` contains Windows/macOS fragments for
every evidence state, older-agent omission, partial source reads and successful zero counts.
`python3 ci/test_usage_evidence_contract.py` validates the canonical app schema and the
metering fields without requiring unrelated device inventory in these fragments. Set
`PATCHED_PLATFORM_SCHEMA` to the authoritative file to also check byte equality.
`PATCHED_USAGE_DUMP=<directory> zsh macos/lib/test-apps.zsh` preserves actual emitted
fixture payloads; the same environment variable makes the contract test validate them.
