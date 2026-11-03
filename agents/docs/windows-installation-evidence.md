# Bounded Windows installation observations (PAT-1875)

This is a read-only collection mechanism, not installation-confidence assessment,
software approval, remediation or an installer catalogue. It preserves every
existing `apps[]` identifier, publisher, version and metering field.

## Current delivery boundary (PAT-1921)

Production has **zero reviewed Windows targets**. PAT-1874's evidence catalogue
contains macOS evidence, with no independently inspected Windows vendor artefacts.
For the reviewed-target path the Windows service therefore emits this honest
capability result on every fresh inventory payload and performs no reviewed-target
probes (PAT-2116's all-apps coverage, below, is separate and does run):

```json
"installation_evidence": {
  "collection_status": "unavailable",
  "errors": ["reviewed_targets_unavailable"]
}
```

Enabling collection requires separately reviewed MSI ProductCode evidence under
PAT-1922. PAT-1921 delivers the platform-owned set in the signed agent-config
payload as `windows_installation_evidence`; the initial delivery contains zero
targets. Legacy package labels, the execution allowlist, display-name matching and
tenant-supplied paths cannot populate it. PAT-1876 still owns canonical platform ingestion and
persistence of the additive fields below. Older servers may retain the raw payload
but ignore these fields; this change does not claim stored or visible confidence.
A signed Windows release, native CI checks and fresh installed-agent payload remain
required before claiming operating evidence. No release or endpoint rollout is
part of this implementation.

## Neutral additive contract

Each selected `apps[]` row gains `installation_evidence`:

```json
{
  "collection_status": "complete",
  "collected_at": "2026-09-20T12:00:00Z",
  "source": "windows_authenticode_offline",
  "install_path": "C:\\Program Files\\Fixture",
  "executable_path": "C:\\Program Files\\Fixture\\Fixture.exe",
  "executable_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "signature_state": "valid",
  "signer": "CN=Fixture Publisher",
  "errors": []
}
```

The example is synthetic, not a reviewed product. These field names and meanings
are platform-neutral: macOS can describe a bundle path, its main executable and a
`macos_codesign` source in the same object. Older apps omit the object. Missing
fields are unknown and must not clear previous evidence, mark a product absent,
resolve findings, or produce a pass/fail installation verdict.

The reviewed target matches a canonical braced MSI ProductCode against the
native uninstall identifier using ordinal case-insensitive equality, never its
display name. Publisher and architecture remain unchanged observation metadata.
`InstalledAppScanner` preserves the ARP subkey name verbatim, including MSI
ProductCode braces. The existing `UninstallPlanner` identity parser recognises
that same braced form; evidence matching does not execute any removal logic.
Duplicate targets use the same equality and are rejected before collection.
It supplies a fixed install directory and
one fixed executable beneath it. Filesystem evidence proves those paths were read;
the registry does not supply executable arguments or an authoritative signer.
Distinct duplicate observations of that identity share one probe per cycle.
An unmatched target is not evidence that the product is absent. Paths outside
reviewed fixed locations and per-user installations remain outside collection.

Per-row status:

| Status | Meaning |
| --- | --- |
| `complete` | Fixed path, SHA-256 and a valid offline OS signature with verified signer were read, or (PAT-2116) an authoritative `unsigned`. |
| `partial` | The file/hash were read but signature or signer evidence is incomplete. An explicit digest mismatch retains `signature_state: invalid`, but no signer is invented. |
| `unavailable` | No file evidence was obtained, including missing/unreadable paths, unsupported paths, helper failure or timeout. |

`signature_state` is `valid`, `invalid` only for the OS's explicit digest mismatch,
`unsigned` only under the conservative rule in "All-apps coverage" below (PAT-2116),
or `unknown` for an unavailable trust chain, a catalog-API failure or any other trust
error.
It is not catalogue equivalence, current revocation assurance, a CVE conclusion or
application health. Signer is the full subject of the leaf certificate retrieved
from WinVerifyTrust's successfully verified provider chain, not the registry
publisher and not a certificate merely attached to an executable.

Top-level summary is `complete` only when every **attempted matched target** is
complete; `unavailable` when all are unavailable; otherwise `partial`. No targets
or no matched observations are `unavailable` with an explicit reason, never an
empty success. This is not completeness of the whole application inventory.
Each native row carries at most one fixed error code; the aggregate carries at
most four distinct codes. Errors contain no exception messages, usernames or
paths. All code literals are shorter than 64 characters. Signer is limited to 512
characters without control characters; file paths to 512 characters.

## LocalSystem safety and resource bounds

At most 24 reviewed targets are accepted. One helper at a time has at most three
seconds, with a 15-second overall collection budget. Exhausted targets remain
unknown. Native IO and WinVerifyTrust run in a separate service process so a hung
filesystem filter or trust provider cannot strand a service thread; the parent
terminates the helper on timeout or failure, then waits at most 250 milliseconds
for process exit. This bounded cleanup grace can extend the final collection
deadline by at most 250 milliseconds; it never changes an unavailable result into
success. Standard output and error are each
capped at 16,384 characters. No shell is used. The only arguments are the fixed
helper command, a numeric target index, delivery version and content hash. The
child loads a fixed protected cache, re-verifies the original signed bytes and
checks the version/hash binding before resolving the index. That command
exits before service startup, credential reads, state bootstrap and hosted work.

The parent starts only its own fixed absolute Program Files service path after
read-only ownership/ACL checks and holds it against write/replace. The child reads
only absolute fixed-drive paths. UNC, device/extended paths, alternate streams,
relative traversal, DOS device names and reparse points are rejected. Ancestor
directory handles are retained without write/delete sharing while descending,
closing the junction-swap and in-place reparse-change windows; the leaf remains open without write/delete sharing while
streaming SHA-256 and verifying the same file handle. Files over 256 MiB are not
hashed. No executable under observation is run. There is no network lookup,
download, install, removal, enforcement, registry mutation or profile loading.

WinVerifyTrust uses cache-only retrieval and disables revocation lookup. Microsoft
documents these flags in [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).
The verified certificate comes from [WTHelperGetProvCertFromChain](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovcertfromchain).
An offline `valid` signature must never be presented as a fresh revocation check.

## All-apps coverage (PAT-2116)

Every app row the scanner reports that carries no reviewed-target evidence now gets
`installation_evidence` from `AppSignatureCoverage`, at the same
`apps[].installation_evidence` location, so the live platform ingests it unchanged.
Reviewed-target rows keep their evidence; coverage never overwrites it. Coverage rows
never carry `catalogue_version`, `delivery_version` or `content_hash`.

**Executable resolution** (`ExecutableResolver`, pure and unit tested), in order:

1. `DisplayIcon`, with surrounding quotes and a trailing `,<icon index>` removed, when it
   is a safe local `.exe` path strictly inside a Program Files root, not under the Windows
   directory, not uninstaller-named, and inside `InstallLocation` when that is also usable.
   Resolution `display_icon`.
2. `InstallLocation`, when it is a safe local directory strictly inside a Program Files
   root and not under the Windows directory: its top level holds exactly one candidate
   `.exe` (`install_location_single_exe`), else the first of its top level, `cmd\` and
   `bin\` that holds exactly one candidate whose name matches the product name
   (`install_location_named_exe`, PAT-2129).
3. With no `InstallLocation` at all, the directory of `UninstallString`'s file, when it is
   strictly inside a Program Files root, by name match only
   (`uninstall_directory_named_exe`, PAT-2129). Never "the one exe beside the
   uninstaller": on WIN-STAGING, UTM Guest Tools' uninstaller sits beside exactly one other
   exe, a bundled `vc_redist.arm64.exe`.
4. For a Windows Installer product (`WindowsInstaller=1` and a braced-GUID subkey name),
   the `.exe` component key paths it registered (`MsiComponentReader`, PAT-2129): exactly
   one candidate with every key path inside the roots (`msi_component_single_exe`), else
   exactly one whose name matches the product name (`msi_component_named_exe`). The
   cached package in `%WINDIR%\Installer` is opened read-only while the locked,
   reparse-refusing walk holds its path; each path comes from `MsiGetComponentPath`
   (`INSTALLSTATE_LOCAL` only), which never installs or repairs anything.
5. Otherwise unresolved, with a reason (below).

A candidate is an `.exe` that is not uninstaller-named (`unins*`, `*uninstall*`) and not a
bundled redistributable (`*redist*`). A name match compares letters and digits,
case-insensitively, after dropping trailing version, architecture (`x64`, `arm64`, ...)
and channel (`preview`, `beta`) qualifiers from `DisplayName`, bare or in parentheses, from
a closed list: `PowerToys (Preview) ARM64` matches `PowerToys.exe`, `Foo (Plugin)` never
matches `foo.exe`, and `QEMU guest agent` does not match `qemu-ga.exe`. A listing that
reached the 64-name bound is never used to claim a unique match. A `cmd\` or `bin\` that
does not exist, or is refused by the locked walk, is skipped.

One executable claimed by more than one row in the same scan is `executable_ambiguous`
for all of them. Every unresolved row is `signature_state: unknown`, never a guess. The
Program Files restriction exists because HKLM hints are installer-written: the Windows
directory holds shared OS binaries (`msiexec.exe`, `%WINDIR%\Installer\{GUID}\*.exe`
icon stubs) that would lend Microsoft's signature to third-party rows, and a directory
outside Program Files may be user-writable while the helper reads as LocalSystem.

**`executable_resolution` on every row (PAT-2129).** A resolved row carries the method
above (or `reviewed_target`). An unresolved row carries a reason, beside the matching
`errors` code: `not_applicable` (`executable_not_applicable`), `unresolved_ambiguous`,
`unresolved_not_found`, `unresolved_outside_roots` (`executable_outside_supported_roots`),
`unresolved_listing_unavailable`, `unresolved_no_hint` (`executable_unresolved`),
`unresolved_registry_unavailable` (`registry_read_unavailable`), and
`unresolved_not_attempted` for a row a limit, timeout, failed or refused helper, or a
reviewed-target outcome decided before resolution ran. Every code matches the platform's
`observed_executable_resolution` CHECK (migration 0188, `^[a-z][a-z0-9_]{0,63}$`).

`not_applicable` means no executable is expected, on evidence, not a guess: a WiX Burn
bundle (`BundleProviderKey` set) published by `Microsoft Corporation`, with no
`InstallLocation`, named exactly as the Visual C++ Redistributable
(`Microsoft Visual C++ <year> Redistributable (<arch>) - <version>`) or .NET SDK
(`Microsoft .NET SDK <version> (<arch>)`) bundles name themselves. Their files are DLLs in
System32 or tools under `dotnet\sdk\<version>\`, and `dotnet.exe` belongs to the separate
`.NET Host` package. The bundle shape alone is not enough: PowerToys is a Microsoft Burn
bundle with a real app. A new pattern needs the same device evidence.

**WIN-STAGING (agent 0.14.3, 2026-09-25).** Resolved: Microsoft Edge (`display_icon`), Git
(`cmd\git.exe`, named), Tailscale (`tailscale.exe`, MSI named), Spice webdavd
(`spice-webdavd.exe`, MSI single); also Visual Studio Code (`display_icon`) and PowerToys
(`PowerToys.exe`, named) installed since. `not_applicable`: both .NET SDKs and the VC++
Redistributable. Unresolved: QEMU guest agent and Patched Agent (MSI, several exes, no name
match: `unresolved_ambiguous`), UTM Guest Tools (`unresolved_not_found`).

**Process boundary.** `Patched.Service.exe --collect-app-signatures` takes no other
argument. The parent writes row indexes, ARP subkey names, the registry view and its
verdict cache to stdin; the helper reads `DisplayIcon`, `InstallLocation`, `DisplayName`,
`Publisher`, `UninstallString`, `BundleProviderKey` and `WindowsInstaller` from HKLM
itself, lists an `InstallLocation` through the same locked, reparse-refusing walk used
for files (reparse points, offline files and cloud placeholders are skipped, never
hydrated), and reads each executable through `WindowsInstallationEvidence.ReadResolved`,
the same code as the reviewed path. It prints one JSON line per step, writes nothing to
disk and executes nothing it observes.

**Time bounds.** 10 seconds per step (hashing plus the Authenticode digest of a large Electron executable on a slow disk): the helper prints a line before each target's IO,
so a longer gap kills it, reports that one row `collection_timeout`, and a fresh helper
continues after it. 45 seconds and at most 6 helpers per scan; rows not reached are
`collection_budget_exhausted`. At most 1,024 rows (`coverage_limit` beyond). Output lines
are capped at 16,384 characters and 8 MiB in total. The summary reports the coverage
separately as `installation_evidence.coverage` (`collection_status`, `attempted`,
`resolved`, `errors`); the platform ignores the summary today.

**Cache.** Verdicts are cached in the service's memory by executable SHA-256, size and
last-write time, for 24 hours (1 hour for `unknown`, the verdict a transient failure
produces). The helper always re-hashes, so changed content never inherits a verdict; a
hit saves WinVerifyTrust, the chain build and the catalog walk. The cache is lost on
service restart and never written to disk.

**The unsigned rule.** `signature_state: unsigned` only when all of these hold, decided
in `SignatureVerdictLogic.Decide`:

- the embedded check returned exactly `TRUST_E_NOSIGNATURE`. `TRUST_E_SUBJECT_FORM_UNKNOWN`
  (an unparseable subject) still consults the catalog for `valid` but is never `unsigned`;
- the SHA-256 catalog lookup ran successfully and found no catalog: the first
  `CryptCATAdminEnumCatalogFromHash` returned NULL with `ERROR_NOT_FOUND`. No admin
  context, no hash, any other enumeration error, or a listed catalog that fails to verify
  is `unknown`;
- no SHA-1 catalog lists the file either, so a SHA-1-only member is withheld from
  `unsigned` (and is still never honoured as `valid`);
- the catalog database found `chkdsk.exe` (or `powershell.exe`) as a SHA-256 member in the
  same helper run, so an empty or broken database cannot turn files into `unsigned`.

**Pinnable publisher.** Beside `valid` only: `signer_thumbprint` (leaf SHA-256 over DER,
lowercase hex), `issuer` (leaf Issuer DN), `root_thumbprint` (SHA-256 of the last
certificate in WinVerifyTrust's own provider chain) and `root_kind`:

| `root_kind` | Rule |
| --- | --- |
| `microsoft` | Root thumbprint is one of Microsoft Root Certificate Authority 2010, 2011, the 2001 Microsoft Root Certificate Authority, or the 1997 Microsoft Root Authority (hard-coded SHA-256, from Microsoft's PKI repository, cross-checked against the published SHA-1 thumbprints). |
| `public` | Self-issued root present in the registry `AuthRoot` physical store (certlm "Third-Party Root Certification Authorities"), where Windows' automatic root update places Microsoft Trusted Root Program roots. Microsoft Identity Verification Root CA 2020 (Trusted Signing, which signs for third parties) lands here, not in `microsoft`. |
| `enterprise` | Everything else: not self-issued, only in `LocalMachine\Root` or a Group Policy or Enterprise store, an unreadable chain, or any doubt. |

An administrator can add a certificate to the registry `AuthRoot` store; checking
membership of the Microsoft-signed root CTL itself is a stronger, later refinement.
Nothing here is fetched from the network and no second chain is built.

**Platform parity.** macOS sends `signing_status` (`signed`, `adhoc`, `unsigned`,
`error`), `notarization_status` and `team_id` (PAT-2112). The Windows equivalents are
`signature_state` (`valid`, `invalid`, `unsigned`, `unknown`) and the pinnable publisher
above. Both map to one platform-neutral publisher key (see the follow-up below):
`apple_team_id:<TEAMID>` on macOS, `authenticode:<root_thumbprint>:<leaf subject DN>` on
Windows. A Team ID is issued under Apple's single root; an Authenticode subject is only
as unique as the root that vouched for it, which is why the root is part of the key.

## Platform follow-up (patched.im, not in this change)

The platform (migration 0186) stores `observed_signature_state` with
`CHECK (... IN ('valid','invalid','unknown'))`, and `windowsSignatureEvidence` stores any
other value as NULL, so `unsigned` and the new fields are ingested harmlessly as
"not reported" today. The follow-up:

1. **Migration** `software_observation_authenticode_publisher`, additive, deploy before
   binaries:
   - replace `software_observations_signature_state_valid` with
     `CHECK (observed_signature_state IS NULL OR observed_signature_state IN ('valid','invalid','unsigned','unknown'))`;
   - add `observed_authenticode_signer_thumbprint TEXT`, `observed_authenticode_issuer TEXT`,
     `observed_authenticode_root_thumbprint TEXT`, `observed_authenticode_root_kind TEXT`;
   - `CHECK` each of the four is NULL unless `observed_signature_state = 'valid'`; the two
     thumbprints `~ '^[0-9a-f]{64}$'`; issuer `char_length BETWEEN 1 AND 512`; root kind
     `IN ('microsoft','public','enterprise')`.
2. **Extractor** `windowsSignatureEvidence`: accept `unsigned`; read the four fields only
   beside `valid`, validate as above, NULL anything else (never refuse the report).
3. **Urgency** (`classifyWindowsTrust`): an installation reported `unsigned` adds reason
   `unsigned` at **Critical**, matching macOS `ExplicitUnsigned`. `invalid` stays High,
   `unknown` and missing stay High. **Low** becomes reachable on Windows only when every
   installation is `valid`, all share one publisher key, the `root_kind` of every
   installation is `microsoft` or `public`, the CVE state is assessed with no known CVEs,
   and the tenant has an approved application policy carrying that publisher key.
   `enterprise` never reaches Low.
4. **Publisher key** on approval policies: one text column `publisher_key`, shape
   `<scheme>:<value>`: `apple_team_id:<10-char Team ID, upper case>` or
   `authenticode:<root_thumbprint>:<leaf subject DN, verbatim>`. The leaf thumbprint is
   deliberately not the key (code-signing certificates renew yearly, Trusted Signing
   certificates within days); it is stored for audit. Issuer DN is not in the key
   (intermediates roll over); the root plus the subject the root's CA validated is.
5. **Payload schema** `payload.schema.json`: add `unsigned` to the `signature_state` enum
   and the four new properties, and correct the description ("the agent never reports
   unsigned" is no longer true). This repo vendors no copy of the apps schema, so nothing
   here changes until the platform publishes it.

## Verification and rollback

The signed delivery has exactly `schema_version: 1`, `catalogue_version`, a positive
64-bit `delivery_version`, lowercase SHA-256 `content_hash`, RFC3339 `published_at`
and `expires_at`, and `targets`. The hash covers compact JSON with alphabetic keys:
`{"catalogue_version":"2026.09.20.1","schema_version":1,"targets":[]}`.
Its v1 empty digest is `a3ea6bba02d8766c4f8432a04caf26154929651cb4722909b7f04df44922df5c`.
Strings use Go `encoding/json` escaping. Targets are sorted ordinal by identity
kind/value and contain exactly `authenticode_subject`, `executable_path`,
`identity_kind`, `identity_value`, `install_path`. V1 supports only
`windows_msi_product_code`; a Winget ID, MSI UpgradeCode or MSIX family never maps
to an ARP identifier. The expected Authenticode subject is catalogue evidence,
not a registry publisher and not an automatic installation verdict.

Both network acceptance and helper reload use the same pinned Ed25519 verifier
over the original bytes. The fixed `%ProgramData%\Patched\installation-evidence`
directory and its files require SYSTEM/Administrators ownership and no non-admin
write access; reparse points are rejected and handles retained while reading.
The original signature envelope is cached alongside a separate monotonic delivery
floor. This floor is global to the reviewed catalogue, survives tenant config
changes and enrolment, and pins hash and validity timestamps as well as version.
A newer tenant config cannot downgrade it; the same delivery cannot change content
or extend expiry. The floor is flushed before atomically replacing the envelope,
so interruption leaves a mismatch and zero probes. Corrupt or unreadable floors
fail closed. Recovery requires administrator investigation, never automatic deletion.
Cache persistence failures produce an agent-config warning while all protected
cache, signature and delivery-floor checks remain in force.

The cache must also match the exact current accepted agent-config bytes, including
when the helper reloads it. Missing/null, malformed, expired, future-dated,
unsupported, regressed or conflicting deliveries are unavailable. Empty valid
deliveries advance the floor but perform zero probes. Older signed configurations
disable this capability and retain the delivery floor. The existing unsigned
agent-config cache alone cannot grant targets. Each collected row and each valid
delivery summary carries `catalogue_version`, `delivery_version` and `content_hash`;
older producers omit these additive provenance fields.

The parent checks catalogue validity before each probe and again on its return;
expiry while collection is running leaves that observation unavailable and stops
further probes. Canonical ProductCodes are uppercase braced GUIDs; observed ARP
identifiers still match without regard to case. Hash compatibility tests include
Go-generated Unicode, HTML, quote/backslash and line-separator vectors. Invalid
UTF-16 strings are refused before hashing, without replacement-character fallback.

Shared tests cover neutral serialization (including macOS), preservation of metadata,
stable-identity matching, duplicate/capped targets, unavailable and mixed outcomes,
and overall budget exhaustion. Service tests cover hostile path shapes and helper
argument rejection. Windows-only tests exercise unsigned/signed files, missing
files, file/directory reparse rejection and Windows sharing. These are skipped on
macOS explicitly; a cross-target build is not proof of native behaviour.

Run `dotnet test windows/tests/Shared.Tests/Shared.Tests.csproj` and
`dotnet test windows/tests/Service.Tests/Service.Tests.csproj` on Windows.
On macOS cross-build with `-p:EnableWindowsTargeting=true`; the native suite still
requires Windows. Verify a signed release under LocalSystem before enrolling any
reviewed production targets. Rollback is the preceding signed Windows agent
artefact. Retain the protected evidence floor/cache across an agent rollback;
an older agent ignores the new delivery feature, and a subsequent upgrade must
still refuse a regressed delivery. No database migration is required.
