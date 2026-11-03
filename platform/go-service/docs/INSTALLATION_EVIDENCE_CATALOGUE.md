# Installation-confidence evidence catalogue

PAT-1874 introduces a reviewed, versioned evidence catalogue for high-value
software observations. It is deliberately separate from the legacy execution
catalogue and from the database-backed product resolution domain.

The catalogue answers one narrow question: does an observed application have
the expected stable identifier, signer and installation path for a reviewed
product? It does not approve software, declare an observed version current,
authorise a package, select an installer, create an install intent, or cause an
endpoint action.

## Files and versioning

- `internal/evidencecatalogue/catalogue.v1.json` is the independently versioned
  data set. `catalogue_version` versions reviewed data changes and
  `schema_version` versions the contract.
- `internal/evidencecatalogue/catalogue.schema.json` is the portable structural
  schema.
- `internal/evidencecatalogue/catalogue.go` is the fail-closed semantic
  validator and pure matcher.

The initial `2026.09.20.1` data set has 24 macOS entries. The Go contract also
supports Windows evidence, but no Windows entry is included until a vendor
artifact has been inspected for both a durable product identifier and its
Authenticode subject. Platform support in the contract is not permission to
invent missing evidence.

## Required evidence

Every entry records:

- a rationale and platform-neutral canonical product identity;
- one or more platform-stable identifiers;
- exact permitted installation paths;
- an Apple Team ID or Windows Authenticode subject;
- a primary vendor HTTPS source and the claim it supports;
- review reference, time, method, artifact version and signed-artifact digest.

For macOS, the first review used installed vendor-signed application bundles.
The reviewer read `CFBundleIdentifier` and `CFBundleShortVersionString` from
the bundle metadata, then read `TeamIdentifier` and `CDHash` with `codesign`.
The vendor URL establishes the vendor's product and macOS distribution surface;
the signed artifact establishes the exact identity, signer and reviewed path.

Windows entries require an exact Winget ID, MSI UpgradeCode, or MSIX package
family name together with an Authenticode subject and SHA-256 of the reviewed
signed artifact. A publisher or display name alone is never accepted.

Identifier validation follows the platform owners' published contracts:

- Apple restricts
  [`CFBundleIdentifier`](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifier)
  to alphanumeric characters, hyphens and periods. The validator additionally
  rejects empty period-separated components.
- Microsoft's authoritative
  [WinGet manifest schema](https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/latest/manifest.singleton.latest.json)
  defines a PackageIdentifier as two to eight period-separated components,
  each at most 32 characters, with a 128-character total limit and an explicit
  prohibited-character set. The validator deliberately mirrors Microsoft's
  negated-character class, which permits Unicode outside that prohibited set;
  it rejects NUL separately as unusable identity data.
- Microsoft's
  [package identity specification](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/package-identity-overview)
  defines an MSIX package family name as `<Name>_<PublisherId>`, with a
  3-to-50-character package name and a 13-character Crockford Base32 publisher
  ID. The validator also applies Microsoft's reserved package-name rules.
- Authenticode subjects accept either a constrained certificate common name or
  Microsoft's canonical X.500 distinguished-name form, documented by the
  [MSIX Identity schema](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/appxmanifestschema/element-identity).

The portable JSON Schema enforces the Authenticode subject size, control-byte
and letter-like minimums. Go semantic validation is authoritative for the full
distinguished-name structure, including supported RDN attributes, quoting,
separator rules and the required common name.

Windows paths are exact drive-rooted paths. Uppercase is the authoring
convention, but lowercase drive letters and path casing are accepted and
normalised case-insensitively for matching. Wildcards, empty components and
`.` or `..` traversal components are rejected.

## Matching outcomes

The matcher first resolves a stable identifier. It never accepts or consults a
display name. A resolved identifier can then produce:

| Outcome | Meaning |
|---|---|
| `expected` | Identifier, signer and exact path all match reviewed evidence |
| `signer_mismatch` | Identifier is known but signer evidence differs or is missing |
| `unexpected_path` | Identifier and signer match but the path is not permitted |
| `unrecognised` | No reviewed stable identifier matches |

These are evidence classifications only. None is an approval or remediation
decision.

## Change and rollback

Data changes must preserve authoritative source and artifact-review provenance,
increment `catalogue_version`, and pass the package tests. A rollback replaces
`catalogue.v1.json` with the previous reviewed version. The pure validator and
matcher accept older reviewed versions. PAT-1921 signed Windows delivery also
requires a new, higher delivery revision; its durable high-water mark must
never be rewound.

PAT-1921 delivers an inactive empty Windows projection through signed
agent-config. Its ledger (migration 0155), expiry, hashing and rollback runbook
are defined in [Windows installation evidence](../../contracts/windows-installation-evidence.md).
No Windows target is populated. PAT-1922 must first add reviewed MSI
ProductCodes and exact install/executable pairs. Existing UpgradeCodes, Winget
IDs and MSIX family names cannot stand in for ProductCodes. Invalid or
unavailable evidence disables only this additive consumer.
Any unreviewed Windows catalogue entry disables the entire Windows delivery
until PAT-1922 reviews and supports it; entries are not silently skipped to
produce a partial target list.

Consumers must keep observations, catalogue evidence, tenant policy and
decisions distinct, and must not convert an `expected` match into deployment
authority.
