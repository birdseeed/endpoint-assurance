# Software observation and identity domain

PAT-1461 introduces the first read-only domain boundary for Endpoint Assurance
and Software Governance. It runs beside `device_apps`. It does not replace the
legacy application, catalogue, policy, package, deployment, or remediation
paths in this phase.

## Invariants

- Raw inventory evidence is preserved in `raw_payloads` and immutable
  `software_observations` rows.
- A software product is independent of a package or installer.
- A Team ID, Authenticode publisher, or other signer identifies a vendor. It
  is never sufficient product identity by itself.
- Product resolution requires a unique curated alias.
- Reprocessing one raw payload is idempotent.
- Every run, observation and installation is tenant scoped in the schema.
- Missing software closes an installation only when the payload carries
  authority for that inventory scope.
- This domain has no write path to policy, deployment or remediation state.

## Tables

| Table | Responsibility |
|---|---|
| `software_products` | Curated platform-neutral product identity |
| `software_product_aliases` | Reviewed platform identity mapped to one product |
| `software_inventory_runs` | Collection event, raw-payload reference and completeness scope |
| `software_observations` | Immutable application evidence from one run |
| `software_observation_resolutions` | Mutable resolution result kept separate from evidence |
| `software_installations` | Current and historical device presence derived from observations |

None of these tables references `catalogue_products`,
`catalogue_platform_targets`, signed package metadata, deployment rings,
install intents or scripts.

## Identity evidence

The extractor derives a stable observation fingerprint from platform,
identity kind, normalised value and a required companion value where one is
available.

| Platform evidence | Observation kind | Raw confidence |
|---|---|---|
| macOS bundle identifier plus Team ID | `macos_bundle_team` | Exact |
| macOS bundle identifier without Team ID | `macos_bundle` | Medium |
| Winget identifier without source | `windows_winget` | Medium |
| Windows native identifier plus publisher | `windows_native_publisher` | Medium |
| Windows native identifier alone | `windows_native` | Low |
| Name plus publisher | `name_publisher` | Low |
| Name only | `display_name` | Low |

The current Windows payload does not carry Winget source, MSIX package family
name, MSI UpgradeCode, or an equivalent durable product key. Those observations
therefore remain unresolved unless an operator has created an exact reviewed
alias. A changing MSI ProductCode is retained as changing installation
evidence and never creates a new product automatically.

Cross-platform normalisation is explicit. Separate macOS and Windows aliases
may point to one product after review. Similar names never create that link.

PAT-1874 adds a standalone, independently versioned
[installation-confidence evidence catalogue](INSTALLATION_EVIDENCE_CATALOGUE.md).
It provides reviewed identifier, signer and path evidence for future product
resolution work, but is not wired into extraction in this phase. It has no
package, deployment, policy or remediation authority.

## Operator review of an observed identity (PAT-2404)

A tenant declaration can only resolve to an alias with `provenance='reviewed'`,
and the extractor only resolves an observation through a curated alias. Staff
create those aliases by promoting an identity that devices actually report.
Routes and bodies are in [API.md](API.md#software-catalogue-review-adminsoftware-catalogue-pat-2404).

**The reviewer never supplies an identity.** A review names one observed
identity by its four stored key fields, exactly as the extractor normalised
them. The platform reads the identity back from current installations. If no
device currently reports exactly that identity there is nothing to review.

**Kinds.** Only the two kinds that bind an identifier to a vendor can be
reviewed: `macos_bundle_team` and `windows_native_publisher`. Every other kind
is refused.

**The evidence bar** is evaluated over every current installation of that
identity in every tenant, each read through its latest observation:

| | macOS | Windows |
|---|---|---|
| Qualifies | Team ID is ten characters of `A-Z0-9`, and at least one installation is reported `signed` | Non-blank publisher, and at least one installation has a `valid` Authenticode signature chained to a `microsoft` or `public` root |
| Hard refusal, on any one installation | `adhoc`, `unsigned`, `untrusted`, `invalid` | `invalid`, `unsigned` |
| Neither blocks nor qualifies | no verdict, `error` | no verdict, `unknown`, `valid` under an `enterprise` root or with no root reported |

A Windows registry publisher with no valid Authenticode evidence never
qualifies. Several distinct Authenticode publisher keys among the valid
installations are allowed, and are recorded in the alias's `evidence`.

"Current" is one definition, `softwaregov.CurrentInstallationSQL`, shared with
the declaration read and the same rule `effective_tenant_app_policies` applies:
not removed, and on Windows the device still lists the identifier in
`device_apps` (matched byte for byte on the observation's
`observed_identifier`), because no application scope closes a native Windows
installation. An uninstalled bad copy therefore does not block a review and an
uninstalled valid copy does not qualify one.

**Effect.** A review creates the alias (`provenance='reviewed'`,
`match_confidence='exact'`, `created_by` = the claimed actor) and creates or
reuses the product whose `canonical_key` is `lower(btrim(canonical_name))`. An
existing product is reused only if it is `active` and under the same vendor;
a vendor that was never recorded is filled in. From then on:

- the alias resolves installations of that identity **estate-wide, for every
  tenant, on each device's next inventory report**. The review itself rewrites
  no installation and no observation;
- the alias appears in the portal product lookup and a declaration can select
  and resolve it.

**Retirement** sets `software_product_aliases.retired_at`. The row is kept. A
retired alias:

- is not returned by the portal lookup and cannot be selected or resolved by a
  declaration;
- resolves no new observation. An installation it already resolved keeps its
  `alias_id` and `product_id` as history, so product-based readers of that
  installation (category product tags) still see the product;
- no longer vouches for an identifier in the approvals write, and no longer
  names a product in the usage report;
- makes every declared approval resolved through it ineffective, on both
  platforms: `effective_tenant_app_policies` withholds the policy row. The
  declaration, its policy row and every decision ledger are untouched. The
  declaration reads as `identity_state: unmatched`.

Only a reviewed alias can be retired this way. The identity becomes a
candidate again.

**Revival.** Reviewing a retired identity again revives the same row: it clears
`retired_at` and refreshes `created_by` and `evidence`. The evidence bar is
evaluated afresh, so an identity that has since gone bad is refused. It must be
reviewed under the product it already belongs to; another product name is
refused, because installations reference the alias together with its product.
**A declaration that was resolved through the alias becomes effective again on
revival, with no action by the tenant.** That is accepted: the tenant's decision
never changed, only whether Patched vouches for the identity.

Retirement and revival change what the policy resolver returns with no policy
row and no report changing, so each bumps
`software_unapproved_presence_state.policy_version` for every tenant with a
declaration resolved through the alias, after its commit (the same pattern,
and the same accepted limitation, as the extractor's eligibility flip: a
failure there is logged and leaves that summary stale until the tenant's next
policy change).

**Audit.** Every review and retirement writes one `software_catalogue_audit`
row in the same transaction: `actor` is the shared admin token identity,
`claimed_actor` is the body's untrusted claim, plus the source address, the
reason, and the alias before and after. The table rejects UPDATE, DELETE and
TRUNCATE by trigger. That stops an accident, not the owning role.

**Known limits.** The bar is read at review time; it is not re-checked as
evidence changes, so a reviewed identity that later turns up unsigned stays
reviewed until staff retire it. An inventory report being extracted at the
moment of a retirement can still resolve through the alias. The candidate list
scans current installations of one platform and kind across all tenants; it is
a staff route on the internal listener and is not indexed for a large estate.

## Extraction flow

For each accepted raw payload, the existing extractor transaction:

1. Updates the legacy `device_apps` projection.
2. Creates or reuses one `software_inventory_runs` row linked to the raw
   payload composite key.
3. Inserts one immutable `software_observations` row for every reported app.
4. Looks for one exact curated alias that is not retired.
5. Records the resolution separately as resolved or unresolved.
6. Creates or refreshes the device installation episode.
7. Closes missing installations only within an authoritative scope.

An old payload replay cannot overwrite newer current-version fields or close
a newer installation. It may acquire a reviewed product resolution because
resolution is deliberately separate from the immutable observation.

## Absence authority

The supported macOS contract defines `apps` as a complete software snapshot,
so a valid macOS run has `all_software` authority.

Windows currently has a narrower contract. A schema-v1 capability declaration
with `windows_winget_inventory_complete=true` grants only `windows_winget`
authority, and only when every reported Windows app has a valid `winget` or
`native` identity kind. It may close a missing Winget installation. It cannot
close registry, MSI, MSIX, Store, portable or other native observations.

False, absent, partial, unsupported or malformed capability declarations grant
no Windows absence authority.

## Homebrew (PAT-2013)

The macOS agent's `homebrew` payload block (PAT-2012) lands on this seam, not
in parallel tables. Each formula keg, cask and tap is one
`software_observations` row in the payload's inventory run, after the apps,
with its own `software_installations` episode.

| Evidence | Observation kind | Value | Companion | Raw confidence |
|---|---|---|---|---|
| Formula keg | `homebrew_formula` | formula name | tap, or `''` when the receipt did not say | Medium with a tap, low without |
| Cask | `homebrew_cask` | cask token | tap, or `''` | Medium with a tap, low without |
| Tap | `homebrew_tap` | tap name (`user/repo`) | `''` | Medium |

`observed_identifier_kind` carries the same value as the kind, so the source
(`homebrew_formula`, `homebrew_cask`) is readable from the observation alone.
A formula name or cask token is Homebrew's package namespace, not a
normalised product. Observations stay unresolved until a reviewed alias maps
them; the alias identity-kind constraint does not yet admit the Homebrew kinds,
which is deliberate until a mapping workflow exists (PAT-2023).

Homebrew-only evidence lives in `homebrew_observation_details`, per-device
status in `homebrew_device_state`, and cask-to-app links in
`homebrew_cask_app_links` (see [SCHEMA.md](SCHEMA.md#software-observation-domain)).

### Absence authority

Homebrew has its own scope. A `complete` or `not_present` block grants the
run the `homebrew` scope, which closes missing Homebrew installations and
nothing else. `partial` and `failed` grant nothing. The macOS `all_software`
scope now covers the `apps` snapshot only and never closes a Homebrew
installation, so an agent that stops sending the block cannot erase Homebrew
history.

| Status | Observations | Installations closed | `authority_at` |
|---|---|---|---|
| `complete` | everything sent | Homebrew ones not in this report | moves to this report |
| `partial` | everything sent | none | unchanged |
| `not_present` | none | every Homebrew installation on the device | moves to this report |
| `failed` | none | none | unchanged |

The portal's current per-device list comes from `homebrew_current_entries`
(migration `0165`, PAT-2032): one row per formula keg (device, kind, prefix,
name, version), cask or tap, pointing at the newest report that listed it. A
`partial` report only adds or refreshes rows. It can list a formula without
having read every keg (the formula bound cuts mid-formula, the time check runs
per keg, an unreadable keg directory is skipped), so it never hides a keg: a
Mac that only ever reports partial shows every keg seen since its last
authority, which is what the evidence supports. A `complete` or `not_present`
report deletes every row it did not refresh. A cask or tap is one row whatever
its version, since its single record is read whole.

Homebrew ingest takes a per-device lock first (`SELECT ... FOR UPDATE` on
`homebrew_device_state`, creating the row if missing), because `ProcessOnce`
can run beside the extractor worker: without it an older partial report could
read the authority before a newer complete one commits. A replay older than
the device's `authority_at` writes nothing, and the portal read also ignores
any row older than `authority_at`. The extractor maintains the projection, so
a portal read joins current rows only and never scans history.

### Formula kegs and identity

Each keg on disk is its own observation. Kegs of one formula share an
identity, and therefore one installation. A keg whose receipt could not be
read has no tap; when the other kegs in the same Cellar directory (same
prefix and name) in the same payload name exactly one tap, the tap-less keg
takes that identity at `low` confidence, and its detail row keeps `tap` NULL
as reported. With no tapped sibling, or siblings naming two taps, it stays
tap-less. The installation's `current_version` is the keg `opt/` links to
(`opt_linked = true`), then the most recently installed keg, then payload
order; never a string sort, which ranks `1.9` above `1.10` (PAT-2032). A
`partial` report that read no linked keg of a formula leaves the stored
`current_version` alone, since the linked keg it skipped may be the
vulnerable one; a `complete` report read every keg, so its fallback stands.

**Re-extraction caveat (PAT-2032).** Tap inference changes the identity
fingerprint of a tap-less keg that has a tapped sibling. A raw payload
extracted under PAT-2013 code stored that keg under the tap-less fingerprint,
so re-extracting it now fails that row with "software observation N changed
during re-extraction" rather than silently rewriting immutable evidence. This
was chosen over tolerating the change because the observation row is
immutable and the installation would otherwise point at an observation whose
identity disagrees with it. Only the handful of Homebrew rows stored before
this change are affected. To rebuild one, delete that payload's
`software_inventory_runs` row (its observations and Homebrew details cascade)
and then reset the raw payload for extraction. The old tap-less installation
keeps its row (its `latest_observation_id` becomes NULL) until the device's
next `complete` report closes it.

The whole block is written in five set-based statements whatever its size
(observations, their ids, resolutions, installations, details), plus at most
two for cask links and two for the current-entry projection. There is no alias
lookup: the alias identity-kind CHECK admits no Homebrew kind, so the
observations are unresolved by construction, and a test fails if that CHECK is
ever widened without restoring the lookup.

### Cask to app bundle

A cask is linked to an active application installation on the same device
by path, on one of two bases (PAT-2032):

- `reported_path`: the agent reported the app inside that cask's own
  `<prefix>/Caskroom/<token>/` directory. Only this basis makes the estate
  count the software once. A reported path anywhere else is not linked at
  all: the agent resolves a symlink in the version directory to its target,
  and Homebrew moves apps out of the Caskroom rather than symlinking to them,
  so a target elsewhere is a link someone placed there, which could name any
  app.
- `default_appdir`: an app reported without a path (Homebrew moved it, the
  usual case) links at `/Applications/<name>`. That is a guess: it ignores a
  cask's `target:` rename and a custom appdir, and cannot tell a name from the
  receipt from a name found on disk. The link is shown, but the cask is still
  counted rather than hidden.

A cask whose receipt was read replaces its links; an unreadable receipt only
adds.

### How CVE matching (PAT-2023) uses this

PAT-2023 keys its curated mapping on the observation identity:
`(identity_kind, identity_value_normalized, companion_value_normalized)`, i.e.
kind plus name plus tap, which is also `HomebrewIdentity` in every portal
response. Auto-seeding reads `homepage` and `source_url` from
`homebrew_observation_details`. Version matching reads the per-keg `version`
from the detail rows (every keg on disk is its own row, so an old keg left
behind is still matched), not `software_installations.current_version`,
which holds only one. `installed_on_request`, `installed_as_dependency` and
`runtime_dependencies` give the on-request versus dependency context the
finding must show. A cask linked through `homebrew_cask_app_links` on the
`reported_path` basis should use the linked app's existing mapping so one
install yields one finding; a `default_appdir` link is not strong enough for
that.

## IDE extensions, packages, local models and MCP servers (PAT-2021)

The four agent blocks `ide_extensions`, `package_managers`, `local_models`
and `mcp_servers` (PAT-2017 to PAT-2020, both platforms) are stored on this
seam the way Homebrew is: each reported item is an ordinary
`software_observations` row in the payload's inventory run, after the apps
and Homebrew ordinals, with an ordinary `software_installations` row, so it
takes part in PAT-2015 category tagging like any other software. Approval
state, new-software and drift for these kinds are PAT-2031, not this seam.

Identity kinds (value / companion): `ide_extension` (extension id /
marketplace), `npm_package` and `pip_package` (registry name normalised by
`categorytag.NormalizePackageName` / `''`), `local_model` (`name[:tag]` /
runtime), `local_model_runtime` (runtime / runtime), `mcp_server` (name /
client), plus `ide_extension_unidentified`, `npm_package_unidentified`,
`pip_package_unidentified`, `local_model_unidentified` and
`mcp_server_unnamed` for an item the agent could not name. None is a product
identity, `software_product_aliases` admits none of them, and every
observation is unresolved. The marketplace is derived from the editor: VS
Code and VS Code Insiders install from the Visual Studio Marketplace, Cursor
and Windsurf from Open VSX, JetBrains IDEs from the JetBrains Marketplace. A
VSIX-sideloaded extension keeps its editor's marketplace namespace; its
`source` is kept in the detail row.

Tables (migration `0166`):

| Table | Purpose |
|---|---|
| `tooling_observation_details` | The item exactly as reported, from the typed struct (so an MCP server can only ever carry the PAT-2020 allowlist), with block, unit, user and a hashed per-item `entry_key`. Immutable. |
| `tooling_device_state` | Newest `collection_status` per device per block, per-unit statuses (`sources`, `runtimes`, `clients`), a small summary (totals, row counts) and issues. `authority` maps each unit to the newest report that was authoritative for it; it only moves forward. Older replays never overwrite the row. |
| `tooling_current_entries` | One row per item per device (keyed per user, editor, prefix, store or config file, with an occurrence index for identical keys), pointing at the observation of the newest report that listed it. Added or refreshed by every complete or partial report at or after its unit's authority; only an authoritative unit deletes rows it did not refresh. |

Absence authority is per unit (`ide_extensions`; `packages:<source>`;
`local_models:<runtime>`; `mcp_servers:<client>`, all recorded in
`software_inventory_runs.authoritative_scopes`). A unit is authoritative only
when its own status is `complete` or `not_present` and the block is neither
`failed` nor truncated. Each scope closes only its own identity kinds;
`pip_package` closes only when both `pip_user` and `pipx` are authoritative,
because both feed it. The macOS `all_software` scope closes no tooling
installation and no tooling scope closes an application.

Migration `0166` re-adds its three CHECK constraints `NOT VALID`; `0167`
validates them in a separate transaction and builds
`software_installations_kind_value_present_idx` `CONCURRENTLY` (the one
statement outside `BEGIN ... COMMIT`, marked
`-- migrate:statement-by-statement` so the Go test harnesses run it
statement by statement, as `psql -f` does on deploy). Roll back `0167`
before `0166`.

Ingest is a fixed number of set-based statements whatever the block sizes
(two for the lock, five for observations, resolutions, installations and
details, one closure, two for current entries, one for state), under a
per-device, per-block `FOR UPDATE` lock on `tooling_device_state`, taken in
the one canonical (alphabetical) block order every tooling list follows, so
two concurrent extractions cannot deadlock. `TestToolingIngestStatementCountIsBounded` pins it at every
contract bound.

## Compatibility and backfill

Migration `0112_software_observation_backfill` backfills the current
`device_apps` snapshot (split out from the `0111_software_observation_domain`
schema migration so the DDL holds no extended lock over a `device_apps` scan —
PAT-1461 review). It is idempotent: it can be re-run safely after a partial
or interrupted apply without duplicating rows. Backfill runs:

- use provenance `backfill_current_snapshot`;
- do not claim a raw-payload relationship;
- use legacy `last_seen` as both ends of the initial installation episode;
- receive no absence authority;
- remain unresolved until reviewed aliases exist.

`GET /admin/tenants/{tenantID}/devices/{deviceID}/software-observation-comparison`
returns counts from the legacy and new current-state projections. It is an
operator diagnostic only and performs no mutation.

## Deferred work

- Customer software policies and append-only approval decisions.
- Product vendor, release and version-scheme modelling.
- Authenticated operator attribution for identity review (the review API
  itself is PAT-2404, above; its actor is still the shared admin token).
- CVE mappings against normalised products and releases.
- Privacy-controlled usage observations.
- Governance findings and remediation exports.
- Legacy API compatibility projections and retirement of patching-only paths.

The next phase should be based on comparison evidence from this seam, not an
assumption that legacy name or signer matches are safe to migrate.
