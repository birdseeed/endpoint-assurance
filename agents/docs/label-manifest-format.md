# Label manifest — format & rationale

**Status:** Draft for review
**Companion to:** `installomator-security-review.md` §4.1, §4.2, §4.9
**Schema:** `contracts/label.schema.json`
**Tracks:** PAT-41 (hard-fork the engine; restructure labels as data)

---

## 1. Why a manifest

Upstream Installomator stores every application as an entry in one ~900-case
`zsh` `case` statement. That is fine for a shell script you `source`, but it is
poor as *data*: it cannot be schema-validated, diffed meaningfully, queried, or
operated on by anything that is not the shell.

Hard-forking the engine (security review §4.1) created **structured data** — one
record per application. The endpoint still executes the committed shell label
dispatch; the release bundle ships and executes `engine/Installomator.sh`, not
the JSON records, and no build step compiles them into the shell engine. There
is no JSON-to-shell compiler and none is planned. CI therefore treats the two
representations as a paired contract for managed labels:

- the **engine** installs from `engine/Installomator.sh`,
- the **allowlist** is a subset of it,
- **CI** validates it and rejects managed shell/manifest drift (PAT-42/PAT-1403),
- the **verification agent** reads it and proposes changes to it (§4.9).

PAT-1385 adds a fail-closed semantic cross-check for `pkgindmg` payload
selection. PAT-1403 owns the broader migration or equivalent drift coverage for
every execution-affecting field.

## 2. One file per label

Each label is its own file: `engine/labels/<label>.json`, where `<label>`
matches the record's `label` field.

The reason is review ergonomics. The verification agent opens a pull request per
label when it proposes a version bump or a URL fix; a Linear issue per label on
an `alert`. One file per label means each such change is a tiny, self-contained
diff a human can review in seconds — which is the whole basis of the
propose-then-approve model. A single monolithic manifest file would make every
agent proposal a noisy diff against a 900-record document.

The full set of these files **is** the label manifest. There is no separate
index file; the manifest is the directory.

## 3. Record structure

The authoritative definition is `contracts/label.schema.json` (JSON Schema
2020-12). A record has four parts:

**Identity & install** — `label`, `name`, `type` (artifact packaging), and
`app_path` (the installed bundle, used for the installed-version read and the
post-install Team ID check). `installed_version_key` is optional and defaults to
`CFBundleShortVersionString`, matching Installomator; use `CFBundleVersion` only
when the shell stanza does too. `name` is a human-readable display identifier —
emitted as the `name` column of the derived endpoint allowlist and used only for
reporting/telemetry, never for execution (the shell's own internal `name=`
assignment drives `app_path`, `archiveName`, and the `blockingProcesses`
fallback, and is what the contract reconciles `app_path` against). It normally
equals the shell's `name=`; the contract enforces that by default and only
tolerates a divergence for a label explicitly listed in the contract's
`_DISPLAY_NAME_EXCEPTIONS` (e.g. `zoom`, whose installed bundle is
`zoom.us.app` — see that label's own `patched.notes`).

For `pkgindmg`, an absent `pkg_in_dmg` field is the
typed `root-unique-pkg` default and means exactly one root-level package. A
non-default layout uses `relative-path-glob` with exactly one safe relative
pattern and requires exactly one match. Alternative runtime selectors are not
representable; architecture-dependent selection uses the typed mapping below.
Absolute paths, traversal,
shell syntax and ambiguous matches are rejected. Architecture-dependent payloads
use `relative-path-glob-by-arch`; the verifier evaluates only its current
arm64/i386 rotation, matching the shell branch used for that architecture.
`relative-path-version-component` renders one exact path from component three
of the Sparkle/source-resolved dotted version; JRE 8 uses it so verification
and endpoint installation both refuse a package from a different update
directory. Probe observations cannot override that source-owned value.
`relative-path-version-digits` removes non-digits from the source-resolved
version and renders one exact package name, matching Archiware's runtime
transformation without broadening it to `*`.
Path globs are matched one component at a time and deliberately
case-insensitively, preserving Installomator's historical `find -iname`
behaviour across case-sensitive and case-insensitive mounted volumes. `*` never
crosses `/`. Neither endpoint nor verifier follows symlinks or descends into an
existing `.pkg` bundle. A literal
basename preserves the safe historical root-package preference before a
unique-only recursive search. Bare parentheses are rejected because zsh treats
them as glob syntax; literal parentheses remain supported inside a character
class, as used by the OpenVPN payload selector.

**Integrity** — `expected_team_id`, the 10-character Apple Developer Team ID the
artifact must be signed by. This is the load-bearing field. It must be present
and non-empty; CI rejects an empty value (this is what closes threat T4 — see
§5). `pinned_sha256` is null on the direct-download path and set only when the
app is served from the internal mirror (review §4.4). For licences that require
a notice to accompany redistributed binaries, `redistribution_notice` pins the
authoritative notice URL and its SHA-256. The mirror publishes the verified
notice beside the artifact and records its URL in the public mirror manifest.

**Acquisition** — `download` and `version` (see §4).

**Patched metadata** — the `patched` object: `allowlisted`, `mirror`,
`mirror_eula_approved`, `vendor_only`/`vendor_only_reason`, `tier`,
`reviewed_by`, `reviewed_at`, `notes`, `ring_policy`,
`smoke_test_exempt`/`smoke_test_exempt_reason`,
`behavioral_exempt`/`behavioral_exempt_reason`/`behavioral_exceptions`. This is
Patched-owned bookkeeping with no counterpart in the upstream model.
`mirror_eula_approved` is a merge-blocking licensing gate — CI (§5) rejects any
record with `mirror = true` and `mirror_eula_approved` not `true`. `vendor_only`
marks a label the mirror pipeline must skip entirely (session-auth-gated
download, CDN hotlink protection, no programmatic URL); `vendor_only_reason` is
required whenever `vendor_only = true`. `ring_policy = immediate` bypasses
staged rollout for security-critical apps. The `smoke_test_exempt*` and
`behavioral_exempt*`/`behavioral_exceptions` fields let a label opt out of the
corresponding CI probe with a mandatory reason — see `contracts/label.schema.json`
for the full field descriptions. Both probes were deleted on 2026-09-30
(PAT-2308), so these fields are now inert.

## 4. The download model — static vs resolved

`download.method` is the field the verification agent and the auditor care about
most, because it captures where threat T5 (run-time URL-resolution tampering)
does and does not apply.

**`static`** — the URL is fixed. It may be a stable vendor URL that
server-side-redirects to the current versioned artifact (Chrome, Firefox, Slack
all work this way). There is no scraping step on the endpoint. Lowest-risk.

**`resolved`** — the real download URL is *computed at run time* by querying a
vendor source: a Sparkle appcast, a GitHub releases API, a redirecting URL, or a
vendor API (`download.strategy` records which). This is the scraping step that
carries residual threat T5. Resolved labels are flagged for the internal mirror
(review §4.4): mirroring an app converts it, from the endpoint's point of view,
back into a static, hash-pinned fetch.

`version.source` records how the *available* version string is obtained —
`resolved-source` (from the same response the resolved download uses),
`download-filename` (parsed from a static-redirect target), `http-headers`, or
`none` (not resolvable; the engine cannot pre-compare and treats the app as
reinstall-on-request only).

## 5. How CI uses the manifest (PAT-42)

A CI check loads every record and fails the build if any of these hold:

- `expected_team_id` is empty or not a 10-character Team ID — **makes threat T4
  unrepresentable in a shipped configuration**;
- any URL (`download.url` or `download.source`) is not `https://`;
- the file name does not match the `label` field;
- the record does not validate against `label.schema.json`.

Because the schema already enforces the Team ID pattern and the `https://`
prefix, "valid against the schema" does most of this work; the CI check is the
belt-and-braces gate that runs on every PR — including every PR the verification
agent opens.

## 6. How the engine consumes it

The engine does not parse the JSON records. `tools/build-bundle.sh` copies the
committed `engine/Installomator.sh` byte-for-byte and generates only the endpoint
allowlist from JSON. Both files are covered by the bundle integrity manifest.
Both update and fresh-install daemons pass an approved label to that shell
engine, whose built-in stanza resolves the URL and selects the payload.

`ci/installomator_execution_contract.py` parses the exact shell dispatch without
sourcing it. For every `patched.allowlisted=true` record it fails closed on:

- a missing or ambiguous label stanza;
- artifact `type`, Team ID, effective app path, blocking-process or installed
  version-key drift, including the shell-runtime default and the upstream
  `NONE` blocking-process sentinel, not just literal array equality;
- a non-mirrored URL that is not one exact static literal matching the manifest;
- a mirrored label without both `mirror_url` and `pinned_sha256` **and** a
  confirmed, unconditional engine-side `PINNED_SHA256` verification of the
  downloaded artifact — the manifest declaring a pin is not sufficient on its
  own (§ below);
- any shell-only execution field not yet represented by the typed manifest;
- any non-assignment shell construct inside the stanza — a function
  definition, control-flow keyword, bare command, or nested `case` block —
  other than a fully literal (`printlog "static text" [LEVEL]`, no `$` or
  backtick) log call, which cannot affect artifact identity. This is
  deliberately narrow: it is the one non-assignment shape known to already
  exist in a currently-allowlisted stanza (firefox, googlechrome's
  deprecation warnings), not a general allowance for shell logic.

The reconciled boundary is deliberately field-specific:

| Execution input | Enforced relationship |
|---|---|
| Label dispatch | Every allowlisted JSON label has one effective shell arm, with nested `case` blocks (e.g. architecture branching) never mistaken for a second arm. |
| Artifact type and signer | Exact JSON-to-shell equality. |
| Installed app identity | Shell `name`/default app path, JSON `app_path`, and the effective installed-version key agree. |
| Display name | JSON `name` equals the shell's `name=` by default; a small, reviewed exception list (`_DISPLAY_NAME_EXCEPTIONS` in the contract) documents the handful of labels (e.g. `zoom`, `firefox`) where `name` is intentionally a human-readable display identifier distinct from the shell's internal name — see below. |
| User-process handling | The effective shell default (absent or empty array — both hit the same `$name` runtime fallback) or literal array equals `blocking_processes`; the `NONE` sentinel is the one shell spelling equivalent to an empty list. |
| Direct artifact URL | A non-mirrored label uses one static literal URL equal to JSON. |
| Mirrored artifact bytes | JSON supplies a mirror URL and SHA-256 pin, AND the engine's own `PINNED_SHA256` verification of the downloaded artifact is confirmed present and reachable for every label (not per-label — it lives outside the label dispatch). Only then is the URL comparison skipped, and the URL's own value shape is still checked for command-substitution/interpreter-piping constructs even when exempted from the manifest cross-check. |
| Nested package payload | PAT-1385 owns the typed `pkgindmg` locator and shell parity — see below. |
| Other installer controls | A managed stanza cannot set package, archive, target, installer, updater, curl, install, or uninstall overrides until they are typed. Unknown assignment fields also fail closed. |
| Available-version resolver | Still shell-owned. Only the current `appNewVersion` and Firefox helper assignments are admitted; any new variable fails closed, and an admitted field's assigned expression is still rejected if it pipes into a shell interpreter or uses backtick substitution — the field-name exemption covers the "already current" check, not arbitrary code execution disguised as one. |
| Non-assignment shell | Any function definition, control-flow, bare command, or nested `case` block fails the label closed, except a fully literal `printlog` call. |

Mirrored labels may retain a dynamic vendor fallback in the shell because the
engine's `PINNED_SHA256` check (PAT-495, run unconditionally after every
label's download, outside the `case $label` dispatch) rejects different bytes
before install. The contract confirms that check is present in the exact
committed `Installomator.sh` — structurally, not just by the manifest
declaring a pin — before granting the downloadURL exemption: it proves the
four markers of the check occur in the order execution requires (guard
opens, archive is hashed, mismatch is checked, abort is reachable), that the
guard opens at nesting depth 0 relative to the top of the main script flow
(so it cannot be wrapped in a per-label `if` that could exclude a specific
label), and that the abort path is reachable before any install-function
call. This is a bounded, line-oriented structural scan, not a full shell
parser — see `_engine_pins_downloaded_artifact_hash`'s docstring for the
exact scope. If any of this cannot be confirmed, the label falls back to the
same static-URL requirement as a non-mirrored label (which a
resolved-download mirrored label will then fail, by design). The update path
additionally supplies the exact mirror URL. The bundle CI step proves that
the reconciled source and regenerated allowlist are the exact files copied
into the release artifact.

Runtime overrides are reapplied after the shell label arm with literal
`typeset` assignment and an exact name allowlist. They are never evaluated as
shell syntax; this matters for catalogue-derived URL and hash values processed
by a root-running engine. The reapply step fails loudly and distinctly rather
than silently, in two cases the allowlist mechanism itself could otherwise
mask: the allowlist array being unset or empty (which would otherwise make
every override look "not allowlisted" for the wrong reason), and an override
name that is array-typed in the shell (e.g. `blockingProcesses`) — a flat
runtime value cannot be safely reconstructed into array elements, so that
override is refused rather than silently corrupted or crashing the run with
an unexplained interpreter error.

### `pkgindmg` payload locator (PAT-1385)

For `pkgindmg`, `ci/installomator_pkg_contract.py` parses that exact committed
shell engine without executing it. It compares each shell `type`, `pkgName`, and
`pkgPathPattern` assignment
with `pkg_in_dmg`, and refuses an allowlisted record that has no executable shell
stanza. The parser keeps `pkgName` and `pkgPathPattern` distinct and CI proves
that both production dispatch branches are reachable in their documented
order. The verifier uses the same manifest locator and refuses zero or multiple
package matches. Installomator previously selected the first root or recursive
match. The fork now deliberately fails when either search returns more than one
package. Root-default is safe for endpoint allowlisting once the other endpoint
gates pass because it remains root-only and exact-one; it never enables the
recursive fallback. CI exhaustively proves that every manifest root-default
record maps to a shell `pkgInDmg` stanza without either selector variable,
every explicit record maps to one typed shell assignment or architecture
branch, and ambiguity remains a
label-local verification alert rather than aborting the run. No currently
allowlisted endpoint label is `pkgindmg`; the stricter selection is a deliberate
compatibility change before that type is enabled on endpoints. Historical
nested/dynamic shell cases have explicit locators; a future root-default vendor
layout change intentionally alerts instead of being made green by verifier-only
recursive discovery. There are currently no verifier-only `pkgindmg` records
without a matching Installomator stanza. CI keeps that inventory explicitly
empty and rejects a future no-stanza record until its historical discovery
behaviour is deliberately represented by a typed locator; it cannot enter the
endpoint allowlist. This closes the discovered payload-selection gap
specifically; the table above covers every other execution-affecting field.

Fiery Command WorkStation and Packages remain explicitly shell-only and cannot
enter the derived endpoint allowlist. Their selectors are still safety-parsed
by CI, but PAT-1385 does not invent manifest identity, application-path, or
download facts that have not been independently verified.

`ci/test-pkgindmg-runtime.zsh` invokes the shipped `installPkgInDmg` dispatcher
end to end with only mount/install side effects stubbed, then exercises its
resolver against nested JRE, case, bare-parenthesis rejection, control-character,
segment-boundary, symlink, package-bundle, root preference and ambiguity
fixtures. Safety and match expectations shared with the Python validator and
verifier live in `ci/fixtures/pkgindmg-locator-cases.json`, preventing three
independent test definitions from drifting. The verifier suite mirrors those
behaviours and contains locator failures inside the affected label.

**Known caveats, kept visible on purpose (PAT-1385, round 10, 2026-08-16).**
Ten remediation rounds is a lot for one ticket; each round documents what it
found and did not chase further here as accepted residual risk, following
this repo's own convention (see the workspace CLAUDE.md's
PAT-1041/PAT-1001/PAT-1056 entries), rather than an open-ended eleventh
round. Each remaining item is real but narrow:

- **`version: None` for `resolved-source` labels on non-archiware
  vendor-api/static/github-release/http-redirect strategies — confirmed NOT
  a regression (round 10).** Round 9 flagged this as unconfirmed either way.
  Checked against the actual pre-PAT-1385 code (`git show
  d3972051:verifier/verify.py`, the parent commit of this ticket's own sole
  commit on this branch): `extract_version()` returned `None`
  *unconditionally* for `version.source: resolved-source`, for every
  strategy including sparkle-appcast, with its own docstring stating this
  was deliberate — "version.source: resolved-source is documented
  (verifier/README.md, 'Prototype scope') as deferred for every
  sparkle-appcast label, not just this one, so wiring it end to end is left
  as it was rather than a one-off for this single label." Neither
  `_resolve_url_with_version()` nor `resolved_source_version` existed at all
  before this ticket. So for 745 of 784 `resolved-source` labels on
  strategies this ticket never touched (static: 275, non-archiware
  vendor-api: 242, github-release: 226, http-redirect: 2 — counted
  2026-08-16 against `engine/labels/*.json`), `version` was `None` before
  this ticket and remains `None` now: not a regression, a pre-existing gap
  this ticket narrowed (from all 784 `resolved-source` labels always
  reporting `None`, to 39 now correctly populated — 35 sparkle-appcast + 2
  sparkle-plist-feed + archiwareb2go/archiwarepst's dedicated vendor-api
  resolver) rather than widened. Pinned by
  `ResolvedSourceVersionNonRegressionTests` in `verifier/test_verify.py`.
- **`engine/fragments/functions.sh`'s trailing blank line removed with no
  matching change in the assembled `engine/Installomator.sh`** — a one-byte
  fragments/shipped-engine sync gap;
  `test_executed_fragment_dispatch_is_byte_identical_to_shipped_engine` only
  compares the resolver/`installPkgInDmg` region specifically, not the whole
  file, so it wouldn't catch this.
- **The claim that no currently-generated allowlist entry is `pkgindmg`
  (the compatibility argument for the stricter `installPkgInDmg` selection
  tightening) is not CI-enforced** — nothing in `ci/validate-labels.py` /
  `ci/test_installomator_pkg_contract.py` actually prevents a future PR from
  allowlisting a `pkgindmg` label, which would silently ship the stricter
  selection behaviour to real endpoints without anyone re-checking the
  compatibility assumption.
- **Multi-line-quote tracking gaps in the pkg contract's `shell_types`/
  `source_pkgindmg_count` reconciliation** (`ci/installomator_pkg_contract.py`
  ~line 315) — a `type="pkgInDmg"` string occurring inside an unrelated quoted
  payload could be miscounted as a real type assignment; a narrow,
  unlikely-but-possible false-CI-failure shape.
- **Triple-implementation pattern vocabulary/matcher disagreement**
  (`verifier/verify.py` ~line 1990, plus `resolvePkgPathPattern`'s shell
  implementation) — the Python-side and shell-side glob-pattern matchers are
  independent implementations that could disagree on edge-case patterns (e.g.
  a character class spanning a path separator); the shared test corpus in
  `ci/fixtures/pkgindmg-locator-cases.json` doesn't cover every shape where
  they could diverge. Confirmed round 11: a pattern like `A[/]B.pkg` passes
  both matchers' bracket-balance checks but is then split on `/` before
  matching, so Python's `fnmatch` treats the dangling `A[` as a literal while
  zsh's glob sees a malformed pattern — a locator CI has already blessed on
  which verifier and endpoint could disagree.
- **A single unbalanced apostrophe anywhere in a pkgInDmg stanza can swallow
  every subsequent line of that stanza in the pkg contract's quote tracker**
  (`ci/installomator_pkg_contract.py` ~line 455, round 11) — the tracker
  treats any unmatched `'` as opening a multi-line quoted span; an ordinary
  same-line trailing comment like `# vendor's installer` is not excluded. If
  the swallowed text was the stanza's only `pkgName=`/`pkgPathPattern=`
  assignment, the drift gate sees no selector at all and a manifest record
  passes clean against a shell stanza that really does pin a payload path —
  the one place in this ticket's parsing work that fails **open** rather
  than closed, unlike everything else here. Real risk, not yet fixed: caught
  late, after ten rounds already invested; recommend a focused, narrowly-
  scoped follow-up ticket specifically for this one parser fragility rather
  than an eleventh round on this ticket.
- **`_ARCHIWARE_VERSION_RE`'s greedy capture** (`verifier/verify.py` ~line
  1227, round 11) — `r'ARCHIWARE P5 Version (.*) -'` captures to the *last*
  ` -` on the matched line, so incidental trailing prose containing digits
  on the real vendor page would be absorbed into the "version" before it's
  digit-stripped and interpolated into both the resolved S3 download URL and
  the `relative-path-version-digits` pkgName template — a benign vendor
  copy-edit could turn into a wrong URL and a wrong payload path (alerting
  every run) rather than a clean, recognisable `FeedResolutionError`. Not
  yet fixed; the real page was hand-verified clean as of this ticket's round
  2 investigation, so this is a latent fragility rather than a live bug
  today.

## 7. The allowlist is a view, not a separate file

The endpoint allowlist is **derived**: it is the subset of manifest records with
`patched.allowlisted = true`. The stopgap `endpoint/labels-allowlist.txt` from
the prototype is superseded — it should be generated from the manifest, not
hand-maintained, so the two cannot drift.

## 8. How the verification agent interacts with it

The agent (review §4.9, `verification-agent-design.md`) **reads** records to
know what to verify, and **proposes** changes to them via PR — a version bump, a
candidate replacement URL. It never writes to a record directly. Crucially, the
agent's daily runtime results (last-verified timestamp, observed hashes, the
day's classification) live in the agent's **own state store**, *not* in the
label record. The label record stays a clean, human-curated, human-reviewed
artifact; mixing agent runtime state into it would make every daily run a diff
and destroy the review ergonomics §2 exists to protect.

## 9. Adding or changing a label

1. Add or edit `engine/labels/<label>.json`.
2. Confirm `expected_team_id` against Apple's records and the vendor.
3. Set `patched.reviewed_by` / `reviewed_at`; note redistribution-licensing
   status in `patched.notes` if the app is a mirror candidate. When the licence
   requires an accompanying notice, add `redistribution_notice` with its SPDX
   identifier, authoritative HTTPS URL and pinned SHA-256.
4. Open a PR. CI (§5) runs. A human reviews — for agent-opened PRs this review
   is the trust gate.
5. Until a compiler replaces the paired representation, update both the JSON
   record and shell stanza. The semantic gate in §6 rejects managed drift.

## 10. Current state

`engine/labels/` holds 1,108 records (as of PAT-1429), all validating against
the schema. Seven are currently endpoint-allowlisted and are covered exhaustively
by the PAT-1403 semantic contract. The remaining 1,101 records are verifier and
catalogue candidates, not executable managed labels; their full shell parity is
not yet enforced. PAT-1385 separately models and checks `pkgindmg` payload
locators before any affected label can be allowlisted.

The residual migration is deliberately explicit: available-version resolver
expressions remain arbitrary shell, including on six managed labels. The gate
classifies those assignments but does not prove equivalence with the verifier's
version strategy. Most of the 1,102 candidate stanzas also have shell-only
fields. Those labels must remain non-allowlisted until their execution fields
are represented and accepted by the semantic gate, or until a future typed
compiler makes the shell dispatch a generated artifact.

## 11. Removed labels

A label is retired (record + `Installomator.sh` stanza + `engine/fragments/labels/`
fragment deleted) rather than retargeted when the vendor discontinues the product
or folds it into something else — retargeting a label at a different app under its
old name is the declared-vs-actual mismatch this manifest exists to prevent. Kept
here as the durable record of why a given count dropped:

| Label | Date removed | Ticket | Reason |
|---|---|---|---|
| `strongsync` | 2026-08-13 | PAT-1291 | Discontinued by the vendor and folded into ExpanDrive; the static URL 404s and the appcast now serves an ExpanDrive artifact under the Strongsync name. |
| `skype` | 2026-08-13 | PAT-1331 | Consumer Skype was discontinued by Microsoft. The redirect certificate at get.skype.com expired; TLS-verified requests fail, and even with TLS ignored the endpoint returns HTTP 400 with no redirect and no download URL. No live successor exists at that path. |
| `bartender` | 2026-08-17 | PAT-1386 | Bartender was sold by its original developer to Applause Group in June 2024, publicly confirmed by the seller and covered by multiple outlets. The live artifact is now signed by Team ID `24J875RH8J`, not the pinned `8DD663WDX4` (Surtees Studios Ltd) — a genuine, reproducible signer change, not a hijack, but the new steward's trustworthiness is unverified and the app requires Accessibility-level system permissions. Never allowlisted, never mirrored, never customer-installed, so nothing was installing it. Dropped rather than retargeted at the new Team ID. |
| `loupedeck` | 2026-08-19 | PAT-1429 | Loupedeck was acquired by Logitech Inc. The live artifact is now signed by Team ID `QED4VVPZWA` (Logitech Inc.), not the pinned `M24R8BN5BK`; the artifact is properly notarized and Logitech is the legitimate acquirer, not a hijacker. Not in the Software Catalogue (`catalogue_apps`), so nothing was installing it and re-pinning would take on a custodian decision for software Patched does not manage, for no benefit. Dropped rather than retargeted at the new Team ID. |
| `polylens` | 2026-08-19 | PAT-1429 | Polylens (Lens Desktop) was acquired by HP Inc. The live artifact is now signed by Team ID `6HB5Y2QTA3` (HP Inc.), not the pinned `WJCM3F7AQ4`; the artifact is properly notarized and HP is the legitimate acquirer, not a hijacker. Not in the Software Catalogue (`catalogue_apps`), so nothing was installing it and re-pinning would take on a custodian decision for software Patched does not manage, for no benefit. Dropped rather than retargeted at the new Team ID. |

## 12. Known caveats, kept visible on purpose (PAT-1403)

Four remediation rounds went into the execution-drift gate (`ci/installomator_execution_contract.py`
and its test suite). Round 4 fixed the two most security-relevant findings from the fourth review —
the stale root `eval` in `engine/fragments/arguments.sh` (confirmed dead for shipping purposes; see
the loud comment above its `eval` and
`test_fragments_arguments_sh_dead_for_shipping_invariants_hold` in
`ci/test_installomator_execution_contract.py`) and the value-shape gap in the
`_VERSION_RESOLVER_FIELDS` exemption — and stops there. The remaining five findings are recorded
here as accepted residual risk rather than silently dropped, following the same convention as the
"Known caveats, kept visible on purpose" section of the workspace root `CLAUDE.md` (the PAT-1041 /
PAT-1001 / PAT-1056 pattern): a documented gap is honest and acceptable; hiding it to make the gate
look more finished than it is would not be.

- **Mirror exemption doesn't pin that `PINNED_SHA256`/`OVERRIDE_DOWNLOAD_URL` are actually always
  passed by the real caller.** `_engine_pins_downloaded_artifact_hash` proves the engine checks a
  pin IF one is supplied, but nothing confirms `endpoint/patched-update.sh` always supplies one for
  every mirrored label; if a caller ever stopped passing it, the mirror downloadURL exemption would
  go silently vacuous while CI stays green.
- **Argument-name drift between the reapply pass's strict allowlist and the first pass's
  silent-ignore is unpinned.** The reapply pass (`PATCHED_REAPPLY_ARGUMENTS_START`) hard-aborts on a
  non-allowlisted `KEY=value` token; the first pass merely logs and continues for the same token.
  Nothing in CI confirms the argument names `patched-update.sh`/`patched-install.sh` actually emit
  stay within `patchedAllowedArgNames`, so a future caller change could turn a previously-harmless
  argument into a fleet-wide fatal failure.
- **`_DEFAULT_ARM_RE` only matches a bare, unindented `*)` alone on its own line.** It doesn't match
  its own docstring's example shape (`*) cleanupAndExit 1 "unknown label $label" ;;`, same line) or
  an indented catch-all; those shapes still risk misattribution into the preceding label's stanza.
- **`_nesting_delta` skips comment lines but not string literals.** A nesting-token-shaped word
  inside a quoted message (e.g. `"download failed; if this persists…"`) could still perturb the
  computed depth and the mirror exemption decision.
- **The zsh-dependent CI steps have no environment guard.** If a runner image lacks `zsh`, the
  label-validation gate errors rather than skipping with a clear message.
