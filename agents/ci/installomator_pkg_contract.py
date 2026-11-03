"""Semantic contract between pkgindmg manifest records and Installomator.

The endpoint ships and executes ``engine/Installomator.sh``.  It does not ship
``engine/labels/*.json``.  This module therefore parses the exact shell label
stanzas that reach endpoints and compares their ``type``/``pkgName`` semantics
with the structured manifest contract.  It never executes or sources shell.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_ARM_PART_RE = re.compile(
    r"^([A-Za-z0-9_.-]+(?:\|[A-Za-z0-9_.-]+)*)(\|\\|\))$")
# PAT-1432: two additional valid-zsh case-arm spellings the arm-boundary
# walker below did not recognise at all, found by PAT-1429's real-corpus
# survey of engine/Installomator.sh and confirmed exhaustive by a
# programmatic sweep of the current file (every line between the top-level
# `case $label in` and its closing `esac`, checked for: a leading-whitespace
# variant, a `;;`-glued variant, zsh's `;&`/`;;&` fallthrough operators, and
# a same-line arm+body+terminator one-liner -- only the first two shapes
# occur anywhere in the real corpus):
#   - an INDENTED arm, e.g. the real `    displaynote)`, `    supportapp)`
#     -- still a single line containing nothing but the arm text, just not
#     flush against column 0.
#   - an arm GLUED directly onto the preceding stanza's `;;` terminator on
#     the same physical line, e.g. the real `;;egnyte)`,
#     `;;editshare-flowstory)`.
# Both are recognised by reducing a line to "what's left after stripping
# leading whitespace and/or a `;;` prefix" and re-testing the exact same
# _ARM_PART_RE the original walker used -- see
# _new_spelling_arm_header_match() and _match_arm_header() below -- rather
# than inventing a second, drift-prone arm grammar.
#
# The real corpus also contains NESTED `case ... in ... esac` blocks inside
# a stanza's own body (e.g. macports' `case $(uname -r | cut -d '.' -f 1)
# in ... 25) ... esac`, and several `case $(arch) in ... esac` blocks
# elsewhere) whose own arms can coincidentally look like a top-level label
# arm once stripped of leading whitespace (macports' bare-numeric `25)`,
# `24)`, ...). Widening the walker to recognise indentation as a possible
# arm boundary would misfire on those without tracking nested-case depth --
# see the nested_case_depth counter in parse_installomator_labels() and
# _NESTED_CASE_OPEN_RE/_NESTED_CASE_CLOSE_RE below, which gate the two new
# spellings (never the original, unindented, unglued spelling, whose
# behaviour over the existing 1000+-label corpus is intentionally left
# untouched) to only fire outside any nested case block.
_NESTED_CASE_OPEN_RE = re.compile(r'^\s*case\b.*\bin\s*$')
_NESTED_CASE_CLOSE_RE = re.compile(r'^\s*esac\s*$')
_TYPE_RE = re.compile(r'^\s*type="([A-Za-z0-9]+)"\s*$')
# PAT-1429: captures a stanza's own `expectedTeamID=` assignment line(s),
# independent of -- and much simpler than -- the pkgInDmg-specific
# tracks_payload machinery above (which only ever runs for stanzas whose
# `type=` is "pkgInDmg" and which reference pkgName/pkgPathPattern/
# appBuildVersion). expectedTeamID appears in effectively every stanza,
# regardless of type, so this scan runs unconditionally over every stanza's
# `body` -- see the assignment site in parse_installomator_labels() below.
# Deliberately line-anchored and NOT run through the multi-line-single-quote/
# nesting state machine tracks_payload uses: every expectedTeamID= assignment
# in the real corpus (verified against the full current engine/Installomator.sh,
# see test_team_id_assignment_is_captured_for_every_current_runtime_stanza) is
# a single physical line, unconditional, never inside a nested case/if
# branch -- so a lighter-weight scan is sufficient and lower-risk than
# threading expectedTeamID through the payload-selector-specific parser.
# A comment-only line is skipped so prose mentioning "expectedTeamID=" cannot
# be mistaken for a real assignment.
_TEAM_ID_ASSIGN_RE = re.compile(r'^\s*expectedTeamID=(.*?)\s*$')


def _body_suggests_absorbed_arm_boundary(body: list[str]) -> bool:
    """PAT-1429 (non-author-review follow-up, round 2): True when `body` (a
    stanza's own collected lines) contains evidence that a NEIGHBOURING
    label's stanza was absorbed into it, because a real arm boundary inside
    it went unrecognised.

    PAT-1429's real-corpus survey found this happening two ways in
    engine/Installomator.sh, both valid zsh:
      - an INDENTED arm, e.g. the real `    displaynote)`, `    supportapp)`
        -- recognised here by stripping leading whitespace and re-testing
        the same _ARM_PART_RE the real walker uses;
      - an arm GLUED directly onto the preceding stanza's `;;` on the same
        physical line, e.g. the real `;;egnyte)`, `;;editshare-flowstory)`
        -- recognised here by testing the text immediately following any
        `;;` substring in the line.

    PAT-1432 taught parse_installomator_labels()'s real arm-boundary walker
    both of these spellings, gated on nested `case ... in ... esac` depth so
    a stanza's own NESTED case block (e.g. macports' `case $(uname -r ...)
    in ... 25) ... esac`) is never mistaken for a label-arm boundary -- see
    _new_spelling_arm_header_match()'s docstring. A first version of this
    fix updated only the real walker and left this diagnostic function
    checking the same two shapes WITHOUT that nested-case gate -- so it kept
    false-positiving on macports specifically (its own nested numeric arms
    `25)`, `24)`, ... still look, line-by-line, exactly like an absorbed
    neighbour to a scan with no case-depth awareness), even though the real
    walker had already correctly parsed macports into a single, ungapped
    stanza with exactly one expectedTeamID. Caught by re-running against the
    real corpus rather than trusting the "should be unreachable" reasoning:
    `boundary-gap suspected now: ['macports']` -- one real label, not zero.

    This function now reuses the EXACT SAME nested-case-depth tracking the
    real walker uses (_NESTED_CASE_OPEN_RE/_NESTED_CASE_CLOSE_RE, and the
    same _new_spelling_arm_header_match() line-level matcher), rather than a
    second hand-maintained implementation of that gating -- so the two can
    no longer drift apart the way the first version already did once. A
    post-fix real-corpus sweep confirms this is genuinely empty: zero shell
    stanzas are flagged team_id_boundary_gap_suspected today (macports
    included), and (as before this second fix) zero have more than one
    expectedTeamID assignment at all. It remains reachable only via the
    narrow synthetic shape in
    test_boundary_gap_message_remains_reachable_via_nested_case_false_
    positive (test_team_id_contract.py) -- a genuine same-stanza double
    assignment that itself sits inside a nested case block, which is a
    different (and inherently unfixable by boundary-recognition alone)
    shape from "this nested case's own arm was mistaken for the absorbed
    neighbour". Deliberately left in place anyway, on Andy's call: it is a
    fail-closed guard, and a guard that is currently redundant is
    preferable to one that has been deleted and is later needed. Used only
    to choose which of two ambiguous-multiple-expectedTeamID error messages
    _effective_team_id() reports; never to actually recover a missing
    boundary or reparent absorbed lines itself.
    """
    nested_case_depth = 0
    for line in body:
        if nested_case_depth == 0 and _new_spelling_arm_header_match(line):
            return True
        if _NESTED_CASE_OPEN_RE.match(line):
            nested_case_depth += 1
        elif nested_case_depth and _NESTED_CASE_CLOSE_RE.match(line):
            nested_case_depth -= 1
    return False


_PKG_NAME_RE = re.compile(r"^\s*pkgName=(.+?)\s*$")
_PKG_PATH_PATTERN_RE = re.compile(r"^\s*pkgPathPattern=(.+?)\s*$")
_VERSION_COMPONENT_RE = re.compile(
    r'^\s*appBuildVersion=\$\(echo \$appNewVersion \| cut -d'
    r'(?P<separator>[^\s]) -f(?P<component>[1-9][0-9]*)\)\s*$')
_ARCH_BRANCH_RE = re.compile(
    r'^\s*(?:if|elif) \[\[ \$\(arch\) == "(arm64|i386)" \]\]; then\s*$')
_SHELL_VAR_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
_SAFE_PATTERN_RE = re.compile(r"^[A-Za-z0-9 ._+()@/\[\]*?-]+$")
_ARCHIWARE_ASSIGNMENT_PREFIX = (
    "$(appNrVersion=`sed 's/[^0-9]//g' <<< $appNewVersion` && echo "
)
# PAT-1385 P2 fix (round 8, finding "appNewVersion itself never checked"):
# the pkg-contract previously only compared the `cut` separator/field-index/
# template SHAPE a version-component locator applies, never confirmed the
# shell and manifest agree on WHICH appcast XML node appNewVersion itself
# comes from -- the same class of bug as the P1 jre8 finding, but as a CI
# gate gap rather than a runtime one. `appNewVersion=` is matched here
# (a sibling of _VERSION_COMPONENT_RE's `appBuildVersion=` match, same
# per-stanza parse loop) whenever it visibly targets a Sparkle
# sparkle:version/shortVersionString node, in whichever of the shapes
# engine/Installomator.sh's own labels actually use: an xpath attribute
# read (`enclosure/@sparkle:version`), a grep/sed scrape of that same
# attribute's raw `field="value"` text, or a child-element/text read
# (`item[1]/sparkle:version`, `string(//item/sparkle:shortVersionString)`).
_APP_NEW_VERSION_RE = re.compile(r'^\s*appNewVersion=(?P<rhs>.*)$')
_SPARKLE_ENCLOSURE_ATTR_RE = re.compile(r'enclosure/@sparkle:(version|shortVersionString)\b')
_SPARKLE_ATTR_TEXT_RE = re.compile(r'sparkle:(version|shortVersionString)="')
_SPARKLE_CHILD_RE = re.compile(r'sparkle:(version|shortVersionString)\b')
# PAT-1385 P2 fix (round 8, finding "wildcard over-generalizes variable
# interpolation"): a $var/${var} interpolated into a quoted pkgName is no
# longer ever silently collapsed to a bare `*` wildcard -- see
# _normalise_pkg_name_assignment()'s docstring. Every interpolated name
# must be explicitly classified here, in one of these two sets, or the
# normaliser fails closed (ValueError, naming the unrecognised variable)
# rather than guessing.
_VERSION_BEARING_SHELL_VARS = frozenset({"appNewVersion"})
# The ONE Installomator shell variable name this codebase has confirmed,
# by reading engine/Installomator.sh, is used to interpolate a resolved
# artifact version directly into a quoted pkgName value (eastwestplay's
# `pkgName="Play Installer ${appNewVersion}.pkg"` -- not itself
# pkgindmg-typed today, but the shape this set exists to recognise the
# moment a pkgindmg label uses it). A deliberately narrow, hand-reviewed
# allowlist, not a heuristic ("any name containing 'version'") -- a
# heuristic can under- or over-match silently; a missed name here instead
# fails CLOSED via the `else: raise` in _normalise_pkg_name_assignment().
_WILDCARD_SAFE_SHELL_VARS: frozenset[str] = frozenset()
# Deliberately empty: no Installomator pkgindmg pkgName variable
# interpolation in this codebase's corpus has been confirmed
# non-version-bearing and therefore safe to collapse to a bare `*`
# wildcard. Add a name here only after confirming, by reading the actual
# shell stanza, that it can never carry version-identifying data.
SHELL_ONLY_EXPLICIT_PKGIN_DMG = frozenset({
    "fierycommandworkstation",
    "packages",
})
VERIFIER_ONLY_PKGIN_DMG = frozenset()

# PAT-1424: an absent pkg_in_dmg block is not a blank waiting to be filled --
# it is an unreviewed claim that the label's payload is a single unique .pkg
# at the mounted DMG's root (see pkgindmg_locator_mode()'s default). A
# repo-wide audit (PAT-1424) mounted the real DMG for every pkgindmg record
# that relied on this implicit default and had no shell pkgName/
# pkgPathPattern for the static contract to corroborate it against. Every
# record that audit could positively confirm now carries an EXPLICIT
# ``pkg_in_dmg: {"mode": "root-unique-pkg"}`` block (see engine/labels/*.json)
# so it no longer depends on either dict below at all.
#
# The records that audit could NOT reduce to zero split into two genuinely
# different states -- collapsing them into one dict (as an earlier version
# of this fix did) loses the more serious one, so they now live in two
# dicts. Non-author review caught this: it is the difference between "we
# checked and it is wrong" and "we could not check at all".
#
# - UNCONFIRMED_PKGINDMG_ROOT_DEFAULT (this dict): the real DMG could not be
#   downloaded/inspected at all (a 404, a login gate, a bot block, a blank
#   per-deployment placeholder). Whether the root-unique-pkg default is
#   actually true for these labels is still genuinely unknown.
# - KNOWN_INCORRECT_PKGINDMG_DEFAULT (below): the real DMG WAS inspected and
#   the root-unique-pkg default was found to be FALSE. This is worse than
#   "unconfirmed" -- the record is actively asserting something false at
#   runtime -- so it gets its own dict, its own tracking-ticket requirement,
#   and its own test coverage rather than hiding inside this one.
#
# Both dicts feed is_reviewed_pkgindmg_locator() and the CI check in
# pkgindmg_contract_errors() (PAT-1424) so that a BRAND NEW pkgindmg record
# added later without either an explicit pkg_in_dmg block or an entry in one
# of these two dicts fails CI immediately, instead of quietly joining the
# unreviewed pile this ticket exists to empty out.
UNCONFIRMED_PKGINDMG_ROOT_DEFAULT: dict[str, str] = {
    "examplify": (
        "vendor page https://support.examsoft.com/hc/en-us/articles/"
        "11146797283469 returns HTTP 403 to a scripted request (bot-"
        "blocked) -- the shell's own curl-based downloadURL scrape gets "
        "the same empty result at runtime (\"need to provide "
        "'downloadURL'\"), so no DMG could be downloaded to inspect."
    ),
    "jdk20": (
        "downloadURL https://download.oracle.com/java/20/latest/"
        "jdk-20_macos-aarch64_bin.dmg returns HTTP 404 -- Oracle's "
        "'latest' JDK 20 pointer is gone (20 is an out-of-support release "
        "line), so no DMG could be downloaded to inspect."
    ),
    "korgsoftwarepass": (
        "downloadURL https://storage.korg.com/korgms/korg_collection/mac/"
        "KORG_Software_Pass_.dmg returns HTTP 404 -- the shell's version "
        "scrape appears to resolve to an empty string (note the bare "
        "trailing underscore before .dmg in the URL), so no DMG could be "
        "downloaded to inspect."
    ),
    "nomachine": (
        "downloadURL https://download.nomachine.com/download/?id=117&"
        "platform=mac returns an HTML page, not a DMG -- either the "
        "vendor's redirect/anti-bot filter rejected the scripted request, "
        "or the URL shape has changed, so no DMG could be downloaded to "
        "inspect."
    ),
    "plantronicshub": (
        "downloadURL https://www.poly.com/content/dam/www/software/"
        "PlantronicsHubInstaller.dmg returns an HTML page (hdiutil "
        "\"image not recognised\"), not a real DMG -- the static URL "
        "appears stale, so no DMG could be downloaded to inspect."
    ),
    "steinbergcubaseelementsaile13": (
        "vendor page https://o.steinberg.net/en/support/downloads/"
        "cubase_13/cubase_elements_13.html redirects (HTTP 303), "
        "consistent with Steinberg gating the real download behind a "
        "MySteinberg account login -- the shell's own scrape gets the "
        "same empty result at runtime (\"need to provide 'downloadURL'\"), "
        "so no DMG could be downloaded to inspect."
    ),
    "steinbergcubaseproartist13": (
        "vendor page https://o.steinberg.net/en/support/downloads/"
        "cubase_13/cubase_pro_13.html redirects (HTTP 303), consistent "
        "with Steinberg gating the real download behind a MySteinberg "
        "account login -- the shell's own scrape gets the same empty "
        "result at runtime (\"need to provide 'downloadURL'\"), so no DMG "
        "could be downloaded to inspect."
    ),
    "teamviewerhostcustom": (
        "the Installomator shell stanza's own "
        "teamviewerCustomDownloadURL=\"\" is a blank per-deployment "
        "placeholder (TeamViewer Host Custom requires an MSP-specific "
        "branded subdomain) -- there is no generic download to resolve "
        "at all, so no DMG could ever be downloaded to inspect without "
        "company-specific configuration this codebase does not have."
    ),
}

# PAT-1424 (non-author-review follow-up): records where the real DMG WAS
# mounted and inspected, and the implicit root-unique-pkg default was found
# to be actively FALSE -- distinct from UNCONFIRMED_PKGINDMG_ROOT_DEFAULT
# above, whose entries were never inspectable at all. A record here has, in
# a real sense, been reviewed MORE thoroughly than most of the manifest: the
# claim was checked against a real artifact and is known wrong. It still
# counts as reviewed for is_reviewed_pkgindmg_locator() -- the record has
# genuinely been looked at, and the fix belongs to a named follow-up ticket,
# not to a red CI gate. Deliberately NOT wired to fail pkgindmg_contract_
# errors(): CI is dark org-wide right now (PAT-1425), so a red gate here
# would be invisible rather than loud, and once CI returns it would block
# unrelated PRs over a defect that already has zero customer exposure
# (every entry here must be `patched.allowlisted: false` -- see
# test_known_incorrect_pkgindmg_default_records_are_not_allowlisted) and an
# already-tracked fix.
#
# Every reason string MUST name the tracking ticket for the engine-side fix
# -- "known wrong, no ticket" is not an acceptable end state for this dict;
# that is what turns a real defect back into something that quietly does
# not get fixed.
KNOWN_INCORRECT_PKGINDMG_DEFAULT: dict[str, str] = {}


def _appcast_version_field(rhs: str) -> tuple[str, str] | None:
    """Classify which appcast XML node an ``appNewVersion=`` assignment's
    right-hand side reads, as (source_shape, field):

    - source_shape == "enclosure-attribute": the assignment targets
      ``enclosure/@sparkle:<field>`` -- either via an xpath attribute
      read, or a grep/sed scrape of that same attribute's raw
      ``field="value"`` text (textually indistinguishable from the xpath
      form once serialised, and semantically the identical XML node).
    - source_shape == "item-child": the assignment targets a
      ``<sparkle:field>`` child element/text node instead (e.g.
      ``item[1]/sparkle:version``, ``string(//item/sparkle:shortVersionString)``).

    Returns None when the assignment does not recognisably target a
    Sparkle sparkle:version/shortVersionString node at all -- archiware's
    HTML-page scrape, a GitHub API lookup, or any other non-Sparkle
    appNewVersion source. Callers must treat None as "this label is not
    Sparkle-appcast-sourced" and skip the cross-check rather than failing
    it -- see pkgindmg_contract_errors()'s version_source handling.
    """
    match = _SPARKLE_ENCLOSURE_ATTR_RE.search(rhs)
    if match:
        return ("enclosure-attribute", match.group(1))
    match = _SPARKLE_ATTR_TEXT_RE.search(rhs)
    if match:
        return ("enclosure-attribute", match.group(1))
    match = _SPARKLE_CHILD_RE.search(rhs)
    if match:
        return ("item-child", match.group(1))
    return None


@dataclass(frozen=True)
class ShellLabel:
    stanza_labels: tuple[str, ...]
    shell_types: tuple[str, ...]
    pkg_name_assignments: tuple[str, ...]
    pkg_name_assignments_by_arch: tuple[tuple[str, tuple[str, ...]], ...] = ()
    pkg_path_pattern_assignments: tuple[str, ...] = ()
    # PAT-1429: every raw `expectedTeamID=` right-hand side found anywhere in
    # this stanza's body (see _TEAM_ID_ASSIGN_RE), captured unconditionally
    # -- unlike the pkgName/pkgPathPattern fields above, this is populated
    # regardless of `type=` and regardless of whether the pkgInDmg-specific
    # payload parsing below succeeded or failed (see both ShellLabel(...)
    # construction sites). Normally exactly one entry; see
    # team_id_contract_errors() for how zero or multiple entries are treated
    # -- never as agreement.
    team_id_assignments: tuple[str, ...] = ()
    # PAT-1429 (non-author-review follow-up, round 2): True when this
    # stanza's body contains a line that looks like a case-arm boundary the
    # shared line-anchored _ARM_PART_RE walker above failed to recognise as
    # one -- see _body_suggests_absorbed_arm_boundary()'s docstring. Used
    # only to distinguish, in _effective_team_id()'s multiple-assignment
    # error message, "this stanza genuinely assigns expectedTeamID twice"
    # from "a neighbouring label's stanza was absorbed into this one", so an
    # investigator is pointed at the right root cause instead of auditing
    # this stanza's own (correct) assignment.
    team_id_boundary_gap_suspected: bool = False
    version_component_derivations: tuple[tuple[str, int], ...] = ()
    # PAT-1385 P2 fix (round 8): the (source_shape, field) classification
    # of this stanza's unconditional appNewVersion= assignment (see
    # _appcast_version_field()), or None when none was found / it does not
    # recognisably target a Sparkle sparkle:version/shortVersionString
    # node. Used only to cross-check a relative-path-version-component
    # locator's version_source against what the shell actually reads.
    app_new_version_sparkle_field: tuple[str, str] | None = None
    # PAT-1385 round 9 (P2 finding 2b): set when parse_installomator_labels()
    # could not safely parse THIS stanza's body (an unmatched conditional, a
    # payload selector inside an unsupported shape, an unrecognised
    # assignment -- see the per-stanza try/except in that function). Every
    # other field above is then a placeholder (empty/None), not "this
    # stanza genuinely has no pkgName" -- callers MUST check this first and
    # report a per-label failure naming this stanza rather than trusting
    # the empty fields, which is exactly what pkgindmg_contract_errors()
    # does. Before this fix, any stanza-body parse failure raised all the
    # way out of parse_installomator_labels() and pkgindmg_contract_errors()
    # turned that into a single whole-gate abort ("Installomator parser:
    # ...") that silenced every OTHER label's result -- one unrelated
    # label's malformed edit could red the entire CI check with a message
    # that didn't even name the label at fault.
    parse_error: str | None = None

    def normalised_pkg_names(self) -> tuple[str, ...]:
        return tuple(
            _normalise_pkg_name_assignment(rhs)
            for rhs in self.pkg_name_assignments)

    def normalised_pkg_path_patterns(self) -> tuple[str, ...]:
        return tuple(
            _normalise_literal_pattern_assignment(rhs)
            for rhs in self.pkg_path_pattern_assignments)

    def normalised_pkg_name_patterns(self) -> tuple[str, ...]:
        """All unconditional selectors, retained for reporting only."""
        return (*self.normalised_pkg_names(),
                *self.normalised_pkg_path_patterns())

    def normalised_pkg_name_patterns_by_arch(self) -> dict[str, tuple[str, ...]]:
        return {
            arch: tuple(_normalise_pkg_name_assignment(rhs) for rhs in values)
            for arch, values in self.pkg_name_assignments_by_arch
        }


@dataclass(frozen=True)
class PkgInDmgRuntimeCapabilities:
    root_requires_unique: bool
    exact_relative_path: bool
    glob_requires_unique: bool
    relative_path_glob: bool
    path_pattern_precedes_root_default: bool
    pkg_name_dispatch_reachable: bool


def parse_pkgindmg_runtime_capabilities(engine_text: str) -> PkgInDmgRuntimeCapabilities:
    """Read the three payload-selection branches from installPkgInDmg()."""
    resolver_match = re.search(
        r"(?ms)^resolvePkgPathPattern\(\) \{\n(?P<body>.*?)^\}\n", engine_text)
    if not resolver_match:
        raise ValueError("resolvePkgPathPattern function not found")
    resolver_body = resolver_match.group("body")
    match = re.search(r"(?ms)^installPkgInDmg\(\) \{\n(?P<body>.*?)^\}\n", engine_text)
    if not match:
        raise ValueError("installPkgInDmg function not found")
    body = match.group("body")
    root_match = re.search(
        r'(?ms)^\s*elif \[\[ -z \$pkgName \]\]; then\n(?P<body>.*?)'
        r'^\s*else\s*$', body)
    if not root_match:
        raise ValueError("installPkgInDmg root/default branch not found")
    return PkgInDmgRuntimeCapabilities(
        root_requires_unique=(
            'find "$dmgmount" -iname "*.pkg" -type f -maxdepth 1' in root_match.group("body")
            and '[[ ${#filearray} -ne 1 ]]' in root_match.group("body")
        ),
        exact_relative_path=(
            'components=( ${(s:/:)pattern} )' in resolver_body
            and 'entries=( "$base"/${~component}(N^@) )' in resolver_body
        ),
        glob_requires_unique=(
            'matches=( ${(u)matches} )' in resolver_body
            and '(( ${#matches} == 1 )) || return 1' in resolver_body
        ),
        relative_path_glob=(
            'resolvedPkg=$(resolvePkgPathPattern "$pkgPathPattern")' in body
            and 'resolvedPkg=$(resolvePkgPathPattern "$pkgName")' in body),
        path_pattern_precedes_root_default=(
            body.find('if [[ -n "$pkgPathPattern" ]]; then') >= 0
            and body.find('if [[ -n "$pkgPathPattern" ]]; then')
            < body.find('elif [[ -z $pkgName ]]; then')),
        pkg_name_dispatch_reachable=(
            body.find('elif [[ -z $pkgName ]]; then') >= 0
            and body.find('elif [[ -z $pkgName ]]; then')
            < body.find('resolvedPkg=$(resolvePkgPathPattern "$pkgName")')),
    )


def is_endpoint_allowlisted(record: dict) -> bool:
    """The single predicate used by both the contract and allowlist emitter."""
    return record.get("patched", {}).get("allowlisted") is True


# The complete pkg_in_dmg mode vocabulary -- the same set
# pkgindmg_contract_errors()'s final `elif mode not in {...}` branch checks.
# Named once here so a second, driftable copy of this list never needs to
# exist; is_reviewed_pkgindmg_locator() below reuses it for the identical
# reason PAT-1424 exists in the first place (an implicit default is an
# unreviewed claim -- a second hand-maintained mode list would just be
# another place that claim could quietly go stale).
PKGINDMG_LOCATOR_MODES = frozenset({
    "root-unique-pkg",
    "relative-path-glob",
    "relative-path-glob-by-arch",
    "relative-path-version-component",
    "relative-path-version-digits",
})


def pkgindmg_locator_mode(record: dict) -> str | None:
    if record.get("type") != "pkgindmg":
        return None
    return record.get("pkg_in_dmg", {}).get("mode", "root-unique-pkg")


def is_explicit_pkgindmg_locator(record: dict) -> bool:
    mode = pkgindmg_locator_mode(record)
    return mode is not None and mode != "root-unique-pkg"


def is_reviewed_pkgindmg_locator(record: dict) -> bool:
    """PAT-1424: True once this pkgindmg record's payload-locator claim has
    actually been looked at, distinct from is_explicit_pkgindmg_locator()
    above (which is about the locator's MODE, not whether anyone has
    reviewed it -- an explicit ``{"mode": "root-unique-pkg"}`` block is
    deliberately still "root default" to that predicate, see
    test_explicit_root_default_object_is_classified_as_root_default).

    A record counts as reviewed if any of:
    - it carries a well-formed ``pkg_in_dmg`` block (any recognised mode,
      including a confirmed-by-real-DMG explicit root-unique-pkg), or
    - its label is named in UNCONFIRMED_PKGINDMG_ROOT_DEFAULT with a
      specific, on-the-record reason it could not be confirmed (a stale
      URL, a login gate, a blank per-deployment placeholder, etc), or
    - its label is named in KNOWN_INCORRECT_PKGINDMG_DEFAULT: the default
      WAS checked against a real DMG and found false, with a named
      follow-up ticket tracking the engine-side fix. This is a genuinely
      different, more serious state than "unconfirmed" (see that dict's
      docstring) -- but it is still a reviewed state, not an unreviewed
      one, so it still satisfies this gate rather than failing it outright.

    ``pkg_in_dmg`` well-formedness here means only: a dict whose ``mode`` is
    one of PKGINDMG_LOCATOR_MODES. An empty object (``{}``), a dict with no
    ``mode``, an unrecognised ``mode`` string, or a non-dict value (a stray
    string or list) all fail this check and do NOT satisfy the gate --
    non-author review (PAT-1424 follow-up) found presence of the key alone
    used to be the whole signal, letting all of those pass silently. This
    predicate deliberately validates presence and mode ONLY; everything
    else about a locator's internal shape (pattern safety, arch coverage,
    version-component fields, ...) is validate-labels.py's schema check's
    job, not duplicated here -- a second implementation of that validation
    in this module would be exactly the kind of drift-prone duplicate this
    ticket exists to eliminate.

    Only a pkgindmg record with NONE of the above -- no well-formed block,
    no documented unconfirmed reason, no documented known-incorrect entry
    -- is a genuinely unreviewed implicit default, the exact state PAT-1424
    exists to drive to zero and keep at zero going forward.
    """
    if record.get("type") != "pkgindmg":
        return True
    if "pkg_in_dmg" in record:
        locator = record["pkg_in_dmg"]
        return (
            isinstance(locator, dict)
            and locator.get("mode") in PKGINDMG_LOCATOR_MODES)
    label = record.get("label")
    return (
        label in UNCONFIRMED_PKGINDMG_ROOT_DEFAULT
        or label in KNOWN_INCORRECT_PKGINDMG_DEFAULT)


def safe_relative_pkg_pattern_error(pattern: str) -> str | None:
    """Return why a pkg path/glob is unsafe, or ``None`` when acceptable."""
    if not isinstance(pattern, str) or not pattern:
        return "must be a non-empty string"
    if len(pattern) > 512:
        return "is longer than 512 characters"
    if pattern.startswith("/"):
        return "must be relative to the mounted DMG, not absolute"
    if "\\" in pattern or "\x00" in pattern or any(ord(c) < 32 for c in pattern):
        return "contains a backslash, null byte, or control character"
    parts = pattern.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "contains an empty, '.' or '..' path component"
    if not _SAFE_PATTERN_RE.fullmatch(pattern):
        return "contains characters outside the safe relative path/glob vocabulary"
    in_class = False
    for char in pattern:
        if char == "[":
            if in_class:
                return "contains a nested glob character class"
            in_class = True
        elif char == "]":
            if not in_class:
                return "contains an unmatched glob character class terminator"
            in_class = False
        elif char in "()" and not in_class:
            return "contains bare parentheses outside a glob character class"
    if in_class:
        return "contains an unterminated glob character class"
    if not pattern.lower().endswith(".pkg"):
        return "must select a .pkg payload"
    return None


def _normalise_pkg_name_assignment(rhs: str) -> str:
    """Convert the supported shell ``pkgName=`` forms to a safe path glob.

    Current endpoint stanzas use either a quoted value or two Archiware command
    substitutions whose final operation is ``echo <template>``. Archiware's
    value is represented as ``{version_digits}``, matching its exact runtime
    transformation of the resolved version. Any new executable or otherwise-
    unrecognised form fails closed.

    PAT-1385 P2 fix (round 8): a ``$var``/``${var}`` interpolated into a
    QUOTED pkgName value is no longer ever silently collapsed to a bare
    ``*`` wildcard. The pre-fix behaviour did that unconditionally, for
    every interpolated name -- a real broadening bug a non-author review
    (2026-08-15) caught: ``pkgName="Foo ${appNewVersion}.pkg"`` normalised
    to ``"Foo *.pkg"``, which a manifest declaring
    ``relative-path-glob: "Foo *.pkg"`` would match cleanly even though
    the real shell only ever installs the ONE exact, version-pinned build
    ``${appNewVersion}`` names -- exactly the broadening
    relative-path-version-digits/-component exist to prevent for cases
    like this. Each interpolated name is now classified explicitly:
    - A KNOWN version-bearing name (_VERSION_BEARING_SHELL_VARS) becomes
      the ``{version_component}`` placeholder -- the same token
      _normalise_literal_pattern_assignment() already uses for
      pkgPathPattern's ``${appBuildVersion}``, since both represent "an
      exact, non-digit-stripped, resolved version-derived substring
      rendered here." pkgindmg_contract_errors() fails the contract
      outright if this placeholder ever lands in a glob-type mode
      comparison (relative-path-glob/-by-arch), regardless of what the
      manifest's glob pattern literally says -- only an exact
      version-component-shaped locator is accepted for it.
    - A name confirmed non-version-bearing (_WILDCARD_SAFE_SHELL_VARS,
      deliberately empty today) still collapses to ``*``.
    - Anything else fails closed with ValueError naming the unrecognised
      variable, rather than guessing which bucket it belongs in.
    """
    value = rhs.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]

        def _classify_interpolated_var(match: re.Match) -> str:
            name = match.group(0).lstrip("$").strip("{}")
            if name in _VERSION_BEARING_SHELL_VARS:
                return "{version_component}"
            if name in _WILDCARD_SAFE_SHELL_VARS:
                return "*"
            raise ValueError(
                f"pkgName assignment interpolates unrecognised variable "
                f"'{name}' -- not in the known version-bearing or "
                f"confirmed-safe-to-wildcard lists, refusing to guess "
                f"which it is: {rhs}")
        value = _SHELL_VAR_RE.sub(_classify_interpolated_var, value)
    elif value.startswith(_ARCHIWARE_ASSIGNMENT_PREFIX) and value.endswith(")"):
        value = value[len(_ARCHIWARE_ASSIGNMENT_PREFIX):-1].strip()
        value = value.replace('"', "").replace("'", "")
        value = value.replace("$appNrVersion", "{version_digits}")
    else:
        raise ValueError(f"unsupported pkgName assignment: {rhs}")

    if any(token in value for token in ("$", "`", ";", "$(")):
        raise ValueError(f"pkgName assignment did not reduce to data: {rhs}")
    value = re.sub(r"\*+", "*", value)
    err = safe_relative_pkg_pattern_error(
        value.replace("{version_digits}", "0").replace("{version_component}", "0"))
    if err:
        raise ValueError(f"unsafe pkgName assignment {rhs!r}: {err}")
    return value


def _normalise_literal_pattern_assignment(rhs: str) -> str:
    value = rhs.strip()
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ValueError(f"pkgPathPattern must be one quoted data value: {rhs}")
    value = value[1:-1]
    if value.count("${appBuildVersion}") == 1:
        value = value.replace("${appBuildVersion}", "{version_component}")
        safety_value = value.replace("{version_component}", "0")
        err = safe_relative_pkg_pattern_error(safety_value)
        if err:
            raise ValueError(f"unsafe pkgPathPattern {rhs!r}: {err}")
        return value
    if "$" in value or "`" in value:
        raise ValueError(f"pkgPathPattern must not contain shell expansion: {rhs}")
    err = safe_relative_pkg_pattern_error(value)
    if err:
        raise ValueError(f"unsafe pkgPathPattern {rhs!r}: {err}")
    return value


def _new_spelling_arm_header_match(line: str) -> re.Match | None:
    """PAT-1432: match the INDENTED or `;;`-GLUED arm spellings only --
    never the original flush-left, unglued spelling (callers already check
    that separately and unconditionally, so its behaviour is untouched).

    Deliberately excludes a line's leading whitespace alone as proof of a
    real label-arm boundary: a NESTED `case ... in ... esac` block inside a
    stanza's own body (the real macports shape, see _NESTED_CASE_OPEN_RE's
    docstring) can contain its own indented, unquoted, arm-shaped lines
    (macports' bare `25)`, `24)`, ...) that would otherwise false-positive
    here. Callers MUST only invoke this once nested_case_depth is confirmed
    to be 0 -- this function has no way to know that itself.
    """
    stripped = line.lstrip()
    if stripped != line:
        match = _ARM_PART_RE.fullmatch(stripped)
        if match:
            return match
    glue_at = line.rfind(";;")
    if glue_at != -1:
        rest = line[glue_at + 2:].lstrip()
        if rest:
            match = _ARM_PART_RE.fullmatch(rest)
            if match:
                return match
    return None


def _match_arm_header(line: str) -> re.Match | None:
    """The full arm-header matcher: the original spelling (flush-left, no
    glue), OR either PAT-1432 spelling recognised by
    _new_spelling_arm_header_match() above. Used to recognise the START of
    an arm's header line -- at the top of parse_installomator_labels()'s
    main loop, and when following a `|\\`-continued arm -- as opposed to
    the boundary check INSIDE a stanza's own body, which additionally gates
    the two new spellings on nested_case_depth (see that loop below).
    """
    return _ARM_PART_RE.fullmatch(line) or _new_spelling_arm_header_match(line)


def parse_installomator_labels(engine_text: str) -> dict[str, ShellLabel]:
    """Parse label/type/pkgName data from the one real shell label dispatch."""
    lines = engine_text.splitlines()
    opens = [i for i, line in enumerate(lines) if line == "case $label in"]
    if len(opens) != 1:
        raise ValueError(
            f"expected exactly one top-level 'case $label in', found {len(opens)}")

    result: dict[str, ShellLabel] = {}
    i = opens[0] + 1
    while i < len(lines):
        if lines[i] == "esac":
            break
        match = _match_arm_header(lines[i])
        if not match:
            i += 1
            continue

        labels = match.group(1).split("|")
        while match.group(2) == "|\\":
            i += 1
            if i >= len(lines):
                raise ValueError("unterminated continued label arm")
            match = _match_arm_header(lines[i])
            if not match:
                raise ValueError(f"malformed continued label arm at line {i + 1}")
            labels.extend(match.group(1).split("|"))

        body: list[str] = []
        i += 1
        # PAT-1432: depth of NESTED `case ... in ... esac` blocks inside
        # THIS stanza's own body -- see _NESTED_CASE_OPEN_RE/_CLOSE_RE and
        # _new_spelling_arm_header_match()'s docstring. Reset per stanza.
        nested_case_depth = 0
        while i < len(lines):
            line = lines[i]
            if line == "esac":
                break
            if _ARM_PART_RE.fullmatch(line):
                break
            if nested_case_depth == 0 and _new_spelling_arm_header_match(line):
                break
            if _NESTED_CASE_OPEN_RE.match(line):
                nested_case_depth += 1
            elif nested_case_depth and _NESTED_CASE_CLOSE_RE.match(line):
                nested_case_depth -= 1
            body.append(line)
            i += 1

        shell_types = [m.group(1) for line in body if (m := _TYPE_RE.fullmatch(line))]
        # PAT-1429: unconditional, every stanza, regardless of type or
        # whether the pkgInDmg payload parsing below succeeds -- see
        # _TEAM_ID_ASSIGN_RE and ShellLabel.team_id_assignments.
        team_id_assignments = tuple(
            team_id_match.group(1) for line in body
            if not line.lstrip().startswith("#")
            and (team_id_match := _TEAM_ID_ASSIGN_RE.fullmatch(line)))
        # PAT-1429: computed unconditionally alongside team_id_assignments,
        # for the same reason (independent of tracks_payload/type) -- see
        # ShellLabel.team_id_boundary_gap_suspected and
        # _body_suggests_absorbed_arm_boundary()'s docstring.
        team_id_boundary_gap_suspected = _body_suggests_absorbed_arm_boundary(body)
        # PAT-1385 round 9 (P2 finding 2a): the strict structural rules below
        # (appNewVersion/appBuildVersion must be unconditional, pkgName/
        # pkgPathPattern must be top-level or in a single arch conditional,
        # an unrecognised assignment shape fails closed) are pkgInDmg
        # semantics -- they encode how installPkgInDmg() locates a payload
        # inside a mounted DMG, a question that only makes sense for a
        # stanza whose own `type=` is genuinely "pkgInDmg". Before this fix,
        # `tracks_payload` triggered on any stanza whose body merely
        # CONTAINED the substrings pkgName=/pkgPathPattern=/appBuildVersion=
        # -- including pkgInZip (and any other non-pkgInDmg type) stanzas
        # that use pkgName for their own, unrelated reasons (confirmed live
        # in engine/Installomator.sh: eastwestplay and logioptions|
        # logitechoptions are both type="pkgInZip" with their own pkgName=
        # assignments). Scoping to pkgInDmg here means editing one of those
        # unrelated labels can never trip pkgInDmg-specific parsing at all,
        # let alone abort the whole gate over it (see the per-stanza
        # try/except and ShellLabel.parse_error below for the complementary
        # fix once a genuine pkgInDmg stanza's own body IS malformed).
        stanza_is_pkgindmg = "pkgInDmg" in shell_types
        pkg_assignments = []
        pkg_path_patterns = []
        pkg_assignments_by_arch: dict[str, list[str]] = {}
        version_component_derivations = []
        app_new_version_fields: list[tuple[str, str] | None] = []
        current_arch = None
        control_stack: list[str] = []
        in_multiline_single_quote = False
        tracks_payload = stanza_is_pkgindmg and any(re.search(
            r"\b(?:pkgName|pkgPathPattern|appBuildVersion)\s*=", line)
            for line in body)
        # PAT-1385 P2 fix (round 8): multi-line single-quote tracking used
        # to run ONLY for the two labels in SHELL_ONLY_EXPLICIT_PKGIN_DMG
        # (`for char in line if shell_only_quoted_data else ()` iterated
        # zero characters -- and therefore never updated
        # in_multiline_single_quote -- for every other label). That meant
        # any OTHER stanza whose body happened to contain a multi-line
        # quoted payload (a heredoc-like value, an embedded help/usage
        # string) with text matching `pkgName=`, an `if`/`elif`/`else`/`fi`
        # shape purely by coincidence would have that quoted DATA parsed
        # as if it were real shell control flow -- misparsing it, and (via
        # the "unmatched fi"/"unmatched shell conditional" ValueErrors
        # above) aborting the ENTIRE parse for every label in the file,
        # not just the one with the multi-line string. Tracking is now
        # unconditional: every stanza's multi-line single-quoted spans are
        # detected and their contents skipped, regardless of which label
        # they belong to -- the allowlist was never actually a precondition
        # for the detection logic being correct, only for which two labels
        # this codebase had, at the time, confirmed actually needed it.
        # PAT-1385 round 9 (P2 finding 2b): the strict per-line tracking
        # below (and the "unterminated shell conditional" check after the
        # loop) is scoped, by the tracks_payload gate above, to genuine
        # pkgInDmg stanzas only -- but a genuine pkgInDmg stanza can still
        # have a malformed body (a real editing mistake: an unbalanced
        # conditional, a payload selector nested somewhere unsupported, an
        # assignment shape this parser doesn't recognise). Before this fix,
        # any ValueError here propagated all the way out of
        # parse_installomator_labels() and pkgindmg_contract_errors() caught
        # it at the top level, discarding every other label's result along
        # with it ("Installomator parser: <exc>", no label named). Catching
        # it HERE, per stanza, means one label's malformed body degrades to
        # a ShellLabel with parse_error set (shell_types is preserved --
        # computed before this loop and never invalidated by a parse
        # failure inside it) and every other stanza is still parsed and
        # reported normally; pkgindmg_contract_errors() below turns
        # parse_error into a per-label error naming this exact stanza.
        try:
            for line in body:
                if not tracks_payload:
                    continue
                if not in_multiline_single_quote and line.lstrip().startswith("#"):
                    continue
                started_in_quote = in_multiline_single_quote
                # PAT-1385 P2 fix (round 8): a stack of per-$(...)-nesting-level
                # double-quote states, not one flat boolean. `$(...)` command
                # substitution starts a genuinely FRESH quoting scope in real
                # shell -- `"$(curl ... "${var}" ...)"` is valid, unambiguous
                # shell with the inner `"${var}"` totally independent of the
                # outer quotes -- but a single flat in_double_quote toggle
                # cannot tell the two scopes apart: it sees four `"` characters
                # in a row-ish and gets their parity wrong the moment a `'`
                # appears after them (exactly jre8's real downloadURL= line,
                # which has this shape and, before this stack was added, threw
                # the flat-boolean tracker's double-quote parity off by one,
                # spuriously "opening" a multi-line single-quote span that then
                # never closed and silently swallowed jre8's own real
                # pkgPathPattern= line on the NEXT iteration -- caught by
                # test_every_current_runtime_pkgname_has_a_typed_locator_and_
                # no_drift the moment this tracking went from allowlisted-to-
                # two-labels to universal). Reset per physical line, same as
                # the old flat boolean was -- a $(...) that itself spans
                # multiple physical lines is a separate, still-unhandled shape;
                # nothing in the current corpus needs it.
                dquote_stack = [False]
                escaped = False
                prev_char = ""
                for char in line:
                    if in_multiline_single_quote:
                        if char == "'":
                            in_multiline_single_quote = False
                        prev_char = char
                        continue
                    if char == "\\" and not escaped:
                        escaped = True
                        prev_char = char
                        continue
                    if not escaped and char == '"':
                        dquote_stack[-1] = not dquote_stack[-1]
                    elif not escaped and not dquote_stack[-1] and char == "'":
                        in_multiline_single_quote = True
                    elif not escaped and char == "(" and prev_char == "$":
                        dquote_stack.append(False)
                    elif not escaped and char == ")" and len(dquote_stack) > 1:
                        dquote_stack.pop()
                    elif not escaped and not dquote_stack[-1] and char == "#":
                        # PAT-1409 fix: an unescaped `#` that is not inside an
                        # open string starts a real shell comment, and real
                        # shell comments run to end of physical line no
                        # matter what characters they contain. Before this
                        # branch, an ordinary trailing comment on an
                        # unrelated line -- e.g. `# vendor's installer` --
                        # was scanned as if it were shell syntax: the `'`
                        # inside "vendor's" is unmatched within the comment
                        # itself, so the single-quote branch above read it as
                        # OPENING a multi-line quoted span that then never
                        # legitimately closed within the stanza. Everything
                        # after it -- potentially the stanza's only real
                        # pkgName=/pkgPathPattern= assignment, on some LATER
                        # line -- was silently swallowed as inert quoted
                        # data, so the drift gate saw no selector at all and
                        # reported a manifest record consistent when it
                        # was not (fails OPEN, unlike every other documented
                        # caveat here). Reaching this branch means: not
                        # already inside a multi-line single-quoted span
                        # (checked at the very top of this loop, `continue`s
                        # before we ever get here), and not inside an
                        # open double-quoted string at the current $(...)
                        # nesting level (`not dquote_stack[-1]`) -- i.e.
                        # genuinely outside any quote, at this scope, right
                        # now. That is exactly shell's own rule for where a
                        # `#` is a comment marker rather than literal text,
                        # and checking both quote characters here (rather
                        # than special-casing single quotes the way the bug
                        # did) is what keeps `pkgName="foo#bar.pkg"` -- a `#`
                        # legitimately INSIDE a quoted value on the same
                        # line -- read as literal text, not a comment: at
                        # that character dquote_stack[-1] is True, so this
                        # branch does not fire and the quote states already
                        # tracked up to this point are correct. Once a
                        # genuine comment starts, nothing after it can
                        # affect quoting for this physical line -- not even
                        # a `$(...)` close paren -- so the char scan simply
                        # stops; the full (untruncated) `line` is still what
                        # every regex below matches against, and those are
                        # anchored (`fullmatch`) shapes that a trailing
                        # comment already fails to match, so this does not
                        # change how assignment lines themselves are read.
                        break
                    escaped = False
                    prev_char = char
                if started_in_quote:
                    continue
                if branch := _ARCH_BRANCH_RE.fullmatch(line):
                    if line.lstrip().startswith("elif "):
                        if control_stack == ["arch"]:
                            current_arch = branch.group(1)
                            continue
                        if control_stack:
                            control_stack[-1] = "unsupported"
                            current_arch = None
                            continue
                        raise ValueError("unmatched architecture elif")
                    if control_stack:
                        control_stack.append("unsupported")
                        current_arch = None
                        continue
                    control_stack.append("arch")
                    current_arch = branch.group(1)
                    continue
                if re.match(r"^\s*if\b", line):
                    control_stack.append("unsupported")
                    current_arch = None
                    continue
                if re.match(r"^\s*(?:elif\b.*;\s*then|else)\s*$", line):
                    if not control_stack:
                        raise ValueError(
                            f"unmatched shell conditional in label stanza {'|'.join(labels)}: {line}")
                    if control_stack[-1] != "arch" or not (
                            branch := _ARCH_BRANCH_RE.fullmatch(line)):
                        control_stack[-1] = "unsupported"
                        current_arch = None
                    else:
                        current_arch = branch.group(1)
                    continue
                if re.fullmatch(r"\s*fi\s*", line):
                    if not control_stack:
                        raise ValueError("unmatched fi in label stanza")
                    control_stack.pop()
                    current_arch = None
                    continue
                derivation = _VERSION_COMPONENT_RE.fullmatch(line)
                if derivation:
                    if control_stack:
                        raise ValueError(
                            "appBuildVersion derivation inside conditional is unsupported")
                    version_component_derivations.append((
                        derivation.group("separator"),
                        int(derivation.group("component")),
                    ))
                    continue
                app_new_version_match = _APP_NEW_VERSION_RE.fullmatch(line)
                if app_new_version_match:
                    if control_stack:
                        raise ValueError(
                            "appNewVersion derivation inside conditional is unsupported")
                    # Shell re-assignment semantics: if a stanza unconditionally
                    # assigns appNewVersion more than once, the LAST one is what
                    # actually reaches appBuildVersion at runtime -- appending
                    # (not requiring exactly one) and taking the last entry
                    # below mirrors that.
                    app_new_version_fields.append(
                        _appcast_version_field(app_new_version_match.group("rhs")))
                    continue
                pkg_match = _PKG_NAME_RE.fullmatch(line)
                if pkg_match:
                    if control_stack and not (
                            len(control_stack) == 1
                            and control_stack[0] == "arch" and current_arch):
                        raise ValueError(
                            "payload selector inside unrecognised or nested conditional")
                    if current_arch:
                        pkg_assignments_by_arch.setdefault(current_arch, []).append(
                            pkg_match.group(1))
                    else:
                        pkg_assignments.append(pkg_match.group(1))
                    continue
                path_pattern_match = _PKG_PATH_PATTERN_RE.fullmatch(line)
                if path_pattern_match:
                    if control_stack:
                        raise ValueError(
                            "pkgPathPattern inside conditional is unsupported")
                    pkg_path_patterns.append(path_pattern_match.group(1))
                elif re.search(r"\b(?:pkgName|pkgPathPattern)\s*=", line):
                    raise ValueError(
                        f"unrecognised payload selector assignment in {'|'.join(labels)}: {line}")
            if control_stack:
                raise ValueError(
                    f"unterminated shell conditional in label stanza {'|'.join(labels)}")
            shell_label = ShellLabel(
                stanza_labels=tuple(labels),
                shell_types=tuple(sorted(shell_types)),
                pkg_name_assignments=tuple(pkg_assignments),
                pkg_name_assignments_by_arch=tuple(
                    (arch, tuple(values))
                    for arch, values in sorted(pkg_assignments_by_arch.items())
                ),
                pkg_path_pattern_assignments=tuple(pkg_path_patterns),
                version_component_derivations=tuple(version_component_derivations),
                app_new_version_sparkle_field=(
                    app_new_version_fields[-1] if app_new_version_fields else None),
                team_id_assignments=team_id_assignments,
                team_id_boundary_gap_suspected=team_id_boundary_gap_suspected,
            )
        except ValueError as exc:
            # See ShellLabel.parse_error's docstring: this stanza's
            # own body could not be safely parsed. shell_types is still
            # accurate (computed before this loop, unaffected by a
            # failure inside it); every pkgName/pkgPathPattern/version
            # field is left empty rather than guessed, so a caller can
            # never mistake "parsing failed" for "this stanza genuinely
            # assigns nothing". team_id_assignments is NOT similarly reset --
            # it was computed unconditionally, before this try block, from
            # the same pkgInDmg-payload-agnostic scan every stanza gets (see
            # its assignment site above), so a pkgName/pkgPathPattern parse
            # failure elsewhere in this stanza's body has no bearing on
            # whether its expectedTeamID= line(s) were read correctly.
            shell_label = ShellLabel(
                stanza_labels=tuple(labels),
                shell_types=tuple(sorted(shell_types)),
                pkg_name_assignments=(),
                parse_error=str(exc),
                team_id_assignments=team_id_assignments,
                team_id_boundary_gap_suspected=team_id_boundary_gap_suspected,
            )
        for label in labels:
            # zsh case dispatch uses the first matching arm. Preserve that
            # exact runtime meaning if the inherited engine contains a later
            # duplicate alias; PAT-1403 owns broader label-set reconciliation.
            result.setdefault(label, shell_label)

    else:
        raise ValueError("top-level label dispatch has no closing esac")

    if not result:
        if re.search(r'type\s*=\s*"pkgInDmg"', "\n".join(lines[opens[0] + 1:i])):
            raise ValueError("unrecognised case arm hid a pkgInDmg assignment")
        raise ValueError("top-level label dispatch contains no labels")
    label_region = "\n".join(lines[opens[0] + 1:i])
    source_pkgindmg_count = len(re.findall(
        r'type\s*=\s*"pkgInDmg"', label_region))
    unique_stanzas = {shell.stanza_labels: shell for shell in result.values()}
    parsed_pkgindmg_count = sum(
        shell.shell_types.count("pkgInDmg") for shell in unique_stanzas.values())
    if source_pkgindmg_count != parsed_pkgindmg_count or any(
            shell.shell_types.count("pkgInDmg") > 1
            for shell in unique_stanzas.values()):
        raise ValueError(
            "unrecognised or ambiguous case arm hid a pkgInDmg type assignment "
            f"(source={source_pkgindmg_count}, parsed={parsed_pkgindmg_count})")
    if any("pkgInDmg" in shell.shell_types and shell.shell_types != ("pkgInDmg",)
           for shell in unique_stanzas.values()):
        raise ValueError(
            "unrecognised case arm merged a pkgInDmg assignment into another stanza")
    return result


def pkgindmg_contract_errors(records: list[dict], engine_text: str) -> list[str]:
    """Return fail-closed manifest/installed-engine semantic drift errors.

    PAT-1385 round 9 (P2 finding 2b): parse_installomator_labels() raising
    ValueError here is now reserved for genuinely WHOLE-FILE structural
    failures -- no top-level `case $label in`/`esac`, a case arm shape the
    parser cannot locate label boundaries from at all -- where there is no
    single label to blame and continuing to parse the rest of the file
    would be guessing. A single stanza's own malformed body (an unbalanced
    conditional, an unrecognised assignment shape) no longer reaches here
    as an exception at all: parse_installomator_labels() already downgrades
    that to a per-stanza ShellLabel.parse_error, handled below by name for
    each shell stanza and each manifest record it touches, so one label's
    bad edit can never again silently blank out every other label's result
    under one whole-gate "Installomator parser: ..." message.
    """
    try:
        shell_labels = parse_installomator_labels(engine_text)
    except ValueError as exc:
        return [f"Installomator parser: {exc}"]

    errors: list[str] = []
    record_labels = {record.get("label") for record in records}
    seen_stanzas: set[tuple[str, ...]] = set()
    for shell in shell_labels.values():
        if ("pkgInDmg" not in shell.shell_types
                or shell.stanza_labels in seen_stanzas):
            continue
        seen_stanzas.add(shell.stanza_labels)
        if shell.parse_error is not None:
            errors.append(
                f"Installomator stanza {'|'.join(shell.stanza_labels)}: "
                f"{shell.parse_error}")
            continue
        try:
            shell.normalised_pkg_names()
            shell.normalised_pkg_path_patterns()
            shell.normalised_pkg_name_patterns_by_arch()
        except ValueError as exc:
            errors.append(
                f"Installomator stanza {'|'.join(shell.stanza_labels)}: {exc}")
            continue
        represented = record_labels.intersection(shell.stanza_labels)
        has_explicit_selector = bool(
            shell.pkg_name_assignments
            or shell.pkg_name_assignments_by_arch
            or shell.pkg_path_pattern_assignments)
        # Root-default is one universal, payload-free contract. Explicit
        # selectors carry label-specific executable data and must have a
        # matching manifest record; otherwise verifier coverage is absent.
        if has_explicit_selector and not represented:
            shell_only = set(shell.stanza_labels).intersection(
                SHELL_ONLY_EXPLICIT_PKGIN_DMG)
            if not shell_only:
                errors.append(
                    f"Installomator pkgInDmg stanza {'|'.join(shell.stanza_labels)} "
                    "has an explicit payload selector but no manifest record")
        if represented and set(shell.stanza_labels).intersection(
                SHELL_ONLY_EXPLICIT_PKGIN_DMG):
            errors.append(
                f"Installomator stanza {'|'.join(shell.stanza_labels)} is explicitly "
                "shell-only and must not acquire a manifest/allowlist record")
    for record in records:
        label = record["label"]
        manifest_is_pkgindmg = record["type"] == "pkgindmg"
        shell = shell_labels.get(label)
        shell_is_pkgindmg = bool(shell and "pkgInDmg" in shell.shell_types)

        # PAT-1424: an absent pkg_in_dmg block is an unreviewed claim, not a
        # blank waiting to be filled -- see is_reviewed_pkgindmg_locator()'s
        # docstring (and UNCONFIRMED_PKGINDMG_ROOT_DEFAULT's / KNOWN_
        # INCORRECT_PKGINDMG_DEFAULT's, for the two distinct reviewed-but-
        # implicit states). Checked independently of the shell-
        # reconciliation logic below so a label with a missing/broken shell
        # stanza still gets flagged for review rather than silently
        # skipping this gate.
        if manifest_is_pkgindmg and not is_reviewed_pkgindmg_locator(record):
            errors.append(
                f"{label}: pkgindmg record relies on the implicit "
                "root-unique-pkg default with no well-formed pkg_in_dmg "
                "block and no documented entry in "
                "UNCONFIRMED_PKGINDMG_ROOT_DEFAULT or "
                "KNOWN_INCORRECT_PKGINDMG_DEFAULT (PAT-1424) -- confirm the "
                "real DMG payload shape and add an explicit pkg_in_dmg "
                "block, or record why it could not be confirmed (or, if "
                "confirmed FALSE, record the tracking ticket for the fix)")

        if not manifest_is_pkgindmg and not shell_is_pkgindmg:
            continue
        if shell is None:
            # No such records exist today. Future verifier-only records must
            # be explicitly inventoried so their historical discovery rule
            # cannot silently change to the stricter root default.
            if label not in VERIFIER_ONLY_PKGIN_DMG:
                errors.append(
                    f"{label}: pkgindmg record has no Installomator label stanza "
                    "and is not explicitly enumerated as verifier-only")
            elif is_endpoint_allowlisted(record):
                errors.append(
                    f"{label}: allowlisted pkgindmg record has no Installomator label stanza")
            continue
        if not manifest_is_pkgindmg or not shell_is_pkgindmg:
            errors.append(
                f"{label}: pkgindmg type drift (manifest={record['type']!r}, "
                f"Installomator={list(shell.shell_types)!r})")
            continue
        if shell.shell_types != ("pkgInDmg",):
            errors.append(
                f"{label}: pkgindmg shell stanza assigns multiple runtime types: "
                f"{list(shell.shell_types)!r}")
            continue
        if shell.parse_error is not None:
            # PAT-1385 round 9 (P2 finding 2b): report the real cause by
            # name instead of falling through to normalised_pkg_names()
            # below, which would see this stanza's placeholder empty
            # pkg_name_assignments and misreport it as a genuine "shell
            # sets nothing" drift against the manifest's locator -- hiding
            # the actual parse failure behind a misleading message.
            errors.append(
                f"{label}: Installomator stanza failed to parse: {shell.parse_error}")
            continue

        locator = record.get("pkg_in_dmg", {"mode": "root-unique-pkg"})
        if not isinstance(locator, dict) or not isinstance(locator.get("mode"), str):
            errors.append(f"{label}: invalid pkg_in_dmg locator shape")
            continue
        mode = locator["mode"]
        expected_patterns = locator.get("patterns", [])
        try:
            actual_pkg_names = shell.normalised_pkg_names()
            actual_path_patterns = shell.normalised_pkg_path_patterns()
            actual = (*actual_pkg_names, *actual_path_patterns)
            actual_by_arch = shell.normalised_pkg_name_patterns_by_arch()
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
            continue
        if mode == "root-unique-pkg":
            if actual:
                errors.append(
                    f"{label}: manifest says root-unique-pkg but Installomator "
                    f"sets pkgName={list(actual_pkg_names)!r} or "
                    f"pkgPathPattern={list(actual_path_patterns)!r}")
            if actual_by_arch:
                errors.append(
                    f"{label}: root locator cannot have architecture-specific pkgName assignments")
        elif mode == "relative-path-glob":
            if actual_by_arch:
                errors.append(
                    f"{label}: non-architecture locator has architecture-specific pkgName assignments")
            if not isinstance(expected_patterns, list) or len(expected_patterns) != 1:
                errors.append(
                    f"{label}: relative-path-glob must declare exactly one pattern, "
                    f"got {expected_patterns!r}")
            if len(actual) != 1:
                errors.append(
                    f"{label}: runtime must assign exactly one active selector, got "
                    f"pkgName={list(actual_pkg_names)!r}, "
                    f"pkgPathPattern={list(actual_path_patterns)!r}")
            elif "{version_component}" in actual[0]:
                # PAT-1385 P2 fix (round 8): a version-bearing shell variable
                # interpolation (see _normalise_pkg_name_assignment()) MUST
                # be paired with an exact version-component/-digits locator,
                # never a loose glob -- fail unconditionally here regardless
                # of what the manifest's glob pattern literally says, since
                # a manifest author could otherwise "match" the placeholder
                # text itself and slip past the plain string-equality check
                # below.
                errors.append(
                    f"{label}: Installomator interpolates a version-bearing "
                    f"variable into pkgName={list(actual_pkg_names)!r}/"
                    f"pkgPathPattern={list(actual_path_patterns)!r}, but "
                    f"manifest declares a plain relative-path-glob -- this "
                    f"would let the verifier accept ANY build matching that "
                    f"glob at install time, not only the one exact, "
                    f"version-pinned build the shell actually installs; "
                    f"declare relative-path-version-component or "
                    f"relative-path-version-digits instead")
            elif (isinstance(expected_patterns, list)
                  and len(expected_patterns) == 1
                  and expected_patterns[0] != actual[0]):
                errors.append(
                    f"{label}: pkg_in_dmg pattern drift (manifest={expected_patterns[0]!r}, "
                    f"Installomator pkgName={list(actual_pkg_names)!r}, "
                    f"pkgPathPattern={list(actual_path_patterns)!r})")
        elif mode == "relative-path-glob-by-arch":
            if actual:
                errors.append(
                    f"{label}: architecture-specific locator has unconditional "
                    f"Installomator pkgName={list(actual)!r}")
                continue
            manifest_by_arch = locator.get("patterns_by_arch")
            if not isinstance(manifest_by_arch, dict):
                errors.append(f"{label}: invalid patterns_by_arch shape")
                continue
            invalid_runtime_arches = {
                arch: values for arch, values in actual_by_arch.items()
                if len(values) != 1
            }
            if set(actual_by_arch) != {"arm64", "i386"} or invalid_runtime_arches:
                errors.append(
                    f"{label}: architecture runtime must assign exactly one pkgName "
                    f"for each arm64/i386 branch, got {actual_by_arch!r}")
                continue
            selected_by_arch = {
                arch: values[0] for arch, values in actual_by_arch.items()
            }
            # See relative-path-glob above for why this must fail regardless
            # of what the manifest's per-arch patterns literally say.
            version_bearing_arches = {
                arch: value for arch, value in selected_by_arch.items()
                if "{version_component}" in value
            }
            if version_bearing_arches:
                errors.append(
                    f"{label}: Installomator interpolates a version-bearing "
                    f"variable into pkgName for arch(es) "
                    f"{sorted(version_bearing_arches)!r}, but manifest "
                    f"declares relative-path-glob-by-arch -- an exact-match "
                    f"locator is required for a version-pinned build, not a "
                    f"glob")
            elif manifest_by_arch != selected_by_arch:
                errors.append(
                    f"{label}: architecture pkg_in_dmg patterns drift "
                    f"(manifest={manifest_by_arch!r}, "
                    f"Installomator={selected_by_arch!r})")
        elif mode == "relative-path-version-component":
            # PAT-1385 P2 fix (round 8): accept the version-component value
            # from EITHER an unconditional pkgPathPattern (jre8's shape,
            # nested inside a wrapper .app) OR an unconditional pkgName
            # (a root-level version-pinned filename via a quoted
            # `${appNewVersion}`-style interpolation -- see
            # _normalise_pkg_name_assignment()) -- exactly one of the two,
            # never both/neither/by-arch.
            if actual_by_arch or len(actual) != 1:
                errors.append(
                    f"{label}: version-component locator requires exactly one "
                    f"unconditional pkgName or pkgPathPattern, got "
                    f"pkgName={actual_pkg_names!r}, "
                    f"pkgPathPattern={actual_path_patterns!r}, arch={actual_by_arch!r}")
                continue
            expected_template = locator.get("template")
            expected_derivation = (
                locator.get("separator"), locator.get("component_index"))
            if (expected_template != actual[0]
                    or shell.version_component_derivations
                    != (expected_derivation,)):
                errors.append(
                    f"{label}: version-component locator drift "
                    f"(manifest={locator!r}, shell={actual[0]!r}, "
                    f"derivation={shell.version_component_derivations!r})")
                continue
            # PAT-1385 P2 fix (round 8, finding "appNewVersion itself never
            # checked"): confirm the manifest's declared version_source
            # (which XML node the verifier reads for this path component --
            # see contracts/label.schema.json and _resolve_sparkle_appcast_
            # entry()'s docstring in verifier/verify.py, retired 2026-09-30 by
            # PAT-2304) actually matches
            # what the shell's own appNewVersion= assignment reads. Without
            # this, a shell stanza that changes its appNewVersion xpath/
            # field (a different appcast node entirely) while keeping the
            # same `cut` separator/field-index/template shape would still
            # pass every check above -- exactly the P1 jre8 bug's shape,
            # generalised: the two sides can silently diverge on WHICH
            # bytes they derive a version from, even while agreeing on HOW
            # they slice whatever they derived.
            manifest_version_source = locator.get("version_source")
            actual_field = shell.app_new_version_sparkle_field
            if manifest_version_source == "sparkle-enclosure-version":
                if actual_field != ("enclosure-attribute", "version"):
                    errors.append(
                        f"{label}: pkg_in_dmg.version_source="
                        f"'sparkle-enclosure-version' but Installomator's "
                        f"appNewVersion reads {actual_field!r}, not the "
                        f"appcast enclosure's raw sparkle:version attribute "
                        f"-- the verifier's version-component pkgName "
                        f"template would render from a different XML node "
                        f"than the shell actually installs")
            elif manifest_version_source == "resolved-version":
                # None (no recognisable Sparkle appNewVersion source at
                # all -- e.g. an HTML-page scrape) is fine: "resolved-
                # version" is the general default and applies to
                # non-Sparkle-appcast labels too, so there is nothing to
                # cross-check against. Only a label that DOES read a
                # sparkle: field but reads the wrong one (the raw build
                # attribute rather than shortVersionString) is drift.
                if actual_field is not None and actual_field[1] != "shortVersionString":
                    errors.append(
                        f"{label}: pkg_in_dmg.version_source='resolved-version' "
                        f"but Installomator's appNewVersion reads "
                        f"{actual_field!r} -- a raw sparkle:version build "
                        f"number, not sparkle:shortVersionString; declare "
                        f"version_source='sparkle-enclosure-version' instead "
                        f"if the path component is meant to come from that "
                        f"raw attribute")
            else:
                errors.append(
                    f"{label}: pkg_in_dmg.version_source {manifest_version_source!r} "
                    f"is not a recognised value ('resolved-version' or "
                    f"'sparkle-enclosure-version')")
        elif mode == "relative-path-version-digits":
            if actual_path_patterns or actual_by_arch or len(actual_pkg_names) != 1:
                errors.append(
                    f"{label}: version-digits locator requires exactly one "
                    f"unconditional pkgName, got pkgName={actual_pkg_names!r}, "
                    f"pkgPathPattern={actual_path_patterns!r}, arch={actual_by_arch!r}")
                continue
            if locator.get("template") != actual_pkg_names[0]:
                errors.append(
                    f"{label}: version-digits locator drift "
                    f"(manifest={locator!r}, shell={actual_pkg_names[0]!r})")
        elif mode not in PKGINDMG_LOCATOR_MODES:
            errors.append(f"{label}: unsupported pkg_in_dmg mode {mode!r}")
    return errors


# PAT-1429 (non-author-review follow-up, round 2): _TEAM_ID_ASSIGN_RE above
# captures the ENTIRE rest of the physical line after `expectedTeamID=`, so a
# trailing shell comment (e.g. `expectedTeamID="HLTN5GLG99" # PAT-1282`) was,
# before this fix, folded straight into the "value" and compared byte-for-
# byte against the manifest -- a real, reachable false-positive drift report
# on a perfectly correct, agreeing assignment. No stanza in the current
# corpus does this (confirmed: zero `expectedTeamID=.*#` matches anywhere in
# engine/Installomator.sh), so this was never a live false positive -- but it
# is exactly the kind of gate a maintainer disables the first time it cries
# wolf, so it is fixed properly rather than left as a known caveat.
#
# Whether `#` can legitimately appear INSIDE a value matters here, not just
# whether a trailing comment can exist. Verified empirically against real
# zsh (not assumed): `#` starts a comment only when it is preceded by
# whitespace (or is the very first character of a word) -- `foo=bar#baz`
# assigns the LITERAL "bar#baz" (no comment stripped), `foo=bar #baz`
# assigns "bar" with `#baz` as a real comment, and `foo="bar"#baz` (glued
# directly onto a closing quote, no space) again assigns the literal
# "bar#baz", not "bar" with a stripped comment. Team IDs (10-char alnum) and
# the known non-team-id sentinel strings this file's own real-corpus survey
# found (`"Software Update"`, `"Group"`, `"Media"`, `"Frydendal"`) never
# contain `#` themselves, so there is no legitimate VALUE this needs to
# tolerate a bare `#` inside of -- only a genuinely SEPARATE trailing
# comment, which real zsh only ever recognises after whitespace.
# _TEAM_ID_QUOTED_LITERAL_RE / _TEAM_ID_BARE_LITERAL_RE below encode exactly
# that rule (`\s+#` required, never a bare `#`) rather than naively
# splitting on the first `#` anywhere in the line, which would have wrongly
# treated `expectedTeamID="bar#baz"` (a literal value containing `#`, were
# one ever added) as `"bar` with a stripped `#baz"` comment -- a real value
# corrupted into cutting off mid-string. Anything that doesn't cleanly match
# one of the two real shapes (quoted-literal-plus-optional-whitespace-
# comment, bare-word-plus-optional-whitespace-comment) is not a shape the
# current corpus uses, so it fails closed (None, "cannot confirm") rather
# than being guessed at.
_TEAM_ID_QUOTED_LITERAL_RE = re.compile(r'^"([^"$`]*)"(?:\s+#.*)?$')
_TEAM_ID_BARE_LITERAL_RE = re.compile(r'^(\S+)(?:\s+#.*)?$')


def _team_id_literal(rhs: str) -> str | None:
    """Reduce a raw ``expectedTeamID=`` right-hand side to the literal value
    it assigns, or None if it is not a plain, static literal.

    Handles both of the two shapes seen in the real corpus: a double-quoted
    value (``expectedTeamID="HLTN5GLG99"``, by far the common case) and a
    bare unquoted word (``expectedTeamID=TXAEAV5RN4`` -- valid, if unusual,
    zsh; seen on epsonprintlayout), each optionally followed by a real
    trailing shell comment (whitespace then ``#...`` -- see the module-level
    comment above _TEAM_ID_QUOTED_LITERAL_RE for why that, and not a bare
    ``#`` anywhere in the line, is the correct rule). An empty value
    (``expectedTeamID=""``), one that still contains shell expansion
    (``$``/backtick -- meaning the real runtime value cannot be determined
    by reading the source text alone), or one that does not cleanly match
    either recognised shape returns None: callers MUST treat None as
    "cannot confirm", never as a value that happens to equal or differ from
    the manifest's.
    """
    value = rhs.strip()
    if not value:
        return None
    if value[0] == '"':
        match = _TEAM_ID_QUOTED_LITERAL_RE.fullmatch(value)
        if not match:
            return None
        literal = match.group(1)
    else:
        match = _TEAM_ID_BARE_LITERAL_RE.fullmatch(value)
        if not match:
            return None
        literal = match.group(1)
    if not literal or "$" in literal or "`" in literal:
        return None
    return literal


def _effective_team_id(shell: ShellLabel) -> tuple[str | None, str | None]:
    """Return (value, error) for a stanza's effective ``expectedTeamID``.

    error is None only when exactly one team_id_assignments entry was found
    and it reduces to a non-empty static literal via _team_id_literal();
    value is then that literal. In every other case value is None and error
    names why -- zero assignments (PAT-912/837/960-shaped: expectedTeamID
    simply absent, which is not the same as "no opinion" -- something later
    in Installomator.sh treats absence as "skip verification", see the
    `reason=missing_expectedTeamID` printlog near the real spctl check), more
    than one assignment (genuinely ambiguous -- see the two DISTINCT causes
    below), or a non-literal/empty value.

    PAT-1429 (non-author-review follow-up, round 2): a multiple-assignment
    error used to describe both possible causes in one message, leaving an
    investigator to guess which applied and potentially audit the wrong
    stanza. The two are told apart using
    ShellLabel.team_id_boundary_gap_suspected (see
    _body_suggests_absorbed_arm_boundary()): a stanza whose body contains a
    line that LOOKS like a missed case-arm boundary (an indented arm, or one
    glued onto the preceding `;;` on the same physical line) most likely
    absorbed a NEIGHBOUR label's stanza, and the fix belongs to the
    arm-boundary parser, not to this stanza's own assignment. Absent that
    evidence, it is reported as what it likely is: a real double assignment
    inside this one stanza.

    PAT-1432 fixed the arm-boundary parser to recognise both of those
    spellings (displaylinkmanager absorbing `    displaynote)`,
    editshare-connect absorbing `;;editshare-flowstory)`, and superwhisper
    absorbing `    supportapp)` were the real corpus's three examples), so
    the "possible arm-boundary parsing gap" branch below can no longer be
    reached by a real neighbour-absorption: a post-fix real-corpus sweep
    found zero shell stanzas with more than one expectedTeamID assignment
    at all. It remains reachable only via a narrow, synthetic shape
    _body_suggests_absorbed_arm_boundary() is NOT nested-case-aware enough
    to avoid (see that function's docstring) and is left in place
    deliberately, as a fail-closed guard, not because it is currently load-
    bearing against the real engine.
    """
    assignments = shell.team_id_assignments
    if len(assignments) == 0:
        return None, "Installomator stanza has no expectedTeamID assignment"
    if len(assignments) > 1:
        if shell.team_id_boundary_gap_suspected:
            return None, (
                "ambiguous: possible arm-boundary parsing gap -- "
                "Installomator stanza assigns expectedTeamID more than once "
                f"({list(assignments)!r}) and its body contains a line that "
                "looks like a case-arm boundary the shared parser did not "
                "recognise (an indented arm, or one glued onto the "
                "preceding ';;' on the same physical line) -- most likely a "
                "NEIGHBOURING label's stanza was absorbed into this one; "
                "investigate the arm-boundary parser gap, not this "
                "stanza's own expectedTeamID value")
        return None, (
            "Installomator stanza assigns expectedTeamID more than once "
            f"({list(assignments)!r}) -- ambiguous, cannot confirm a single "
            "effective value")
    value = _team_id_literal(assignments[0])
    if value is None:
        return None, (
            f"expectedTeamID={assignments[0]!r} is empty or not a static "
            "literal (contains shell expansion) -- cannot confirm its "
            "runtime value")
    return value, None


def team_id_contract_errors(records: list[dict], engine_text: str) -> list[str]:
    """Return fail-closed manifest/installed-engine Team ID drift errors.

    PAT-1429: engine/labels/veracrypt.json and engine/labels/
    veracrypt-fuse-t.json's `expected_team_id` were each independently
    reviewed and corrected under their own ticket -- PAT-1282 (veracrypt:
    corrected to HLTN5GLG99, Mounir Joseph IDRASSI, confirmed via two live
    verifier runs against the actual downloaded artifact plus a
    cross-check against the sibling veracrypt-fuse-t artifact) and PAT-1283
    (veracrypt-fuse-t: same correction, hand-verified via `pkgutil
    --check-signature` against the live, Apple-notarized installer) -- while
    engine/Installomator.sh's own `expectedTeamID=` for both labels had
    drifted to the stale pre-correction value (Z933746L2S), and nothing
    compared the two. A third, unrelated ticket (PAT-1272, logseq: corrected
    to K378MFWK59 after a vendor certificate rotation, corroborated by an
    upstream Installomator issue, an upstream commit, and a byte-for-byte
    Homebrew cask SHA256 match) turned out to have drifted the exact same
    way when this check's first real run was pointed at the full manifest.
    Three separate tickets, three separate reviewers' worth of legitimacy
    work, each landing the fix on only the manifest half and missing the
    shell half: that is a systemic pattern in how a two-sided contract with
    no automated cross-check degrades, not three coincidences -- and it is
    the single best argument for why this function exists, and against ever
    deleting it because "the checks it catches look like one-off typos."
    None of the three fixes below bless an OBSERVED identity as correct;
    each syncs the shell to a value that was independently reviewed and
    signed off on before this check ever ran. This mirrors
    pkgindmg_contract_errors() above (same file, same shape: parse the one
    real shell dispatch as data, never execute it, compare it against the
    manifest's own claim, fail closed on drift) but for `expected_team_id`
    vs `expectedTeamID=`, across every label and every type -- not just
    pkgindmg -- since Team ID verification is universal, not
    pkgInDmg-specific.

    Edge cases, decided explicitly (PAT-1429 -- "absence must not silently
    read as agreement", the PAT-912/837/960 failure shape):

    - Label in manifest AND shell, both resolve to a single static literal,
      values differ: ALWAYS an error, regardless of allowlisted status. This
      is a CONFIRMED disagreement -- the exact veracrypt/veracrypt-fuse-t
      shape this ticket exists to catch -- not a case of missing data, so it
      is never suppressed.
    - Label in manifest, shell stanza absent, unparseable
      (ShellLabel.parse_error), or its expectedTeamID cannot be reduced to
      a single static literal (_effective_team_id returns an error): this is
      "cannot confirm", not "confirmed to agree" -- but it is only surfaced
      as a gate FAILURE when the record is endpoint-allowlisted
      (is_endpoint_allowlisted). A real-manifest sweep for this ticket found
      13 labels in this state today (e.g. antcon, blackhole64,
      googlegemini's manifest label "gemini") -- each genuinely has no
      shell stanza at all in engine/Installomator.sh, and each carries its
      own `patched.notes: "Auto-converted from Installomator fragment...
      requires human review before setting allowlisted=true"`. (PAT-1429's
      original survey found 16: the other 3 -- displaynote, egnyte,
      supportapp -- DID have a real, working runtime stanza that the
      shared arm-boundary walker's line-anchored regexes simply failed to
      recognise as a boundary, because engine/Installomator.sh spells them
      with a leading indent (`    displaynote)`, `    supportapp)`) or
      glued onto the preceding `;;` on one physical line (`;;egnyte)`) --
      both valid zsh, neither matched by the walker at the time. PAT-1432
      taught the walker both spellings, so those 3 now parse into real
      stanzas and are compared normally like any other label; they are no
      longer in this 13.) None of the 13 is allowlisted, so none reaches a
      real endpoint today; gating this check on allowlisted status mirrors
      pkgindmg_contract_errors' own precedent for a missing shell stanza in
      the exact same situation (VERIFIER_ONLY_PKGIN_DMG's
      is_endpoint_allowlisted branch) and keeps this check from going red,
      out of the box, over 13 pre-existing unrelated stub records neither
      PAT-1429 nor PAT-1432's scope extends to fixing. Every one of the 13
      is still real, named signal -- not silence -- surfaced in this
      function's PAT-1429 rollout report rather than as a CI failure; if any
      of them is ever allowlisted, this check starts failing on it
      immediately, by construction, with no extra wiring required.
    - Label present in the shell but absent from the manifest: not compared
      at all. The manifest is deliberately a subset of Installomator's full
      label set (per AGENTS.md: "a resolver pool drawn on when an app is
      added to the [Dashboard Software Catalogue], and nothing else") --
      most of Installomator's 1000+ built-in labels have no manifest record
      by design, not by omission, so this is not a gap to report.
    """
    try:
        shell_labels = parse_installomator_labels(engine_text)
    except ValueError as exc:
        return [f"Installomator parser: {exc}"]

    errors: list[str] = []
    for record in records:
        label = record.get("label")
        manifest_team_id = record.get("expected_team_id")
        shell = shell_labels.get(label)

        if shell is None:
            if is_endpoint_allowlisted(record):
                errors.append(
                    f"{label}: allowlisted record's expected_team_id "
                    f"{manifest_team_id!r} has no Installomator label "
                    "stanza to enforce it")
            continue

        if shell.parse_error is not None:
            if is_endpoint_allowlisted(record):
                errors.append(
                    f"{label}: Installomator stanza failed to parse, "
                    f"cannot confirm expectedTeamID: {shell.parse_error}")
            continue

        shell_team_id, confirm_error = _effective_team_id(shell)
        if confirm_error is not None:
            if is_endpoint_allowlisted(record):
                errors.append(f"{label}: {confirm_error}")
            continue

        if shell_team_id != manifest_team_id:
            errors.append(
                f"{label}: Team ID drift (manifest expected_team_id="
                f"{manifest_team_id!r}, Installomator expectedTeamID="
                f"{shell_team_id!r})")
    return errors
