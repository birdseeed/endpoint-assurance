#!/usr/bin/env python3
"""
validate-install-types.py — CI gate for PAT-1294: keeps every shell
`type="..."` value in engine/Installomator.sh inside the set the install
dispatch can actually handle.

Background: engine/labels/*.json (validated by validate-labels.py) uses a
JSON-schema type vocabulary (contracts/label.schema.json: dmg, pkg, zip,
tbz, appindmg, appinzip, pkgindmg, pkginzip, appindmginzip) that is *not*
the same vocabulary as the shell engine's `case $type in` install dispatch
(dmg, pkg, zip, tbz, bz2, pkgInDmg, pkgInZip, appInDmgInZip). A label
stanza can be perfectly schema-valid and still be un-installable in the
shell engine — exactly what shipped as inetclearreportsdesigner's
`type="appindmg"` (PAT-1294): it matched no installFrom* arm and fell
through to `cleanupAndExit 99 "Cannot handle type $type"` on every real
install attempt. PAT-1288 (espanso) was the same class of mistake.

This script DERIVES the accepted type set by parsing the install dispatch
`case $type in` block out of engine/Installomator.sh, rather than
hardcoding a list that can silently drift from the dispatch it's meant to
guard. If it cannot locate that block unambiguously, it FAILS LOUDLY —
never falls back to "no types to check" or an empty allowlist. A guard
that passes when it cannot see the thing it guards is the exact failure
shape already on record for this codebase (PAT-912, PAT-837, PAT-960,
PAT-1041): something that fails safe looks identical to something healthy
until it's needed.

Usage:
    python3 ci/validate-install-types.py [--repo-root DIR]
"""

import argparse
import re
import sys
from pathlib import Path

LABEL_DISPATCH_OPEN_RE = re.compile(r'^(\s*)case \$label in\s*$')
TYPE_DISPATCH_OPEN_RE = re.compile(r'^(\s*)case \$type in\s*$')

# A case arm label at zero indentation, e.g. `inetclearreportsdesigner)` or
# `foo|bar)` for a multi-label arm. Zero indentation is what distinguishes a
# label arm from a `case $type in` / `case $(arch) in` arm nested inside a
# label body or the install-time if-blocks — every such nested arm in this
# file is indented.
LABEL_ARM_RE = re.compile(r'^([A-Za-z0-9_][A-Za-z0-9_|.-]*)\)\s*$')

# An accepted-type arm inside the install dispatch, e.g. `dmg)` or
# `tbz|bz2)`. The catch-all `*)` arm is deliberately excluded — `*` is not
# in the character class, so it never matches this pattern.
TYPE_ARM_RE = re.compile(r'^\s*([A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)*)\)\s*$')

TYPE_ASSIGN_RE = re.compile(r'^\s*type="([A-Za-z0-9_]+)"\s*$')

# Marker unique to the authoritative install dispatch. engine/Installomator.sh
# has two other `case $type in` blocks (deriving archiveName and targetDir)
# that switch on the same variable but never install anything — only the
# real dispatch calls the installFrom*/install* helpers.
INSTALL_MARKER = "installFromDMG"


def find_blocks(lines, open_re):
    """Find every block opened by a line matching open_re and closed by the
    next `esac` line at the SAME indentation as the opening line (this file
    nests case statements inside label bodies, so a same-or-deeper-indented
    `esac` belonging to a nested block must not be mistaken for the close of
    the outer one). Returns a list of (start, end) 0-based line indices,
    where `end` is the index of the closing `esac` line."""
    blocks = []
    i = 0
    while i < len(lines):
        m = open_re.match(lines[i].rstrip("\n"))
        if m:
            indent = m.group(1)
            close_re = re.compile(r'^' + re.escape(indent) + r'esac\s*$')
            j = i + 1
            while j < len(lines) and not close_re.match(lines[j].rstrip("\n")):
                j += 1
            if j >= len(lines):
                # Unterminated block — let the caller's "not found" handling
                # fail loudly rather than silently skipping it.
                i += 1
                continue
            blocks.append((i, j))
            i = j + 1
        else:
            i += 1
    return blocks


def find_install_dispatch(lines):
    """Locate the authoritative `case $type in ... esac` block: the one
    whose body calls installFromDMG. Returns (start, end, accepted_types),
    or None if the block can't be found unambiguously."""
    candidates = find_blocks(lines, TYPE_DISPATCH_OPEN_RE)
    matches = [(s, e) for s, e in candidates if INSTALL_MARKER in "".join(lines[s:e])]
    if len(matches) != 1:
        return None
    start, end = matches[0]
    accepted = set()
    for k in range(start + 1, end):
        m = TYPE_ARM_RE.match(lines[k].rstrip("\n"))
        if m:
            accepted.update(m.group(1).split("|"))
    if not accepted:
        return None
    return start, end, accepted


def find_label_region(lines):
    """Locate the single `case $label in ... esac` block holding every
    label stanza. Returns (start, end), or None if not found unambiguously."""
    blocks = find_blocks(lines, LABEL_DISPATCH_OPEN_RE)
    if len(blocks) != 1:
        return None
    return blocks[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="Repo root (default: cwd)")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    engine_path = root / "engine" / "Installomator.sh"

    if not engine_path.is_file():
        print(f"FATAL: engine not found at {engine_path}", file=sys.stderr)
        return 2

    lines = engine_path.read_text().splitlines(keepends=True)

    dispatch = find_install_dispatch(lines)
    if dispatch is None:
        print(
            "FATAL: could not locate exactly one install dispatch block "
            "(`case $type in ... esac` containing an installFromDMG call) "
            f"in {engine_path}. Refusing to pass with an empty or unknown "
            "accepted-type set — fix this parser (or the engine's dispatch "
            "structure) rather than let this check silently stop guarding "
            "anything.",
            file=sys.stderr,
        )
        return 2
    dispatch_start, dispatch_end, accepted_types = dispatch

    label_region = find_label_region(lines)
    if label_region is None:
        print(
            "FATAL: could not locate exactly one `case $label in ... esac` "
            f"block in {engine_path}. Refusing to pass without checking any "
            "label stanzas.",
            file=sys.stderr,
        )
        return 2
    label_start, label_end = label_region

    current_label = None
    errors = []
    checked = 0
    for i in range(label_start + 1, label_end):
        line = lines[i].rstrip("\n")
        arm = LABEL_ARM_RE.match(line)
        if arm:
            current_label = arm.group(1)
            continue
        m = TYPE_ASSIGN_RE.match(line)
        if m:
            checked += 1
            t = m.group(1)
            if t not in accepted_types:
                errors.append((current_label or "(unknown label)", i + 1, t))

    print(f"Install dispatch located at {engine_path}:{dispatch_start + 1}-{dispatch_end + 1}")
    print(f"Accepted shell types: {', '.join(sorted(accepted_types))}")
    print(f"Checked {checked} type=\"...\" assignment(s) in the label dispatch "
          f"({engine_path}:{label_start + 1}-{label_end + 1})")

    if errors:
        print(f"\nFAILED — {len(errors)} label stanza(s) set a shell type the "
              f"install dispatch cannot handle (falls through to "
              f"cleanupAndExit 99 \"Cannot handle type $type\" on every real "
              f"install):\n")
        for label, lineno, t in errors:
            print(f"  ✗ {label} ({engine_path}:{lineno}): type=\"{t}\"")
        return 1

    print("\nAll type=\"...\" assignments are handled by the install dispatch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
