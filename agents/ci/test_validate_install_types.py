#!/usr/bin/env python3
"""
test_validate_install_types.py — PAT-1294 unit + fixture tests for
ci/validate-install-types.py.

Covers the class of bug that shipped as inetclearreportsdesigner's
`type="appindmg"`: a shell `type="..."` value that is not one of the arms
the install dispatch (`case $type in ... esac`) can actually handle, so a
real install falls through to `cleanupAndExit 99 "Cannot handle type
$type"`. Tests build a small synthetic engine file that mirrors the real
structure of engine/Installomator.sh (a `case $label in` block, the two
decoy `case $type in` blocks that derive archiveName/targetDir, and the
authoritative install dispatch) rather than depending on the real
1,100+-label file, so they stay fast and pinned to the exact shape being
guarded.

Stdlib-only (unittest), no network.

Run:
    cd updater && python3 -m unittest ci.test_validate_install_types -v
or, since ci/ is not a package:
    cd updater/ci && python3 test_validate_install_types.py
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# validate-install-types.py has a hyphen in its name, so it can't be
# `import`ed normally — load it by file path instead (same trick as
# test_validate_labels.py uses for validate-labels.py).
_here = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("validate_install_types", _here / "validate-install-types.py")
vit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vit)

# The two decoy `case $type in` blocks from the real engine (archiveName and
# targetDir derivation) — present in every fixture so the "find the real
# dispatch, not a decoy" logic is exercised, not just the happy path of only
# one `case $type in` existing at all.
_DECOY_BLOCKS = '''
if [ -z "$archiveName" ]; then
    case $type in
        dmg|pkg|zip|tbz|bz2)
            archiveName="${name}.$type"
            ;;
        pkgInDmg)
            archiveName="${name}.dmg"
            ;;
        *InZip)
            archiveName="${name}.zip"
            ;;
        updateronly)
            ;;
        *)
            printlog "Cannot handle type $type"
            cleanupAndExit 99
            ;;
    esac
fi

if [ -z "$targetDir" ]; then
    case $type in
        dmg|zip|tbz|bz2|app*)
            targetDir="/Applications"
            ;;
        pkg*)
            targetDir="/"
            ;;
        updateronly)
            ;;
        *)
            cleanupAndExit 99 "Cannot handle type $type" ERROR
            ;;
    esac
fi
'''

# The real, authoritative install dispatch (verbatim shape from
# engine/Installomator.sh line ~12941) — the block the guard must find and
# derive its accepted-type set from.
_INSTALL_DISPATCH = '''
case $type in
    dmg)
        installFromDMG
        ;;
    pkg)
        installFromPKG
        ;;
    zip)
        installFromZIP
        ;;
    tbz|bz2)
        installFromTBZ
        ;;
    pkgInDmg)
        installPkgInDmg
        ;;
    pkgInZip)
        installPkgInZip
        ;;
    appInDmgInZip)
        installAppInDmgInZip
        ;;
    *)
        cleanupAndExit 99 "Cannot handle type $type" ERROR
        ;;
esac
'''


def _make_engine(tmp_path, label_arms, include_decoys=True, include_dispatch=True):
    """Write a synthetic engine/Installomator.sh under tmp_path and return
    its repo root."""
    root = Path(tmp_path)
    engine_dir = root / "engine"
    engine_dir.mkdir(parents=True)

    parts = [
        "#!/bin/zsh --no-rcs\n",
        "# header filler\n",
        "case $label in\n",
        label_arms,
        "esac\n",
    ]
    if include_decoys:
        parts.append(_DECOY_BLOCKS)
    if include_dispatch:
        parts.append(_INSTALL_DISPATCH)

    (engine_dir / "Installomator.sh").write_text("".join(parts))
    return root


def _run_main(repo_root):
    argv = ["validate-install-types.py", "--repo-root", str(repo_root)]
    with mock.patch.object(sys, "argv", argv):
        return vit.main()


class CleanTreeTests(unittest.TestCase):
    def test_clean_tree_passes(self):
        """Every label uses a type the dispatch handles — must exit 0."""
        label_arms = (
            'testapp)\n'
            '    name="Test App"\n'
            '    type="dmg"\n'
            '    ;;\n'
            'testpkg)\n'
            '    name="Test Pkg"\n'
            '    type="pkgInDmg"\n'
            '    ;;\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_engine(tmp, label_arms)
            rc = _run_main(root)
        self.assertEqual(rc, 0)

    def test_all_eight_accepted_types_pass(self):
        """One label per real accepted type (including the tbz|bz2 pair) —
        proves the alternation-arm parsing (`tbz|bz2)`) is not mistaken for
        a single literal type "tbz|bz2"."""
        types = ["dmg", "pkg", "zip", "tbz", "bz2", "pkgInDmg", "pkgInZip", "appInDmgInZip"]
        label_arms = "".join(
            f'label{i}_{t})\n    name="Label {i}"\n    type="{t}"\n    ;;\n'
            for i, t in enumerate(types)
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_engine(tmp, label_arms)
            rc = _run_main(root)
        self.assertEqual(rc, 0)


class UnknownTypeTests(unittest.TestCase):
    def test_unknown_type_fails_with_label_and_line(self):
        """The exact PAT-1294 defect: type="appindmg" (case-mismatched
        against the shell dispatch's appInDmgInZip / no appInDmg arm at
        all) must be reported with the offending label name and line."""
        label_arms = (
            'inetclearreportsdesigner)\n'
            '    name="i-Net Clear Reports Designer"\n'
            '    type="appindmg"\n'
            '    ;;\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_engine(tmp, label_arms)
            rc = _run_main(root)
        self.assertEqual(rc, 1)

    def test_error_message_names_label_line_and_type(self):
        label_arms = (
            'inetclearreportsdesigner)\n'
            '    name="i-Net Clear Reports Designer"\n'
            '    type="appindmg"\n'
            '    ;;\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_engine(tmp, label_arms)
            engine_path = root / "engine" / "Installomator.sh"
            bad_line = next(
                i for i, line in enumerate(engine_path.read_text().splitlines(), 1)
                if line.strip() == 'type="appindmg"'
            )
            buf = []
            with mock.patch("builtins.print", side_effect=lambda *a, **k: buf.append(" ".join(str(x) for x in a))):
                rc = _run_main(root)
        self.assertEqual(rc, 1)
        output = "\n".join(buf)
        self.assertIn("inetclearreportsdesigner", output)
        self.assertIn(f":{bad_line})", output)
        self.assertIn('type="appindmg"', output)

    def test_reports_every_offending_stanza_not_just_the_first(self):
        """Two independent bad labels — both must be reported, not just the
        first one found."""
        label_arms = (
            'badone)\n'
            '    name="Bad One"\n'
            '    type="appindmg"\n'
            '    ;;\n'
            'goodone)\n'
            '    name="Good One"\n'
            '    type="dmg"\n'
            '    ;;\n'
            'badtwo)\n'
            '    name="Bad Two"\n'
            '    type="pkgindmg"\n'
            '    ;;\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_engine(tmp, label_arms)
            buf = []
            with mock.patch("builtins.print", side_effect=lambda *a, **k: buf.append(" ".join(str(x) for x in a))):
                rc = _run_main(root)
        self.assertEqual(rc, 1)
        output = "\n".join(buf)
        self.assertIn("badone", output)
        self.assertIn("badtwo", output)
        self.assertNotIn("goodone (", output)


class DispatchNotFoundTests(unittest.TestCase):
    """A guard that passes when it cannot see the thing it guards is the
    exact failure shape this codebase already has tickets about
    (PAT-912/PAT-837/PAT-960/PAT-1041) — these prove it fails loudly
    instead."""

    def test_missing_install_dispatch_fails_not_passes(self):
        label_arms = (
            'testapp)\n'
            '    name="Test App"\n'
            '    type="dmg"\n'
            '    ;;\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            # No install dispatch at all — only the two decoys, which
            # switch on $type but never call an installFrom* helper.
            root = _make_engine(tmp, label_arms, include_decoys=True, include_dispatch=False)
            rc = _run_main(root)
        self.assertEqual(rc, 2)

    def test_missing_engine_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "engine").mkdir()
            rc = _run_main(root)
        self.assertEqual(rc, 2)

    def test_two_blocks_with_install_marker_is_ambiguous_and_fails(self):
        """If a second `case $type in` block also happened to contain
        installFromDMG (e.g. a stray copy/paste), the parser must refuse to
        guess which one is authoritative rather than silently picking one."""
        label_arms = (
            'testapp)\n'
            '    name="Test App"\n'
            '    type="dmg"\n'
            '    ;;\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_engine(tmp, label_arms, include_decoys=False, include_dispatch=True)
            engine_path = root / "engine" / "Installomator.sh"
            # Duplicate the real dispatch so there are two installFromDMG-
            # bearing `case $type in` blocks.
            engine_path.write_text(engine_path.read_text() + _INSTALL_DISPATCH)
            rc = _run_main(root)
        self.assertEqual(rc, 2)


class RealEngineFileTests(unittest.TestCase):
    """End-to-end: run against the actual committed engine/Installomator.sh
    so a regression in the real file (not just the synthetic fixture) is
    caught too."""

    def test_real_engine_file_currently_passes(self):
        repo_root = _here.parent
        rc = _run_main(repo_root)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
