#!/usr/bin/env python3
"""
test_validate_labels.py — PAT-882 unit + fixture tests for ci/validate-labels.py.

Covers the new URL-sanity check that rejects a regex/shell fragment masquerading
as a download.source (the bug class that shipped as engine/labels/cinema4d.json's
"https://[^\"" value — captured verbatim from the shell fragment's own grep
pattern instead of resolving to the vendor page it scrapes).

Stdlib-only (unittest), no network. Requires jsonschema (same as validate-labels.py
itself).

Run:
    cd updater && python3 -m unittest ci.test_validate_labels -v
or, since ci/ is not a package:
    cd updater/ci && python3 test_validate_labels.py
"""

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest import mock

# validate-labels.py has a hyphen in its name, so it can't be `import`ed
# normally — load it by file path instead.
_here = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("validate_labels", _here / "validate-labels.py")
vl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vl)

_SCHEMA_PATH = _here.parent / "contracts" / "label.schema.json"

_BASE_RECORD = {
    "label": "testapp",
    "name": "Test App",
    "type": "dmg",
    "app_path": "/Applications/Test App.app",
    "expected_team_id": "ABCD123456",
    "download": {
        "method": "resolved",
        "strategy": "vendor-api",
        "source": "https://example.com/downloads",
    },
    "version": {"source": "resolved-source"},
    "blocking_processes": [],
    "pinned_sha256": None,
    "patched": {
        "allowlisted": False,
        "mirror": False,
        "reviewed_by": "test",
        "reviewed_at": "2026-07-15",
        "notes": None,
    },
}


class UrlSanityErrorTests(unittest.TestCase):
    """Unit tests for the url_sanity_error() helper in isolation."""

    def test_well_formed_https_url_passes(self):
        self.assertIsNone(vl.url_sanity_error("https://example.com/downloads"))

    def test_regex_fragment_is_rejected(self):
        """The exact PAT-882 defect: a grep pattern fragment leaked as a URL."""
        err = vl.url_sanity_error('https://[^"')
        self.assertIsNotNone(err)
        self.assertIn("regex/grep fragment", err)

    def test_caret_metacharacter_is_rejected(self):
        err = vl.url_sanity_error("https://example.com/^anchor")
        self.assertIsNotNone(err)

    def test_backtick_is_rejected(self):
        err = vl.url_sanity_error("https://example.com/`whoami`")
        self.assertIsNotNone(err)

    def test_raw_whitespace_is_rejected(self):
        err = vl.url_sanity_error("https://example.com/not a url")
        self.assertIsNotNone(err)

    def test_missing_host_is_rejected(self):
        err = vl.url_sanity_error("https:///no-host")
        self.assertIsNotNone(err)

    def test_host_without_dot_is_rejected(self):
        err = vl.url_sanity_error("https://localhost/x")
        self.assertIsNotNone(err)

    def test_shell_template_placeholder_still_passes(self):
        """${var} placeholders are a legitimate, pre-existing pattern in the
        manifest (amazoncorretto*jdk.json, jetbrains*.json) — the check must
        not regress these."""
        err = vl.url_sanity_error(
            "https://corretto.aws/downloads/latest/amazon-corretto-11-${cpu_arch}-macos-jdk.pkg"
        )
        self.assertIsNone(err)

    def test_query_string_with_ampersand_still_passes(self):
        err = vl.url_sanity_error(
            "https://download.jetbrains.com/product?code=x&latest&distribution=y"
        )
        self.assertIsNone(err)


class ValidateLabelsFixtureTests(unittest.TestCase):
    """End-to-end fail-before / pass-after test driving main() against a
    throwaway repo root, proving the CI gate actually rejects a reintroduced
    regex-fragment source and accepts the corrected record."""

    def _run_main(self, repo_root, emit_allowlist=None):
        argv = ["validate-labels.py", "--repo-root", str(repo_root)]
        if emit_allowlist is not None:
            argv.extend(["--emit-allowlist", str(emit_allowlist)])
        with mock.patch.object(sys, "argv", argv):
            return vl.main()

    def _make_repo(self, tmp_path, download_source):
        root = Path(tmp_path)
        contracts_dir = root / "contracts"
        labels_dir = root / "engine" / "labels"
        contracts_dir.mkdir(parents=True)
        labels_dir.mkdir(parents=True)

        contracts_dir.joinpath("label.schema.json").write_text(_SCHEMA_PATH.read_text())
        # PAT-1403: validate-labels.py now also runs
        # managed_execution_contract_errors() against this same engine text,
        # which (unlike PAT-1385's narrower pkgindmg-only check) requires
        # every allowlisted label's name/downloadURL/expectedTeamID/
        # blockingProcesses to be modeled too. Kept in exact sync with
        # _BASE_RECORD below -- NONE is the shell sentinel for an empty
        # blocking_processes list.
        (root / "engine" / "Installomator.sh").write_text(
            'case $label in\n'
            'testapp)\n'
            '    name="Test App"\n'
            '    type="dmg"\n'
            '    downloadURL="https://example.com/downloads"\n'
            '    expectedTeamID="ABCD123456"\n'
            '    blockingProcesses=( NONE )\n'
            '    ;;\n'
            'esac\n')

        rec = json.loads(json.dumps(_BASE_RECORD))  # deep copy
        rec["download"]["source"] = download_source
        labels_dir.joinpath("testapp.json").write_text(json.dumps(rec, indent=2))
        return root

    def test_fails_on_reintroduced_regex_fragment(self):
        """Before the PAT-882 fix this exact value shipped in seven label
        records and passed CI (it starts with https://, satisfying the old
        check). Prove the hardened check now rejects it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, 'https://[^"')
            rc = self._run_main(root)
        self.assertEqual(rc, 1)

    def test_passes_on_well_formed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            rc = self._run_main(root)
        self.assertEqual(rc, 0)

    def test_shared_allowlist_predicate_drives_actual_emitter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            rec["patched"]["allowlisted"] = True
            # PAT-1403: a real allowlisted, non-mirrored managed label must
            # use a static download (managed_execution_contract_errors
            # requires the shell's downloadURL to be one static literal
            # equal to the manifest) -- _BASE_RECORD's default "resolved"/
            # vendor-api shape is for non-allowlisted verifier-only tests.
            rec["download"] = {"method": "static",
                               "url": "https://example.com/downloads"}
            label_path.write_text(json.dumps(rec))
            output = root / "allowlist.txt"
            rc = self._run_main(root, output)
            emitted = output.read_text()
        self.assertEqual(rc, 0)
        self.assertIn("\ntestapp\t", emitted)

    def test_pkgindmg_without_locator_fails_pat_1424_review_gate(self):
        # PAT-1424: an absent pkg_in_dmg block is an unreviewed claim, not a
        # blank waiting to be filled -- it silently asserts the typed
        # root-unique-pkg default without anyone having confirmed the real
        # DMG payload actually is that shape. validate-labels.py must fail
        # closed on a brand new pkgindmg record that has neither an explicit
        # pkg_in_dmg block nor a documented reason in
        # UNCONFIRMED_PKGINDMG_ROOT_DEFAULT, so this can never quietly grow
        # again. See test_root_locator_and_matching_shell_pass below for the
        # explicit-block shape that satisfies this gate.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            rec["type"] = "pkgindmg"
            label_path.write_text(json.dumps(rec))
            (root / "engine" / "Installomator.sh").write_text(
                'case $label in\n'
                'testapp)\n'
                '    type="pkgInDmg"\n'
                '    ;;\n'
                'esac\n')
            rc = self._run_main(root)
        self.assertEqual(rc, 1)

    def test_root_locator_and_matching_shell_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            rec["type"] = "pkgindmg"
            rec["pkg_in_dmg"] = {"mode": "root-unique-pkg"}
            label_path.write_text(json.dumps(rec))
            (root / "engine" / "Installomator.sh").write_text(
                'case $label in\n'
                'testapp)\n'
                '    type="pkgInDmg"\n'
                '    ;;\n'
                'esac\n')
            rc = self._run_main(root)
        self.assertEqual(rc, 0)

    def test_traversal_locator_fails_custom_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            rec["type"] = "pkgindmg"
            rec["pkg_in_dmg"] = {
                "mode": "relative-path-glob", "patterns": ["../Escape.pkg"],
            }
            label_path.write_text(json.dumps(rec))
            (root / "engine" / "Installomator.sh").write_text(
                'case $label in\n'
                'testapp)\n'
                '    type="pkgInDmg"\n'
                '    pkgName="../Escape.pkg"\n'
                '    ;;\n'
                'esac\n')
            rc = self._run_main(root)
        self.assertEqual(rc, 1)

    def test_multiple_patterns_fail_schema_even_when_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            rec["type"] = "pkgindmg"
            rec["pkg_in_dmg"] = {
                "mode": "relative-path-glob",
                "patterns": ["Installer.pkg", "Alternative.pkg"],
            }
            label_path.write_text(json.dumps(rec))
            output = io.StringIO()
            with redirect_stdout(output):
                rc = self._run_main(root)
        self.assertEqual(rc, 1)
        self.assertIn("FAILED — 1 problem", output.getvalue())
        self.assertIn("pkg_in_dmg", output.getvalue())
        self.assertNotIn("type drift", output.getvalue())

    def test_schema_invalid_locator_fails_cleanly_before_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            rec["type"] = "pkgindmg"
            rec["pkg_in_dmg"] = {"mode": "invented"}
            label_path.write_text(json.dumps(rec))
            output = io.StringIO()
            with redirect_stdout(output):
                rc = self._run_main(root)
        self.assertEqual(rc, 1)
        self.assertIn("schema", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_genuinely_missing_required_keys_short_circuit_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, "https://example.com/downloads")
            label_path = root / "engine" / "labels" / "testapp.json"
            rec = json.loads(label_path.read_text())
            for key in ("label", "type", "patched"):
                rec.pop(key)
            label_path.write_text(json.dumps(rec))
            output = io.StringIO()
            with redirect_stdout(output):
                rc = self._run_main(root)
        self.assertEqual(rc, 1)
        self.assertIn("required property", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


class EmitAllowlistColumnCountTests(unittest.TestCase):
    """PAT-1403 (round 2, Finding 5): round 1 added an 8th trailing
    installed_version_key column to the derived endpoint allowlist, but the
    only real consumer — endpoint/patched-update.sh's
    `while IFS=$'\\t' read -r label name expected_tid app_path url_method
    allowlist_mirror_url allowlist_pinned_sha256; do` — only ever names
    SEVEN variables. zsh `read` assigns any extra fields (with their
    delimiters) onto the LAST named variable, so an 8-field row silently
    corrupted allowlist_pinned_sha256 with an embedded tab plus the version-
    key value appended, breaking pinned-hash verification for every
    mirrored label in production. That column addition is reverted;
    installed_version_key remains a manifest field reconciled against the
    shell's versionKey by the execution contract, but is deliberately NOT
    emitted into this derived view until a real consumer needs it. This
    test is a regression guard against silently reintroducing an 8th
    column (or any other column the one known consumer's fixed-arity `read`
    can't tolerate)."""

    def _make_repo(self, tmp_path, installed_version_key=None):
        root = Path(tmp_path)
        contracts_dir = root / "contracts"
        labels_dir = root / "engine" / "labels"
        contracts_dir.mkdir(parents=True)
        labels_dir.mkdir(parents=True)
        contracts_dir.joinpath("label.schema.json").write_text(_SCHEMA_PATH.read_text())

        rec = json.loads(json.dumps(_BASE_RECORD))
        rec["patched"]["allowlisted"] = True
        rec["download"] = {"method": "static", "url": "https://example.com/app.dmg"}
        # Matches the shell's implicit blockingProcesses=( $name ) fallback
        # below, so this allowlisted fixture also satisfies the execution
        # contract validate-labels.py runs at the end of main().
        rec["blocking_processes"] = ["Test App"]
        if installed_version_key is not None:
            rec["installed_version_key"] = installed_version_key
        labels_dir.joinpath("testapp.json").write_text(json.dumps(rec, indent=2))

        body = '''    name="Test App"
    type="dmg"
    downloadURL="https://example.com/app.dmg"
    expectedTeamID="ABCD123456"'''
        if installed_version_key is not None:
            body += f'\n    versionKey="{installed_version_key}"'
        root.joinpath("engine/Installomator.sh").write_text(
            "case $label in\ntestapp)\n" + body + "\n    ;;\nesac\n")
        return root

    def _emit(self, root):
        out = root / "allowlist.txt"
        argv = ["validate-labels.py", "--repo-root", str(root), "--emit-allowlist", str(out)]
        with mock.patch.object(sys, "argv", argv):
            rc = vl.main()
        return rc, out.read_text()

    def test_emitted_row_has_exactly_seven_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp)
            rc, text = self._emit(root)
        self.assertEqual(rc, 0)
        line = next(l for l in text.splitlines() if l.startswith("testapp\t"))
        self.assertEqual(7, len(line.split("\t")), line)

    def test_installed_version_key_override_is_not_emitted_as_extra_column(self):
        """Even when the manifest overrides installed_version_key, the
        derived allowlist row must still be exactly 7 fields — the override
        is reconciled by the execution contract, not surfaced here."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(tmp, installed_version_key="CFBundleVersion")
            rc, text = self._emit(root)
        self.assertEqual(rc, 0)
        line = next(l for l in text.splitlines() if l.startswith("testapp\t"))
        self.assertEqual(7, len(line.split("\t")), line)

    def test_real_endpoint_consumer_read_line_names_seven_fields(self):
        """Belt-and-braces: directly pins the actual consumer's `read`
        arity, so a future change to either side (the emitter or
        endpoint/patched-update.sh's read line) that lets them drift back
        out of sync fails loudly here instead of silently corrupting a
        pinned hash in production."""
        root = Path(__file__).resolve().parents[1]
        consumer_source = (root / "endpoint" / "patched-update.sh").read_text()
        self.assertIn(
            "while IFS=$'\\t' read -r label name expected_tid app_path url_method "
            "allowlist_mirror_url allowlist_pinned_sha256; do",
            consumer_source,
        )


if __name__ == "__main__":
    unittest.main()
