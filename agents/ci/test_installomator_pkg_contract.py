#!/usr/bin/env python3
"""PAT-1385 pkgindmg manifest/endpoint-engine contract regressions."""

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installomator_pkg_contract import (
    KNOWN_INCORRECT_PKGINDMG_DEFAULT,
    SHELL_ONLY_EXPLICIT_PKGIN_DMG,
    UNCONFIRMED_PKGINDMG_ROOT_DEFAULT,
    VERIFIER_ONLY_PKGIN_DMG,
    is_endpoint_allowlisted,
    is_explicit_pkgindmg_locator,
    is_reviewed_pkgindmg_locator,
    parse_installomator_labels,
    parse_pkgindmg_runtime_capabilities,
    pkgindmg_contract_errors,
    safe_relative_pkg_pattern_error,
)


ROOT = Path(__file__).resolve().parent.parent
LOCATOR_CASES = json.loads((
    ROOT / "ci" / "fixtures" / "pkgindmg-locator-cases.json"
).read_text(encoding="utf-8"))


def record(label, locator=None, *, allowlisted=False, artifact_type="pkgindmg"):
    result = {
        "label": label,
        "type": artifact_type,
        "patched": {"allowlisted": allowlisted},
    }
    if locator is not None:
        result["pkg_in_dmg"] = locator
    return result


def engine(*arms):
    return "\n".join(("case $label in", *arms, "esac", ""))


class PathSafetyTests(unittest.TestCase):
    def test_shared_locator_corpus_matches_validator_safety(self):
        for case in LOCATOR_CASES["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    safe_relative_pkg_pattern_error(case["pattern"]) is None,
                    case["valid"],
                )
    def test_safe_relative_exact_path_and_glob(self):
        self.assertIsNone(safe_relative_pkg_pattern_error(
            "Acrobat/Acrobat DC Installer.pkg"))
        self.assertIsNone(safe_relative_pkg_pattern_error(
            "OpenVPN_Connect_[0-9_()]*_arm64_Installer_signed.pkg"))

    def test_traversal_and_absolute_paths_fail(self):
        self.assertIn("'..'", safe_relative_pkg_pattern_error("../Escape.pkg"))
        self.assertIn("relative", safe_relative_pkg_pattern_error("/Escape.pkg"))
        self.assertIn("'..'", safe_relative_pkg_pattern_error("A/../Escape.pkg"))

    def test_non_pkg_and_shell_payload_fail(self):
        self.assertIn(".pkg", safe_relative_pkg_pattern_error("Installer.app"))
        self.assertIn("vocabulary", safe_relative_pkg_pattern_error("$(touch owned).pkg"))


class ParserTests(unittest.TestCase):
    def test_indented_case_arm_is_recognised_as_its_own_stanza(self):
        # PAT-1432: an INDENTED arm (the real `    displaynote)`,
        # `    supportapp)` shape) used to be silently absorbed into the
        # PRECEDING stanza's body -- undetectable as a boundary at all --
        # which this test used to pin as a "fails closed" containment
        # (the pkgInDmg-count sanity check at the bottom of
        # parse_installomator_labels() caught the resulting count mismatch
        # and raised). Now that the walker recognises this spelling, both
        # stanzas parse correctly and independently: no exception, and
        # 'hidden' is not merged into 'good'.
        parsed = parse_installomator_labels(engine(
            'good)', '    type="dmg"', '    ;;',
            '  hidden)', '    type="pkgInDmg"', '    ;;'))
        self.assertEqual(parsed["good"].shell_types, ("dmg",))
        self.assertEqual(parsed["hidden"].shell_types, ("pkgInDmg",))

    def test_glued_case_arm_is_recognised_as_its_own_stanza(self):
        # PAT-1432: an arm GLUED directly onto the preceding stanza's `;;`
        # terminator on the same physical line (the real `;;egnyte)`,
        # `;;editshare-flowstory)` shape) -- the second missed spelling,
        # found alongside the indented one by PAT-1429's real-corpus
        # survey. Same fix, same assertion shape as the indented case above.
        parsed = parse_installomator_labels(engine(
            'good)', '    type="dmg"',
            '    ;;hidden)', '    type="pkgInDmg"', '    ;;'))
        self.assertEqual(parsed["good"].shell_types, ("dmg",))
        self.assertEqual(parsed["hidden"].shell_types, ("pkgInDmg",))

    def test_nested_case_arms_are_not_mistaken_for_label_arm_boundaries(self):
        # PAT-1432: recognising an INDENTED line as a possible arm boundary
        # is dangerous on its own -- the real corpus has a genuine nested
        # `case ... in ... esac` block (macports' own
        # `case $(uname -r | cut -d '.' -f 1) in ... 25) ... esac`) whose
        # bare numeric arms (`25)`, `24)`, ...) would themselves look like
        # indented label-arm boundaries once stripped of leading
        # whitespace, wrongly truncating the stanza and losing the real
        # `expectedTeamID=` assignment that follows the nested `esac`. The
        # walker must track nested case depth and only treat an indented
        # (or glued) line as a real boundary outside any nested case.
        parsed = parse_installomator_labels(engine(
            'widget)', '    type="dmg"',
            "    case $(uname -r | cut -d '.' -f 1) in",
            '        25)',
            '            archiveName="Tahoe.pkg"',
            '            ;;',
            '        *)',
            '            cleanupAndExit 98 "unsupported"',
            '            ;;',
            '    esac',
            '    expectedTeamID="ABCDEFGHIJ"',
            '    ;;',
            'next)', '    type="dmg"', '    ;;'))
        self.assertEqual(parsed["widget"].team_id_assignments,
                          ('"ABCDEFGHIJ"',))
        self.assertEqual(parsed["next"].shell_types, ("dmg",))

    def test_single_line_case_arm_with_pkgindmg_fails_closed(self):
        # A THIRD candidate shape -- arm header, body, and `;;` terminator
        # all on one physical line -- was checked by PAT-1432's real-corpus
        # sweep (a search for zsh's `;&`/`;;&` fallthrough operators and
        # for any same-line arm+body+terminator one-liner) and confirmed to
        # occur nowhere in the real corpus, so it remains deliberately
        # unrecognised: still absorbed into the preceding stanza, still
        # caught by the pkgInDmg-count sanity check, still fails closed.
        with self.assertRaisesRegex(ValueError, "case arm"):
            parse_installomator_labels(
                'case $label in\nhidden) type="pkgInDmg" ;;\nesac\n')
    def test_adobe_nested_literal(self):
        parsed = parse_installomator_labels(engine(
            'adobeacrobatprodc)',
            '    type="pkgInDmg"',
            '    pkgName="Acrobat/Acrobat DC Installer.pkg"',
            '    ;;',
        ))
        self.assertEqual(
            parsed["adobeacrobatprodc"].normalised_pkg_names(),
            ("Acrobat/Acrobat DC Installer.pkg",),
        )
        self.assertEqual(
            parsed["adobeacrobatprodc"].normalised_pkg_path_patterns(), ())

    def test_pkg_path_pattern_is_parsed_separately_from_pkg_name(self):
        parsed = parse_installomator_labels(engine(
            'jre8)',
            '    type="pkgInDmg"',
            '    pkgPathPattern="Java *.app/Contents/Resources/Plugin.pkg"',
            '    ;;',
        ))["jre8"]
        self.assertEqual(parsed.normalised_pkg_names(), ())
        self.assertEqual(parsed.normalised_pkg_path_patterns(), (
            "Java *.app/Contents/Resources/Plugin.pkg",))

    def test_dynamic_and_architecture_globs_normalise_to_data(self):
        parsed = parse_installomator_labels(engine(
            'archiwareb2go)',
            '    type="pkgInDmg"',
            "    pkgName=$(appNrVersion=`sed 's/[^0-9]//g' <<< $appNewVersion` && echo P5-Workstation-\"$appNrVersion\"-Install.pkg)",
            '    ;;',
            'openvpnconnectv3)',
            '    type="pkgInDmg"',
            '    if [[ $(arch) == "arm64" ]]; then',
            '        pkgName="OpenVPN_Connect_[0-9_()]*_arm64_Installer_signed.pkg"',
            '    elif [[ $(arch) == "i386" ]]; then',
            '        pkgName="OpenVPN_Connect_[0-9_()]*_x86_64_Installer_signed.pkg"',
            '    fi',
            '    ;;',
        ))
        self.assertEqual(
            parsed["archiwareb2go"].normalised_pkg_names(),
            ("P5-Workstation-{version_digits}-Install.pkg",),
        )
        self.assertEqual(
            parsed["openvpnconnectv3"].normalised_pkg_name_patterns_by_arch(),
            {
                "arm64": ("OpenVPN_Connect_[0-9_()]*_arm64_Installer_signed.pkg",),
                "i386": ("OpenVPN_Connect_[0-9_()]*_x86_64_Installer_signed.pkg",),
            },
        )

    def test_continued_alias_uses_first_real_runtime_arm(self):
        parsed = parse_installomator_labels(engine(
            'googledrive|\\',
            'googledrivefilestream)',
            '    type="pkgInDmg"',
            '    ;;',
        ))
        self.assertEqual(parsed["googledrive"].shell_types, ("pkgInDmg",))
        self.assertIs(parsed["googledrive"], parsed["googledrivefilestream"])

    def test_same_line_alias_arm_is_discovered(self):
        parsed = parse_installomator_labels(engine(
            'one|two)', '    type="pkgInDmg"', '    ;;'))
        self.assertEqual(set(parsed), {"one", "two"})
        self.assertIs(parsed["one"], parsed["two"])

    def test_unrecognised_executable_assignment_fails_closed(self):
        parsed = parse_installomator_labels(engine(
            'bad)',
            '    type="pkgInDmg"',
            '    pkgName=$(curl https://example.test/name)',
            '    ;;',
        ))
        with self.assertRaisesRegex(ValueError, "unsupported pkgName assignment"):
            parsed["bad"].normalised_pkg_names()

    def test_lookalike_echo_command_substitution_still_fails_closed(self):
        parsed = parse_installomator_labels(engine(
            'bad)',
            '    type="pkgInDmg"',
            '    pkgName=$(curl https://example.test/name && echo Safe.pkg)',
            '    ;;',
        ))
        with self.assertRaisesRegex(ValueError, "unsupported pkgName assignment"):
            parsed["bad"].normalised_pkg_names()


class TrailingCommentQuoteTrackerTests(unittest.TestCase):
    """PAT-1409: the per-stanza single-quote tracker used to treat ANY
    unmatched `'` as opening a multi-line quoted span, with no exclusion for
    same-line trailing comments. An ordinary comment containing an
    apostrophe -- `# vendor's installer` -- was therefore misread as
    OPENING a span that never legitimately closed within the stanza, and
    everything after it (potentially the stanza's only real pkgName=/
    pkgPathPattern= assignment) was silently swallowed as inert quoted
    data. Unlike every other documented caveat in this parser, that failure
    is silent and fails OPEN: the drift gate would see no selector at all
    and report a manifest record consistent when it was not. These tests
    prove the fix (an unescaped `#` outside any open string now ends
    quote-tracking for the rest of the physical line) without regressing
    the harder adjacent cases: a `#` legitimately inside an already-open
    quoted string, a `#` inside a same-line double-quoted value, escaped
    quotes/`#`, and a real multi-line quoted span that must still track
    correctly across lines."""

    def test_trailing_apostrophe_comment_does_not_swallow_later_pkgname(self):
        # The exact defect shape: a same-line trailing comment with an
        # apostrophe on an UNRELATED line (downloadURL=), followed later in
        # the same stanza by the stanza's only real pkgName= assignment.
        # Before the fix, the comment's "'" in "vendor's" opened a
        # multi-line single-quote span that never closed, so pkgName=
        # below was parsed as inert quoted data and never registered --
        # normalised_pkg_names() would have returned () here.
        parsed = parse_installomator_labels(engine(
            'vendorapp)',
            '    type="pkgInDmg"',
            "    downloadURL=\"https://cdn.example.test/VendorApp.dmg\" # vendor's installer",
            '    appNewVersion="1.2.3"',
            '    pkgName="VendorApp Installer.pkg"',
            '    ;;',
        ))
        self.assertEqual(
            parsed["vendorapp"].normalised_pkg_names(),
            ("VendorApp Installer.pkg",))

    def test_trailing_apostrophe_comment_does_not_swallow_later_pkgpathpattern(self):
        # Same defect shape, exercised against pkgPathPattern= rather than
        # pkgName= -- the ticket calls out both selectors separately since
        # they are matched by distinct regexes further down the loop.
        parsed = parse_installomator_labels(engine(
            'vendorapp2)',
            '    type="pkgInDmg"',
            "    downloadURL=\"https://cdn.example.test/VendorApp2.dmg\" # vendor's installer",
            '    appNewVersion="1.2.3"',
            '    pkgPathPattern="VendorApp2 *.app/Contents/Resources/Installer.pkg"',
            '    ;;',
        ))
        self.assertEqual(
            parsed["vendorapp2"].normalised_pkg_path_patterns(),
            ("VendorApp2 *.app/Contents/Resources/Installer.pkg",))

    def test_escaped_apostrophe_and_real_trailing_comment_apostrophe_together(self):
        # Combines two of the ticket's tricky cases on one physical line: an
        # escaped apostrophe in the code portion (`Bob\'s`, literal text,
        # must not open a span) immediately followed by a real trailing
        # comment that itself contains an unescaped apostrophe (must not
        # open a span either, because it never reaches shell as code at
        # all). Both must leave the tracker un-opened so the real pkgName=
        # below is still seen.
        parsed = parse_installomator_labels(engine(
            'escapedapos)',
            '    type="pkgInDmg"',
            "    note=Bob\\'s installer # vendor's installer",
            '    pkgName="Installer.pkg"',
            '    ;;',
        ))
        self.assertEqual(
            parsed["escapedapos"].normalised_pkg_names(), ("Installer.pkg",))

    def test_hash_inside_double_quoted_pkgname_value_is_parsed_literally(self):
        # A `#` legitimately inside a quoted value on the same line (the
        # ticket's `pkgName="foo#bar.pkg"` example) must not be treated as
        # opening a comment at all -- the raw assignment must still be
        # captured with the `#` intact, verbatim, rather than the line
        # being cut short. (`#` is outside `_SAFE_PATTERN_RE`'s vocabulary,
        # so a genuinely `#`-containing pkg name would separately be
        # rejected by normalised_pkg_names() -- that safety check is
        # unrelated to quote tracking and out of scope here; this test
        # only proves the assignment reaches that check intact rather than
        # being silently truncated or dropped by the tracker.)
        parsed = parse_installomator_labels(engine(
            'hashvalue)',
            '    type="pkgInDmg"',
            '    pkgName="Foo#Bar.pkg"',
            '    ;;',
        ))
        self.assertEqual(
            parsed["hashvalue"].pkg_name_assignments, ('"Foo#Bar.pkg"',))

    def test_hash_inside_double_quote_does_not_end_scan_early(self):
        # Sharper version of the case above: proves the fix reasons about
        # BOTH quote characters consistently rather than special-casing
        # single quotes, by making a WRONG answer observable. The line
        # below has a `#` inside a same-line double-quoted value
        # ("See vendor#docs"), then -- still on that same physical line,
        # after the double quote closes -- a genuine unmatched `'` that
        # legitimately opens a real multi-line span (mirroring
        # test_multiline_quoted_payload_generalizes_beyond_hardcoded_labels).
        # A tracker that special-cased single quotes (checking only
        # in_multiline_single_quote, not the double-quote stack) before
        # deciding a `#` starts a comment would misfire on the double-quoted
        # `#`, stop scanning the line right there, and never reach the real
        # `'` -- so the span below would never open, and the quoted-data
        # `pkgName="Fake.pkg"` line would be misread as a second real
        # assignment instead of staying inert.
        parsed = parse_installomator_labels(engine(
            'hashtrap)',
            '    type="pkgInDmg"',
            '    pkgName="Installer.pkg"',
            "    note=\"See vendor#docs\" && payload=$(curl -s -d '<xml>",
            '    pkgName="Fake.pkg"',
            "    </xml>' http://example.test)",
            '    ;;',
        ))
        self.assertEqual(
            parsed["hashtrap"].normalised_pkg_names(), ("Installer.pkg",))

    def test_escaped_hash_does_not_start_comment(self):
        # An escaped `#` (`\#`) outside any quote is literal text, not a
        # comment marker -- exactly like the escaped-quote handling this
        # loop already had. Same observable-wrong-answer trap as above: a
        # genuine `'` after the escaped `#`, on the same line, must still
        # be recognised as opening a real multi-line span.
        parsed = parse_installomator_labels(engine(
            'escapedhash)',
            '    type="pkgInDmg"',
            '    pkgName="Installer.pkg"',
            "    note=foo\\#bar && payload=$(curl -s -d '<xml>",
            '    pkgName="Fake.pkg"',
            "    </xml>' http://example.test)",
            '    ;;',
        ))
        self.assertEqual(
            parsed["escapedhash"].normalised_pkg_names(), ("Installer.pkg",))

    def test_hash_inside_open_multiline_singlequote_is_literal_not_comment(self):
        # The remaining hard case named by the ticket: a `#` that appears
        # while ALREADY inside an open multi-line single-quoted span (from
        # a previous line) is inert quoted data, not a comment, and must
        # not disturb the span. The tracker's top-of-loop
        # `if in_multiline_single_quote:` branch already ignores every
        # character except the closing `'` while a span is open, so this
        # case cannot reach the new comment-detection branch at all -- this
        # test is the regression guard proving that stays true.
        parsed = parse_installomator_labels(engine(
            'openquote)',
            '    type="pkgInDmg"',
            '    pkgName="Installer.pkg"',
            "    payload=$(curl -s -d '<xml note=\"see vendor#docs for details\">",
            '    pkgName="Fake.pkg" # this looks real but is quoted data',
            "    </xml>' http://example.test)",
            '    ;;',
        ))
        self.assertEqual(
            parsed["openquote"].normalised_pkg_names(), ("Installer.pkg",))


class NonPkgindmgScopeAndPerLabelIsolationTests(unittest.TestCase):
    """PAT-1385 round 9 (P2 finding 2): the pkgInDmg-specific structural
    strictness in parse_installomator_labels() (appNewVersion/
    appBuildVersion must be unconditional, pkgName/pkgPathPattern must be
    top-level or in a single arch conditional, an unrecognised assignment
    shape fails closed) must apply ONLY to stanzas whose own `type=` is
    genuinely "pkgInDmg" (finding 2a), and a stanza that fails to parse
    must degrade to a per-label error naming it, never abort every other
    label's result via a whole-gate ValueError (finding 2b)."""

    def test_real_pkginzip_labels_with_unrelated_pkgname_are_untouched(self):
        # Real evidence, not a synthetic worst-case: engine/Installomator.sh
        # has two type="pkgInZip" stanzas (eastwestplay, logioptions|
        # logitechoptions) that assign pkgName for their own, unrelated
        # pkgInZip extraction reasons. logioptions's assignment
        # (`pkgName=LogiMgr.pkg`, unquoted) is a shape
        # _normalise_pkg_name_assignment() genuinely rejects ("unsupported
        # pkgName assignment") -- proving these are real, live pkgName
        # assignments this parser would object to if pkgInDmg's strictness
        # ever reached them. Before finding 2a's fix, tracks_payload fired
        # on ANY stanza containing the substring, so pkgInDmg's structural
        # rules ran on these pkgInZip bodies too; scoping tracks_payload to
        # `stanza_is_pkgindmg` means these bodies are never even scanned
        # for pkgName at all now (their pkgName is pkgInZip's own concern,
        # not this contract's), let alone validated/raised over.
        engine_text = (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8")
        parsed = parse_installomator_labels(engine_text)
        for label in ("eastwestplay", "logioptions", "logitechoptions"):
            with self.subTest(label=label):
                shell = parsed[label]
                self.assertEqual(shell.shell_types, ("pkgInZip",))
                self.assertIsNone(shell.parse_error)
                # Untracked entirely for a non-pkgInDmg stanza -- pkgInDmg's
                # pkgName bookkeeping is simply not this stanza's business.
                self.assertEqual(shell.pkg_name_assignments, ())

        errors = pkgindmg_contract_errors([], engine_text)
        # None of these three real pkgInZip labels should generate any
        # pkgindmg-contract error -- they are not pkgInDmg-typed and were
        # never touched by this contract before this ticket either.
        for label in ("eastwestplay", "logioptions", "logitechoptions"):
            self.assertFalse(any(label in error for error in errors), errors)

    def test_synthetic_pkginzip_pkgname_inside_conditional_does_not_trip_strictness(self):
        # A sharper synthetic case than the real labels above: a pkgName=
        # nested inside a plain (non-arch) `if` -- exactly the shape that
        # raises "payload selector inside unrecognised or nested
        # conditional" for a pkgInDmg stanza. A pkgInZip stanza doing the
        # same thing must parse cleanly, because pkgInDmg's structural
        # rules are not this stanza's semantics at all.
        parsed = parse_installomator_labels(engine(
            'unrelatedzip)',
            '    type="pkgInZip"',
            '    if [[ -f /tmp/marker ]]; then',
            '        pkgName="Marker.pkg"',
            '    fi',
            '    ;;',
        ))
        shell = parsed["unrelatedzip"]
        self.assertEqual(shell.shell_types, ("pkgInZip",))
        self.assertIsNone(shell.parse_error)

    def test_malformed_pkgindmg_stanza_is_a_per_label_error_not_a_whole_gate_abort(self):
        # A genuine pkgInDmg stanza with pkgName nested inside a plain (non-
        # arch) conditional -- the exact shape that raises "payload
        # selector inside unrecognised or nested conditional". Paired with
        # a second, well-formed pkgInDmg label in the SAME engine text.
        # Before finding 2b's fix, parse_installomator_labels() propagated
        # that ValueError all the way out and pkgindmg_contract_errors()
        # turned it into a single whole-gate
        # "Installomator parser: ..." error that silenced goodlabel's
        # result entirely.
        engine_text = engine(
            'brokenlabel)',
            '    type="pkgInDmg"',
            '    if [[ -f /tmp/marker ]]; then',
            '        pkgName="Marker.pkg"',
            '    fi',
            '    ;;',
            'goodlabel)',
            '    type="pkgInDmg"',
            '    pkgName="Good.pkg"',
            '    ;;',
        )
        # The parser itself no longer raises for this -- it degrades the
        # one broken stanza to a ShellLabel.parse_error and keeps going.
        parsed = parse_installomator_labels(engine_text)
        self.assertIsNotNone(parsed["brokenlabel"].parse_error)
        self.assertIn(
            "payload selector inside unrecognised or nested conditional",
            parsed["brokenlabel"].parse_error)
        self.assertIsNone(parsed["goodlabel"].parse_error)

        errors = pkgindmg_contract_errors([
            record("goodlabel", {"mode": "relative-path-glob",
                                  "patterns": ["Good.pkg"]}),
        ], engine_text)
        # brokenlabel's failure is reported BY NAME, not as an opaque
        # whole-gate "Installomator parser: ..." message that gives no
        # label to investigate.
        self.assertTrue(any(
            "brokenlabel" in error and "payload selector" in error
            for error in errors), errors)
        # goodlabel's own, unrelated check still ran and found no drift --
        # proof the whole gate did not abort over brokenlabel's failure.
        self.assertFalse(any("goodlabel" in error for error in errors), errors)

    def test_malformed_pkgindmg_stanza_with_manifest_record_names_the_label(self):
        # Same malformed shell shape as above, but this time a manifest
        # record for "brokenlabel" DOES exist -- exercising the second
        # (per-record) parse_error check in pkgindmg_contract_errors(),
        # which must report the real parse failure by name rather than
        # letting the broken stanza's placeholder-empty pkg_name_assignments
        # fall through to normalised_pkg_names() and get misreported as an
        # ordinary locator-drift mismatch against the manifest.
        engine_text = engine(
            'brokenlabel)',
            '    type="pkgInDmg"',
            '    if [[ -f /tmp/marker ]]; then',
            '        pkgName="Marker.pkg"',
            '    fi',
            '    ;;',
        )
        errors = pkgindmg_contract_errors([
            record("brokenlabel", {"mode": "relative-path-glob",
                                    "patterns": ["Marker.pkg"]}),
        ], engine_text)
        self.assertTrue(any(
            error.startswith("brokenlabel: Installomator stanza failed to parse:")
            for error in errors), errors)
        # And NOT the generic, unrelated-sounding locator-drift message
        # that reading empty pkg_name_assignments as "shell sets nothing"
        # would have produced.
        self.assertFalse(any(
            "runtime must assign exactly one active selector" in error
            for error in errors), errors)


class ContractTests(unittest.TestCase):
    def test_full_validator_reads_engine_and_manifest_as_utf8_under_c_locale(self):
        env = os.environ.copy()
        env.update({
            "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0",
            "PYTHONIOENCODING": "utf-8",
        })
        result = subprocess.run(
            [sys.executable, str(ROOT / "ci" / "validate-labels.py")],
            cwd=ROOT, env=env, capture_output=True, timeout=30)
        self.assertEqual(
            result.returncode, 0,
            (result.stdout + result.stderr).decode("utf-8", errors="replace"))

    def test_allowlist_predicate_is_exact_boolean_true(self):
        self.assertTrue(is_endpoint_allowlisted({"patched": {"allowlisted": True}}))
        for value in (False, None, 1, "true"):
            with self.subTest(value=value):
                self.assertFalse(is_endpoint_allowlisted(
                    {"patched": {"allowlisted": value}}))

    def test_root_default_matches_stanza_without_pkgname(self):
        # PAT-1424: an explicit {"mode": "root-unique-pkg"} block (not a
        # bare implicit record -- see test_undocumented_implicit_default_
        # fails_pat_1424_review_gate below) so this test keeps exercising
        # ONLY the shell/manifest root-default reconciliation it names,
        # without also tripping the separate PAT-1424 "has this record been
        # reviewed at all" gate.
        errors = pkgindmg_contract_errors([
            record("rootpkg", {"mode": "root-unique-pkg"}),
        ], engine('rootpkg)', '    type="pkgInDmg"', '    ;;'))
        self.assertEqual(errors, [])

    def test_explicit_nested_path_matches_shell(self):
        errors = pkgindmg_contract_errors([
            record("adobeacrobatprodc", {
                "mode": "relative-path-glob",
                "patterns": ["Acrobat/Acrobat DC Installer.pkg"],
            }),
        ], engine(
            'adobeacrobatprodc)',
            '    type="pkgInDmg"',
            '    pkgName="Acrobat/Acrobat DC Installer.pkg"',
            '    ;;',
        ))
        self.assertEqual(errors, [])

    def test_architecture_locator_matches_shell_branches(self):
        errors = pkgindmg_contract_errors([
            record("openvpn", {
                "mode": "relative-path-glob-by-arch",
                "patterns_by_arch": {
                    "arm64": "OpenVPN_*_arm64_Installer.pkg",
                    "i386": "OpenVPN_*_x86_64_Installer.pkg",
                },
            }),
        ], engine(
            'openvpn)',
            '    type="pkgInDmg"',
            '    if [[ $(arch) == "arm64" ]]; then',
            '        pkgName="OpenVPN_*_arm64_Installer.pkg"',
            '    elif [[ $(arch) == "i386" ]]; then',
            '        pkgName="OpenVPN_*_x86_64_Installer.pkg"',
            '    fi',
            '    ;;',
        ))
        self.assertEqual(errors, [])

    def test_jre_dynamic_exact_path_is_supported_by_runtime_branch(self):
        records = [json.loads(path.read_text())
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        errors = pkgindmg_contract_errors(
            records,
            (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8"))
        self.assertEqual(errors, [])
        self.assertTrue(parse_pkgindmg_runtime_capabilities(
            (ROOT / "engine" / "Installomator.sh").read_text()).exact_relative_path)

    def test_ambiguous_or_drifted_shell_patterns_fail(self):
        errors = pkgindmg_contract_errors([
            record("multi", {
                "mode": "relative-path-glob",
                "patterns": ["One.pkg"],
            }),
        ], engine(
            'multi)',
            '    type="pkgInDmg"',
            '    pkgName="One.pkg"',
            '    pkgName="Two.pkg"',
            '    ;;',
        ))
        self.assertEqual(len(errors), 1)
        self.assertIn("exactly one active selector", errors[0])

    def test_type_drift_fails(self):
        errors = pkgindmg_contract_errors([
            record("wrong", {"mode": "root-unique-pkg"}),
        ], engine('wrong)', '    type="dmg"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("type drift", errors[0])

    def test_missing_runtime_stanza_requires_explicit_verifier_only_inventory(self):
        shell = engine('other)', '    type="dmg"', '    ;;')
        errors = pkgindmg_contract_errors([
            record("verify-only", {"mode": "root-unique-pkg"}),
        ], shell)
        self.assertTrue(any("not explicitly enumerated" in error
                            for error in errors))
        errors = pkgindmg_contract_errors([
            record("endpoint", {"mode": "root-unique-pkg"}, allowlisted=True),
        ], shell)
        self.assertEqual(len(errors), 1)
        self.assertIn("no Installomator label stanza", errors[0])

    def test_root_default_can_be_endpoint_allowlisted_when_runtime_is_root_unique(self):
        # PAT-1424: see test_root_default_matches_stanza_without_pkgname --
        # explicit here for the same reason (isolate this test's own
        # concern, allowlisting a root-unique record, from the separate
        # PAT-1424 review gate).
        errors = pkgindmg_contract_errors([
            record("rootpkg", {"mode": "root-unique-pkg"}, allowlisted=True),
        ], engine('rootpkg)', '    type="pkgInDmg"', '    ;;'))
        self.assertEqual(errors, [])

    def test_assigning_both_runtime_selector_variables_fails_closed(self):
        errors = pkgindmg_contract_errors([
            record("both", {
                "mode": "relative-path-glob", "patterns": ["One.pkg", "Two.pkg"],
            }),
        ], engine(
            'both)', '    type="pkgInDmg"',
            '    pkgName="One.pkg"',
            '    pkgPathPattern="Two.pkg"', '    ;;'))
        self.assertTrue(any("exactly one active selector" in error
                            for error in errors))

    def test_multi_pattern_manifest_fails_even_with_one_runtime_assignment(self):
        errors = pkgindmg_contract_errors([
            record("multi", {
                "mode": "relative-path-glob", "patterns": ["One.pkg", "Two.pkg"],
            }),
        ], engine(
            'multi)', '    type="pkgInDmg"', '    pkgName="One.pkg"', '    ;;'))
        self.assertTrue(any("must declare exactly one pattern" in error
                            for error in errors))

    def test_duplicate_runtime_assignment_is_not_collapsed_to_a_set(self):
        errors = pkgindmg_contract_errors([
            record("duplicate", {
                "mode": "relative-path-glob", "patterns": ["One.pkg"],
            }),
        ], engine(
            'duplicate)', '    type="pkgInDmg"',
            '    pkgName="One.pkg"', '    pkgName="One.pkg"', '    ;;'))
        self.assertTrue(any("exactly one active selector" in error
                            for error in errors))

    def test_non_arch_conditional_alternatives_fail_as_multiple_assignments(self):
        errors = pkgindmg_contract_errors([
            record("conditional", {
                "mode": "relative-path-glob", "patterns": ["One.pkg"],
            }),
        ], engine(
            'conditional)', '    type="pkgInDmg"',
            '    if [[ "$channel" == "one" ]]; then',
            '        pkgName="One.pkg"', '    else',
            '        pkgName="Two.pkg"', '    fi', '    ;;'))
        self.assertTrue(any("unrecognised or nested conditional" in error
                            for error in errors))

    def test_nested_arch_selector_conditional_fails_closed(self):
        errors = pkgindmg_contract_errors([], engine(
            'nested)', '    type="pkgInDmg"',
            '    if [[ $(arch) == "arm64" ]]; then',
            '        if [[ "$channel" == "stable" ]]; then',
            '            pkgName="Arm.pkg"', '        fi', '    fi', '    ;;'))
        self.assertTrue(any("unrecognised or nested conditional" in error
                            for error in errors))

    def test_split_line_unrecognised_selector_conditional_fails_closed(self):
        errors = pkgindmg_contract_errors([], engine(
            'split)', '    type="pkgInDmg"',
            '    if [[ "$channel" == "stable" ]]', '    then',
            '        pkgPathPattern="Nested/Stable.pkg"', '    fi', '    ;;'))
        self.assertTrue(any("conditional" in error for error in errors))

    def test_jre_component_derivation_drift_fails(self):
        errors = pkgindmg_contract_errors([
            record("jre8", {
                "mode": "relative-path-version-component",
                "template": ("Java 8 Update {version_component}.app/Contents/"
                             "Resources/JavaAppletPlugin.pkg"),
                "separator": ".", "component_index": 3,
            }),
        ], engine(
            'jre8)', '    type="pkgInDmg"',
            '    appBuildVersion=$(echo $appNewVersion | cut -d. -f2)',
            '    pkgPathPattern="Java 8 Update ${appBuildVersion}.app/Contents/Resources/JavaAppletPlugin.pkg"',
            '    ;;'))
        self.assertTrue(any("version-component locator drift" in error
                            for error in errors))

    def test_appnewversion_xpath_field_drift_fails_even_with_matching_cut_transform(self):
        # PAT-1385 P2 fix (round 8): the contract used to only compare the
        # `cut` separator/field-index/template SHAPE, never confirm the
        # shell and manifest agree on which appcast XML node appNewVersion
        # itself comes from -- exactly the P1 jre8 bug's shape (verifier
        # reads shortVersionString, shell reads the raw sparkle:version
        # attribute) but as a CI gate gap. This stanza changes the xpath
        # field from sparkle:version to sparkle:shortVersionString while
        # keeping the IDENTICAL `cut -d. -f3` transform and pkgPathPattern
        # template the old check already passed -- proving the gate now
        # catches THIS shape, not just an outright transform mismatch.
        errors = pkgindmg_contract_errors([
            record("jre8", {
                "mode": "relative-path-version-component",
                "template": ("Java 8 Update {version_component}.app/Contents/"
                             "Resources/JavaAppletPlugin.pkg"),
                "separator": ".", "component_index": 3,
                "version_source": "sparkle-enclosure-version",
            }),
        ], engine(
            'jre8)', '    type="pkgInDmg"',
            '    appNewVersion=$(curl -fs "${versionURL}" | '
            'xpath \'(//rss/channel/item/enclosure/@sparkle:shortVersionString)\' '
            '2>/dev/null | cut -d \'"\' -f 2)',
            '    appBuildVersion=$(echo $appNewVersion | cut -d. -f3)',
            '    pkgPathPattern="Java 8 Update ${appBuildVersion}.app/Contents/Resources/JavaAppletPlugin.pkg"',
            '    ;;'))
        self.assertTrue(any(
            "version_source='sparkle-enclosure-version'" in error
            and "appNewVersion reads" in error
            for error in errors))

    def test_appnewversion_xpath_field_matching_source_passes(self):
        # Positive control for the check above: jre8's REAL shape (raw
        # sparkle:version attribute, version_source='sparkle-enclosure-
        # version') must produce no drift error.
        errors = pkgindmg_contract_errors([
            record("jre8", {
                "mode": "relative-path-version-component",
                "template": ("Java 8 Update {version_component}.app/Contents/"
                             "Resources/JavaAppletPlugin.pkg"),
                "separator": ".", "component_index": 3,
                "version_source": "sparkle-enclosure-version",
            }),
        ], engine(
            'jre8)', '    type="pkgInDmg"',
            '    appNewVersion=$(curl -fs "${versionURL}" | '
            'xpath \'(//rss/channel/item/enclosure/@sparkle:version)\' '
            '2>/dev/null | cut -d \'"\' -f 2)',
            '    appBuildVersion=$(echo $appNewVersion | cut -d. -f3)',
            '    pkgPathPattern="Java 8 Update ${appBuildVersion}.app/Contents/Resources/JavaAppletPlugin.pkg"',
            '    ;;'))
        self.assertEqual(errors, [])

    def test_version_bearing_pkgname_interpolation_rejects_plain_glob(self):
        # PAT-1385 P2 fix (round 8): pkgName="Foo ${appNewVersion}.pkg" used
        # to normalise to "Foo *.pkg" (every interpolated variable
        # unconditionally wildcarded), which a manifest declaring
        # relative-path-glob: "Foo *.pkg" matched cleanly -- letting the
        # verifier accept ANY build matching that glob, while the real
        # shell only ever installs the one exact, version-pinned build
        # ${appNewVersion} names. Must now be REJECTED, not silently
        # accepted.
        errors = pkgindmg_contract_errors([
            record("varglob", {
                "mode": "relative-path-glob",
                "patterns": ["Foo *.pkg"],
            }),
        ], engine(
            'varglob)', '    type="pkgInDmg"',
            '    pkgName="Foo ${appNewVersion}.pkg"',
            '    ;;'))
        self.assertTrue(any("version-bearing" in error for error in errors))

    def test_version_bearing_pkgname_interpolation_accepted_with_version_component_locator(self):
        # The correct fix for the shape above: declare an exact
        # version-component locator instead of a loose glob. Same shell
        # pkgName= interpolation, now accepted because the manifest pins
        # the exact build rather than globbing.
        errors = pkgindmg_contract_errors([
            record("varcomp", {
                "mode": "relative-path-version-component",
                "template": "Foo {version_component}.pkg",
                "separator": ".", "component_index": 3,
                "version_source": "resolved-version",
            }),
        ], engine(
            'varcomp)', '    type="pkgInDmg"',
            '    pkgName="Foo ${appNewVersion}.pkg"',
            '    appBuildVersion=$(echo $appNewVersion | cut -d. -f3)',
            '    ;;'))
        self.assertEqual(errors, [])

    def test_multiline_quoted_payload_generalizes_beyond_hardcoded_labels(self):
        # PAT-1385 P2 fix (round 8): multi-line single-quote tracking used
        # to be allowlisted to SHELL_ONLY_EXPLICIT_PKGIN_DMG
        # (fierycommandworkstation, packages) only -- ANY OTHER label with
        # a similar multi-line quoted payload would have that data
        # misparsed as real control flow (pkgName=/if/else/fi-shaped text
        # inside the quoted blob), aborting the ENTIRE parse. "thirdlabel"
        # is a label name that is NOT in that hardcoded set.
        self.assertNotIn("thirdlabel", SHELL_ONLY_EXPLICIT_PKGIN_DMG)
        parsed = parse_installomator_labels(engine(
            'thirdlabel)',
            '    type="pkgInDmg"',
            '    pkgName="Installer.pkg"',
            "    payload=$(curl -s -d '<xml>",
            '    if [[ true ]]; then',
            '        pkgName="Fake.pkg"',
            '    else',
            '        pkgName="AlsoFake.pkg"',
            '    fi',
            "    </xml>' http://example.test)",
            '    ;;',
        ))
        # Only the ONE real, unquoted pkgName= assignment registers -- the
        # quoted pkgName=/if/else/fi text inside the multi-line single
        # quote must be treated as inert data, not parsed (and, before
        # this fix, would have raised "payload selector inside
        # unrecognised or nested conditional" and aborted the whole run).
        self.assertEqual(
            parsed["thirdlabel"].normalised_pkg_names(), ("Installer.pkg",))

    def test_arch_branch_duplicate_assignment_fails_without_set_collapse(self):
        errors = pkgindmg_contract_errors([
            record("archduplicate", {
                "mode": "relative-path-glob-by-arch",
                "patterns_by_arch": {"arm64": "Arm.pkg", "i386": "Intel.pkg"},
            }),
        ], engine(
            'archduplicate)', '    type="pkgInDmg"',
            '    if [[ $(arch) == "arm64" ]]; then',
            '        pkgName="Arm.pkg"', '        pkgName="Arm.pkg"',
            '    elif [[ $(arch) == "i386" ]]; then',
            '        pkgName="Intel.pkg"', '    fi', '    ;;'))
        self.assertTrue(any("exactly one pkgName" in error for error in errors))

    def test_every_current_runtime_pkgname_has_a_typed_locator_and_no_drift(self):
        records = [json.loads(path.read_text())
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        parsed = parse_installomator_labels(
            (ROOT / "engine" / "Installomator.sh").read_text())
        manifest_labels = {rec["label"] for rec in records}
        runtime_explicit = {
            label for label, shell in parsed.items()
            if label in manifest_labels and "pkgInDmg" in shell.shell_types
            and (shell.pkg_name_assignments or shell.pkg_name_assignments_by_arch
                 or shell.pkg_path_pattern_assignments)
        }
        manifest_explicit = {
            rec["label"] for rec in records
            if is_explicit_pkgindmg_locator(rec)
        }
        self.assertEqual(runtime_explicit, manifest_explicit)
        manifest_root_default = {
            rec["label"] for rec in records
            if (rec["type"] == "pkgindmg"
                and not is_explicit_pkgindmg_locator(rec))
        }
        runtime_root_default = {
            label for label, shell in parsed.items()
            if label in manifest_labels and "pkgInDmg" in shell.shell_types
            and not shell.pkg_name_assignments
            and not shell.pkg_name_assignments_by_arch
            and not shell.pkg_path_pattern_assignments
        }
        self.assertTrue(manifest_root_default)
        self.assertEqual(runtime_root_default, manifest_root_default)
        self.assertEqual(pkgindmg_contract_errors(
            records, (ROOT / "engine" / "Installomator.sh").read_text()), [])

    def test_explicit_root_default_object_is_classified_as_root_default(self):
        records = [record("rootpkg", {"mode": "root-unique-pkg"})]
        parsed = parse_installomator_labels(engine(
            'rootpkg)', '    type="pkgInDmg"', '    ;;'))
        manifest_explicit = {
            rec["label"] for rec in records
            if is_explicit_pkgindmg_locator(rec)
        }
        runtime_explicit = {
            label for label, shell in parsed.items()
            if (shell.pkg_name_assignments or shell.pkg_name_assignments_by_arch
                or shell.pkg_path_pattern_assignments)
        }
        self.assertEqual(manifest_explicit, runtime_explicit)
        self.assertEqual(pkgindmg_contract_errors(
            records, engine('rootpkg)', '    type="pkgInDmg"', '    ;;')), [])

    def test_shell_only_explicit_pkgindmg_stanza_fails_reverse_check(self):
        errors = pkgindmg_contract_errors([], engine(
            'shellonly)', '    type="pkgInDmg"',
            '    pkgName="Installer.pkg"', '    ;;'))
        self.assertTrue(any("no manifest record" in error for error in errors))

    def test_declared_shell_only_stanzas_are_safe_but_never_manifest_records(self):
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        labels = {record["label"] for record in records}
        self.assertTrue(SHELL_ONLY_EXPLICIT_PKGIN_DMG.isdisjoint(labels))
        self.assertEqual(pkgindmg_contract_errors(
            records,
            (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8")), [])

    def test_canonical_manifest_has_no_implicit_verifier_only_pkgindmg_records(self):
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        shell = parse_installomator_labels(
            (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8"))
        missing = {record["label"] for record in records
                   if record["type"] == "pkgindmg" and record["label"] not in shell}
        self.assertEqual(missing, set(VERIFIER_ONLY_PKGIN_DMG))

    def test_every_touched_explicit_stanza_matches_its_source_fragment(self):
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        touched = {
            record["label"] for record in records
            if is_explicit_pkgindmg_locator(record)
        } | set(SHELL_ONLY_EXPLICIT_PKGIN_DMG)
        assembled = (ROOT / "engine" / "Installomator.sh").read_text(
            encoding="utf-8")
        for label in touched:
            with self.subTest(label=label):
                fragment = (ROOT / "engine" / "fragments" / "labels"
                            / f"{label}.sh").read_text(encoding="utf-8").strip()
                self.assertIn(fragment, assembled)

    def test_every_known_historical_nested_pkg_label_has_explicit_locator(self):
        records = {
            json.loads(path.read_text())["label"]: json.loads(path.read_text())
            for path in sorted((ROOT / "engine" / "labels").glob("*.json"))
        }
        # These executable shell stanzas historically selected nested or
        # dynamically named payloads. They must never silently fall back to
        # verifier-only recursive discovery.
        for label in {
            "adobeacrobatprodc", "googlesoftwareupdate", "jre8",
            "teamviewer", "teamviewerhost",
        }:
            with self.subTest(label=label):
                self.assertIn("pkg_in_dmg", records[label])
                self.assertNotEqual(
                    records[label]["pkg_in_dmg"]["mode"], "root-unique-pkg")

    def test_endpoint_runtime_and_source_fragment_refuse_ambiguous_payloads(self):
        assembled = parse_pkgindmg_runtime_capabilities(
            (ROOT / "engine" / "Installomator.sh").read_text())
        fragment = parse_pkgindmg_runtime_capabilities(
            (ROOT / "engine" / "fragments" / "functions.sh").read_text())
        self.assertEqual(assembled, fragment)
        self.assertTrue(assembled.root_requires_unique)
        self.assertTrue(assembled.exact_relative_path)
        self.assertTrue(assembled.glob_requires_unique)
        self.assertTrue(assembled.relative_path_glob)
        self.assertTrue(assembled.path_pattern_precedes_root_default)
        self.assertTrue(assembled.pkg_name_dispatch_reachable)

    def test_executed_fragment_dispatch_is_byte_identical_to_shipped_engine(self):
        def functions(text):
            match = re.search(
                r"(?ms)^resolvePkgPathPattern\(\) \{.*?"
                r"^installPkgInDmg\(\) \{.*?^\}\n", text)
            self.assertIsNotNone(match)
            return match.group(0)

        assembled = functions(
            (ROOT / "engine" / "Installomator.sh").read_text())
        fragment = functions(
            (ROOT / "engine" / "fragments" / "functions.sh").read_text())
        self.assertEqual(assembled, fragment)

    def test_new_selector_is_cleared_before_label_dispatch(self):
        for path in (
            ROOT / "engine" / "Installomator.sh",
            ROOT / "engine" / "fragments" / "arguments.sh",
        ):
            with self.subTest(path=path):
                self.assertRegex(
                    path.read_text(), r'pkgPathPattern=""\ncase \$label in')


class Pat1424ReviewGateTests(unittest.TestCase):
    """PAT-1424: an absent pkg_in_dmg block is an unreviewed claim, not a
    blank waiting to be filled. These regressions prove the CI gate that
    keeps that count at zero going forward actually fires -- and keep it
    honest by proving it can fail (see the ticket's own "prove any new test
    can fail" requirement): a genuinely new, never-reviewed pkgindmg record
    must be caught, not silently accepted the way it always was before this
    ticket.
    """

    def test_undocumented_implicit_default_fails_pat_1424_review_gate(self):
        # A brand new pkgindmg record with no pkg_in_dmg block and no entry
        # in UNCONFIRMED_PKGINDMG_ROOT_DEFAULT -- exactly the unreviewed
        # shape PAT-1424 exists to drive to zero. This is the "pre-fix"
        # shape every one of the 68 audited records had before PAT-1424:
        # running this exact scenario against the contract as it stood
        # before this ticket's fix produced ZERO errors (see
        # test_root_default_matches_stanza_without_pkgname's original,
        # pre-PAT-1424 form) -- i.e. this assertion is what would have
        # failed had the gate not been added.
        never_reviewed = record("brandnewpkgindmg")
        self.assertNotIn(
            "brandnewpkgindmg", UNCONFIRMED_PKGINDMG_ROOT_DEFAULT,
            "test fixture must not collide with a real documented label")
        self.assertFalse(is_reviewed_pkgindmg_locator(never_reviewed))
        errors = pkgindmg_contract_errors([never_reviewed], engine(
            'brandnewpkgindmg)', '    type="pkgInDmg"', '    ;;'))
        self.assertTrue(any(
            "brandnewpkgindmg" in e and "PAT-1424" in e for e in errors), errors)

    def test_documented_unconfirmed_reason_satisfies_the_review_gate(self):
        # A label named in UNCONFIRMED_PKGINDMG_ROOT_DEFAULT with a real,
        # on-the-record reason is reviewed -- just not confirmable -- and
        # must not trip the gate a second time.
        for label, reason in UNCONFIRMED_PKGINDMG_ROOT_DEFAULT.items():
            with self.subTest(label=label):
                self.assertTrue(reason.strip())
                self.assertTrue(is_reviewed_pkgindmg_locator(record(label)))

    def test_explicit_pkg_in_dmg_block_satisfies_the_review_gate(self):
        # A confirmed record (PAT-1424 wrote these for all 54 it could
        # positively verify against a real mounted DMG) is reviewed by
        # virtue of the block's presence, regardless of mode.
        self.assertTrue(is_reviewed_pkgindmg_locator(
            record("confirmedpkg", {"mode": "root-unique-pkg"})))

    def test_malformed_pkg_in_dmg_block_does_not_satisfy_the_review_gate(self):
        # Non-author review (PAT-1424 follow-up): presence of the
        # pkg_in_dmg key alone used to be the whole signal, so an empty
        # object, a dict missing/mis-keying mode, an unrecognised mode
        # string, or even a non-dict value all passed this gate silently.
        # validate-labels.py's schema check would catch each of these too,
        # but this predicate must not depend on that -- it is meant to be
        # the thing that cannot be satisfied accidentally.
        malformed_shapes = {
            "empty object": {},
            "empty mode string": {"mode": ""},
            "missing mode key": {"notmode": "x"},
            "non-dict string value": "root-unique-pkg",
            "non-dict list value": ["root-unique-pkg"],
        }
        for shape_name, pkg_in_dmg in malformed_shapes.items():
            with self.subTest(shape=shape_name):
                self.assertFalse(is_reviewed_pkgindmg_locator(
                    record("malformedpkg", pkg_in_dmg)))

    def test_every_pkgindmg_manifest_record_is_reviewed(self):
        # The actual manifest, today: PAT-1424's Done-when. Every real
        # engine/labels/*.json pkgindmg record must be reviewed -- either an
        # explicit pkg_in_dmg block, a documented reason in
        # UNCONFIRMED_PKGINDMG_ROOT_DEFAULT, or a documented known-incorrect
        # entry in KNOWN_INCORRECT_PKGINDMG_DEFAULT -- with zero exceptions.
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        unreviewed = [
            r["label"] for r in records
            if r.get("type") == "pkgindmg" and not is_reviewed_pkgindmg_locator(r)
        ]
        self.assertEqual(unreviewed, [])

    def test_unconfirmed_and_known_incorrect_dicts_are_disjoint(self):
        # Non-author review (P1, this ticket's best finding): "we could not
        # check" and "we checked and it is wrong" are two genuinely
        # different states. A label sitting in both dicts would be
        # ambiguous about which one actually applies to it -- disjointness
        # keeps that impossible, not just currently-true.
        overlap = (set(UNCONFIRMED_PKGINDMG_ROOT_DEFAULT)
                   & set(KNOWN_INCORRECT_PKGINDMG_DEFAULT))
        self.assertEqual(overlap, set())

    def test_known_incorrect_pkgindmg_default_still_satisfies_review_gate(self):
        # A record whose default was checked against a real DMG and found
        # false is reviewed -- more thoroughly than most of the manifest --
        # so it must still satisfy is_reviewed_pkgindmg_locator() rather
        # than failing the gate. Failing it outright would make CI red for
        # an already-tracked defect with zero customer exposure, and CI is
        # dark org-wide right now (PAT-1425): a red gate here would be
        # invisible today and a blocker on unrelated work once CI returns.
        for label in KNOWN_INCORRECT_PKGINDMG_DEFAULT:
            with self.subTest(label=label):
                self.assertTrue(is_reviewed_pkgindmg_locator(record(label)))

    def test_known_incorrect_pkgindmg_default_reasons_name_a_tracking_ticket(self):
        # A "known wrong, no ticket" entry is not an acceptable end state
        # for this dict -- that would quietly turn a real, confirmed defect
        # into something nobody is on the hook to fix. Every reason must
        # name its tracking ticket (a PAT-NNNN reference).
        for label, reason in KNOWN_INCORRECT_PKGINDMG_DEFAULT.items():
            with self.subTest(label=label):
                self.assertRegex(reason, r"PAT-\d+")

    def test_known_incorrect_pkgindmg_default_records_are_not_allowlisted(self):
        # Zero customer exposure is the whole reason this dict is allowed
        # to satisfy the review gate instead of failing it. If a label ever
        # both sits here AND reaches endpoints, that premise is gone.
        manifest = {
            r["label"]: r for r in (
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((ROOT / "engine" / "labels").glob("*.json")))
        }
        for label in KNOWN_INCORRECT_PKGINDMG_DEFAULT:
            with self.subTest(label=label):
                self.assertIn(label, manifest)
                self.assertFalse(is_endpoint_allowlisted(manifest[label]))

    def test_documented_dict_entries_track_a_real_still_implicit_pkgindmg_record(self):
        # PAT-1424 (non-author-review follow-up, P2): nothing previously
        # cross-checked that a key in either dict still corresponds to a
        # real, still-implicit pkgindmg record -- so a label could be
        # renamed, removed, retyped, or made explicit and the entry would
        # sit there as dead weight (or worse, silently exempt a label that
        # no longer means what the entry says). Checked against the REAL
        # engine/labels/ tree, not a synthesised record.
        manifest = {
            r["label"]: r for r in (
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((ROOT / "engine" / "labels").glob("*.json")))
        }
        for dict_name, documented in (
                ("UNCONFIRMED_PKGINDMG_ROOT_DEFAULT", UNCONFIRMED_PKGINDMG_ROOT_DEFAULT),
                ("KNOWN_INCORRECT_PKGINDMG_DEFAULT", KNOWN_INCORRECT_PKGINDMG_DEFAULT)):
            for label in documented:
                with self.subTest(dict=dict_name, label=label):
                    self.assertIn(
                        label, manifest,
                        f"{label} is documented in {dict_name} but no "
                        "engine/labels/*.json record has that label")
                    record_ = manifest[label]
                    self.assertEqual(
                        record_.get("type"), "pkgindmg",
                        f"{label} is documented in {dict_name} but its "
                        f"manifest record's type is {record_.get('type')!r}, "
                        "not 'pkgindmg'")
                    self.assertNotIn(
                        "pkg_in_dmg", record_,
                        f"{label} is documented in {dict_name} but its "
                        "manifest record already carries an explicit "
                        "pkg_in_dmg block -- the entry is stale dead "
                        "weight and should be removed")

    def test_lcadvancedvpnclient_has_explicit_locator_matching_shell_selector(self):
        # PAT-1428: a real mounted DMG (LC-Advanced-VPN-Client-macOS-473-
        # Rel-x86-64.dmg) contains TWO root .pkg files -- "LANCOM Advanced
        # VPN Client.pkg" (the real installer) and "Uninstall.pkg" (a
        # hazard if a root-unique-pkg resolver ever picked it) -- so the
        # implicit root-unique-pkg default is confirmed false for this
        # label. Before PAT-1428's fix this was tracked as an exemption in
        # KNOWN_INCORRECT_PKGINDMG_DEFAULT because no explicit locator
        # could be written without a matching shell-side pkgName. The fix
        # adds pkgName="LANCOM Advanced VPN Client.pkg" to the shell
        # stanza (both the assembled Installomator.sh and its source
        # fragment) and an explicit relative-path-glob manifest locator to
        # match, retiring the exemption. This test proves both halves
        # landed and agree: it fails on the pre-fix tree (no pkg_in_dmg
        # block, label still exempted) and passes once the exemption is
        # gone and manifest/shell are reconciled.
        manifest = {
            r["label"]: r for r in (
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((ROOT / "engine" / "labels").glob("*.json")))
        }
        self.assertIn("lcadvancedvpnclient", manifest)
        record_ = manifest["lcadvancedvpnclient"]
        self.assertEqual(
            record_.get("pkg_in_dmg"),
            {
                "mode": "relative-path-glob",
                "patterns": ["LANCOM Advanced VPN Client.pkg"],
            },
        )
        self.assertNotIn("lcadvancedvpnclient", KNOWN_INCORRECT_PKGINDMG_DEFAULT)
        self.assertTrue(is_reviewed_pkgindmg_locator(record_))

        engine_text = (ROOT / "engine" / "Installomator.sh").read_text(
            encoding="utf-8")
        all_records = list(manifest.values())
        errors = [
            e for e in pkgindmg_contract_errors(all_records, engine_text)
            if "lcadvancedvpnclient" in e
        ]
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
