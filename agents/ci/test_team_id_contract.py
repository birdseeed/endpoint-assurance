#!/usr/bin/env python3
"""PAT-1429 manifest expected_team_id vs Installomator expectedTeamID= contract.

engine/labels/veracrypt.json and engine/labels/veracrypt-fuse-t.json's
`expected_team_id` were each independently reviewed and corrected under their
own ticket (PAT-1282, PAT-1283 -- corrected to HLTN5GLG99, the real VeraCrypt
maintainer's Team ID, confirmed against live downloaded artifacts) while
engine/Installomator.sh's own `expectedTeamID=` for both labels had drifted to
the stale pre-correction value (Z933746L2S) -- and nothing in CI compared the
two, so a manifest record that was RIGHT still failed closed on every real
install, silently, because the shell -- what actually runs on endpoints --
was wrong. A third, unrelated ticket (PAT-1272, logseq) turned out to have
drifted the exact same way. Three separate tickets each fixing the manifest
half and silently missing the shell half is a systemic pattern, not three
coincidences -- see team_id_contract_errors()'s own docstring in
installomator_pkg_contract.py for the fuller argument. That function closes
the gap, in the same shape pkgindmg_contract_errors() already uses for the
payload locator: parse the one real shell dispatch as data, never execute it,
compare it against the manifest's own claim, fail closed on drift.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installomator_pkg_contract import (
    ShellLabel,
    _effective_team_id,
    is_endpoint_allowlisted,
    parse_installomator_labels,
    team_id_contract_errors,
)


ROOT = Path(__file__).resolve().parent.parent


def record(label="widget", *, expected_team_id="ABCDEFGHIJ", allowlisted=False):
    return {
        "label": label,
        "type": "dmg",
        "expected_team_id": expected_team_id,
        "patched": {"allowlisted": allowlisted},
    }


def engine(*arms):
    return "\n".join(("case $label in", *arms, "esac", ""))


class DisagreementTests(unittest.TestCase):
    """The core drift check: real veracrypt/veracrypt-fuse-t shape."""

    def test_fails_on_team_id_disagreement(self):
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ")],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ZZZZZZZZZZ"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("widget", errors[0])
        self.assertIn("ABCDEFGHIJ", errors[0])
        self.assertIn("ZZZZZZZZZZ", errors[0])

    def test_passes_when_team_ids_agree(self):
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ")],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ABCDEFGHIJ"', '    ;;'))
        self.assertEqual(errors, [])

    def test_disagreement_fails_even_when_not_allowlisted(self):
        # veracrypt/veracrypt-fuse-t are themselves NOT allowlisted today --
        # a CONFIRMED disagreement between two static literals must never be
        # suppressed by allowlisted status. Only the "cannot confirm either
        # way" edge cases below are gated on it.
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=False)],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ZZZZZZZZZZ"', '    ;;'))
        self.assertEqual(len(errors), 1)

    def test_reproduces_the_real_veracrypt_drift_shape(self):
        # The exact real values from PAT-1429's real-artifact sweep.
        errors = team_id_contract_errors(
            [record("veracrypt", expected_team_id="HLTN5GLG99"),
             record("veracrypt-fuse-t", expected_team_id="HLTN5GLG99")],
            engine(
                'veracrypt-fuse-t)', '    type="pkgInDmg"',
                '    expectedTeamID="Z933746L2S"', '    ;;',
                'veracrypt|\\', 'veracrypt-macfuse)', '    type="pkgInDmg"',
                '    expectedTeamID="Z933746L2S"', '    ;;'))
        self.assertEqual(len(errors), 2)
        flagged = {e.split(":")[0] for e in errors}
        self.assertEqual(flagged, {"veracrypt", "veracrypt-fuse-t"})
        for e in errors:
            self.assertIn("HLTN5GLG99", e)
            self.assertIn("Z933746L2S", e)


class EdgeCaseTests(unittest.TestCase):
    """PAT-1429: absence must never silently read as agreement."""

    def test_manifest_with_no_shell_stanza_is_silent_when_not_allowlisted(self):
        errors = team_id_contract_errors(
            [record("ghost", expected_team_id="ABCDEFGHIJ", allowlisted=False)],
            engine('other)', '    type="dmg"', '    expectedTeamID="ABCDEFGHIJ"', '    ;;'))
        self.assertEqual(errors, [])

    def test_manifest_with_no_shell_stanza_fails_when_allowlisted(self):
        # A record that actually reaches customer endpoints (allowlisted)
        # but has NOTHING enforcing its Team ID claim at all must fail --
        # this is exactly the shape absence-as-agreement would hide.
        errors = team_id_contract_errors(
            [record("ghost", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            engine('other)', '    type="dmg"', '    expectedTeamID="ABCDEFGHIJ"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("ghost", errors[0])
        self.assertIn("no Installomator label stanza", errors[0])

    def test_shell_stanza_with_no_manifest_record_is_not_compared(self):
        # Only labels present in BOTH places are compared at all -- the
        # manifest is a deliberate subset of Installomator's full label set.
        errors = team_id_contract_errors(
            [],
            engine('shellonly)', '    type="dmg"',
                   '    expectedTeamID="ABCDEFGHIJ"', '    ;;'))
        self.assertEqual(errors, [])

    def test_absent_expected_team_id_is_silent_when_not_allowlisted(self):
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=False)],
            engine('widget)', '    type="dmg"', '    ;;'))
        self.assertEqual(errors, [])

    def test_absent_expected_team_id_fails_when_allowlisted(self):
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            engine('widget)', '    type="dmg"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("no expectedTeamID assignment", errors[0])

    def test_empty_expected_team_id_is_not_treated_as_agreement(self):
        # expectedTeamID="" must never read as "agrees" with anything,
        # including a manifest record that (invalidly) also carried "".
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="", allowlisted=True)],
            engine('widget)', '    type="dmg"', '    expectedTeamID=""', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("empty", errors[0])

    def test_empty_expected_team_id_silent_when_not_allowlisted(self):
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=False)],
            engine('widget)', '    type="dmg"', '    expectedTeamID=""', '    ;;'))
        self.assertEqual(errors, [])

    def test_dynamic_expected_team_id_cannot_be_confirmed(self):
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="$SOME_VAR"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("shell expansion", errors[0])

    def test_ambiguous_multiple_assignment_is_not_treated_as_agreement(self):
        # A genuine double assignment within ONE stanza -- no evidence of an
        # absorbed neighbour (no indented or ';;'-glued arm anywhere in the
        # body) -- must never be silently resolved to "the last one wins"
        # and compared as if unambiguous, and must NOT be misattributed to
        # the arm-boundary parser gap (see the distinct test below for that
        # shape).
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ABCDEFGHIJ"',
                   '    expectedTeamID="ZZZZZZZZZZ"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("more than once", errors[0])
        self.assertNotIn("arm-boundary parsing gap", errors[0])

    def test_glued_arm_boundary_is_now_fixed_not_merely_flagged(self):
        # PAT-1432: this used to be the real corpus shape (editshare-connect
        # absorbing `;;editshare-flowstory)`, glued directly onto the
        # preceding ';;' with no separating whitespace) that PAT-1429 could
        # only detect and FLAG via team_id_boundary_gap_suspected, not fix
        # -- see the now-superseded assertions this test used to make (a
        # single "ambiguous: possible arm-boundary parsing gap" error). The
        # arm-boundary walker now recognises this spelling as a real
        # boundary, so 'widget' and 'neighbour' parse as two independent,
        # correct stanzas: no ambiguity, no error, for either label.
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True),
             record("neighbour", expected_team_id="ZZZZZZZZZZ", allowlisted=True)],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ABCDEFGHIJ"',
                   '    ;;neighbour)', '    type="dmg"',
                   '    expectedTeamID="ZZZZZZZZZZ"', '    ;;'))
        self.assertEqual(errors, [])

    def test_indented_arm_boundary_is_now_fixed_not_merely_flagged(self):
        # PAT-1432: the other real corpus shape -- an INDENTED absorbed arm
        # (the real `    displaynote)`, `    supportapp)`) -- is likewise
        # now a recognised boundary instead of merely a flagged ambiguity.
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True),
             record("neighbour", expected_team_id="ZZZZZZZZZZ", allowlisted=True)],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ABCDEFGHIJ"',
                   '    ;;', '    neighbour)', '    type="dmg"',
                   '    expectedTeamID="ZZZZZZZZZZ"', '    ;;'))
        self.assertEqual(errors, [])

    def test_nested_case_own_arm_is_not_misattributed_as_a_boundary_gap(self):
        # PAT-1432, second fix: an EARLIER version of this fix taught only
        # the real arm-boundary walker about nested `case ... in ... esac`
        # depth, and left the separate _body_suggests_absorbed_arm_boundary()
        # diagnostic checking the same two shapes WITHOUT that awareness --
        # so it kept misattributing a stanza's own nested-case arm (e.g. the
        # real macports' bare `25)`, `24)`, ...) as evidence of an absorbed
        # NEIGHBOUR, even after the real walker had already correctly parsed
        # macports into one ungapped stanza with a single expectedTeamID.
        # Caught by re-running against the real corpus rather than trusting
        # "should be unreachable": `boundary-gap suspected now: ['macports']`.
        # This exercises exactly that shape synthetically: a genuine,
        # unrelated double expectedTeamID assignment inside a stanza that
        # ALSO happens to contain a nested case block whose own arm
        # (`neighbour)`) would -- pre-fix -- have tripped the diagnostic.
        # Now that the diagnostic reuses the walker's own nested-case-depth
        # tracking, this must resolve to the plain "assigned more than once"
        # message, NOT the "arm-boundary parsing gap" one: there is no
        # absorbed neighbour here, only a real duplicate assignment, and the
        # nested case's own arm must not be mistaken for evidence of one.
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            engine('widget)', '    type="dmg"',
                   "    case $(uname -r) in",
                   '        neighbour)',
                   '            somevar=1',
                   '            ;;',
                   '    esac',
                   '    expectedTeamID="ABCDEFGHIJ"',
                   '    expectedTeamID="ZZZZZZZZZZ"',
                   '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("more than once", errors[0])
        self.assertNotIn("arm-boundary parsing gap", errors[0])

    def test_effective_team_id_still_renders_the_boundary_gap_message_directly(self):
        # PAT-1432: once _body_suggests_absorbed_arm_boundary() was made to
        # share the real walker's own nested-case-depth tracking (see the
        # test above), team_id_boundary_gap_suspected became unreachable via
        # ANY input to parse_installomator_labels() -- not just the real
        # corpus. Proof: the diagnostic now replays, line-for-line, the
        # exact same boundary decision the walker itself already made while
        # building `body` (same matcher, same depth counter, same lines, same
        # order). A line that would trip the diagnostic at depth 0 would
        # therefore already have made the walker stop appending before that
        # line was ever added to `body` -- so no body the walker can produce
        # ever contains a line the diagnostic would flag. The
        # "arm-boundary parsing gap" branch in _effective_team_id() is
        # consequently dead code with respect to the real parser today. Per
        # Andy's call, the machinery (flag, branch, and this diagnostic) is
        # kept anyway as a fail-closed guard -- so this test exercises the
        # message-differentiation logic directly, on a hand-built
        # ShellLabel, bypassing the parser entirely, to keep it covered
        # rather than letting it go silently untested along with the flag.
        shell = ShellLabel(
            stanza_labels=("widget",),
            shell_types=("dmg",),
            pkg_name_assignments=(),
            team_id_assignments=('"ABCDEFGHIJ"', '"ZZZZZZZZZZ"'),
            team_id_boundary_gap_suspected=True,
        )
        value, error = _effective_team_id(shell)
        self.assertIsNone(value)
        self.assertIn("more than once", error)
        self.assertIn("arm-boundary parsing gap", error)
        self.assertIn("NEIGHBOURING", error)

    def test_trailing_inline_comment_is_not_a_false_positive(self):
        # PAT-1429 (non-author-review follow-up, round 2): _TEAM_ID_ASSIGN_RE
        # captures the rest of the physical line, so a trailing shell
        # comment used to be folded into the "value" and compared byte-for-
        # byte against the manifest -- a reachable false-positive drift
        # report on a perfectly correct, agreeing assignment. Confirmed
        # against real zsh that `#` only starts a comment when preceded by
        # whitespace (see _team_id_literal()'s module-level comment) --
        # this exercises exactly that shape for both the quoted and bare
        # literal forms.
        self.assertEqual(
            team_id_contract_errors(
                [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
                engine('widget)', '    type="dmg"',
                       '    expectedTeamID="ABCDEFGHIJ" # PAT-1282', '    ;;')),
            [])
        self.assertEqual(
            team_id_contract_errors(
                [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
                engine('widget)', '    type="dmg"',
                       '    expectedTeamID=ABCDEFGHIJ # PAT-1282', '    ;;')),
            [])

    def test_comment_glued_directly_onto_closing_quote_is_not_silently_stripped(self):
        # Real zsh: `expectedTeamID="ABC"#comment` (no whitespace before the
        # `#`) does NOT start a comment -- it assigns the literal
        # "ABC#comment" (verified empirically: `foo="bar"#baz` -> foo is
        # "bar#baz", not "bar"). This must never be misread as "ABC" with a
        # silently-stripped comment; the correct outcome is "cannot
        # confirm" (fails closed), not a wrong-but-plausible-looking value.
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID="ABCDEFGHIJ"#comment', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("cannot confirm", errors[0])

    def test_unquoted_bare_team_id_literal_is_confirmed(self):
        # A real, if unusual, zsh shape (epsonprintlayout's own
        # expectedTeamID=TXAEAV5RN4, no quotes) -- must still be recognised
        # as a plain literal, not treated as unconfirmable.
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="TXAEAV5RN4")],
            engine('widget)', '    type="dmg"',
                   '    expectedTeamID=TXAEAV5RN4', '    ;;'))
        self.assertEqual(errors, [])

    def test_sentinel_shell_values_are_not_special_cased_and_still_drift(self):
        # Real upstream Installomator sentinels like expectedTeamID="Software
        # Update" are legitimate shell text for labels with no manifest
        # record today (see PAT-1429's real-corpus survey). If a manifest
        # record for such a label were ever added, it must be treated as a
        # normal, confirmed disagreement -- not silently exempted for being
        # a known sentinel shape.
        errors = team_id_contract_errors(
            [record("softwareupdatelabel", expected_team_id="ABCDEFGHIJ")],
            engine('softwareupdatelabel)', '    type="dmg"',
                   '    expectedTeamID="Software Update"', '    ;;'))
        self.assertEqual(len(errors), 1)
        self.assertIn("Software Update", errors[0])

    def test_unparsed_stanza_is_silent_when_not_allowlisted_but_fails_when_allowlisted(self):
        # A pkgInDmg stanza whose payload-selector body is malformed sets
        # ShellLabel.parse_error; team_id_contract_errors() must not fall
        # through to normalised_pkg_names()-style guessing for that stanza.
        bad_engine = engine(
            'widget)', '    type="pkgInDmg"',
            '    if [[ $(arch) == "arm64" ]]; then',
            # pkgPathPattern inside ANY conditional is unconditionally
            # unsupported (see parse_installomator_labels()) -- guaranteed
            # to raise ValueError and set ShellLabel.parse_error, unlike a
            # second pkgName inside the same arch branch (which is merely
            # collected, not rejected, by this parser).
            '        pkgPathPattern="Arm/Installer.pkg"',
            '    fi', '    expectedTeamID="ABCDEFGHIJ"', '    ;;')
        self.assertEqual(
            team_id_contract_errors(
                [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=False)],
                bad_engine),
            [])
        errors = team_id_contract_errors(
            [record("widget", expected_team_id="ABCDEFGHIJ", allowlisted=True)],
            bad_engine)
        self.assertEqual(len(errors), 1)
        self.assertIn("failed to parse", errors[0])


class RealManifestRegressionTests(unittest.TestCase):
    """Regression gate against the actual shipped manifest and engine."""

    def test_check_flags_the_real_pre_fix_veracrypt_drift(self):
        # Reconstruct the exact pre-fix state (the stale shell value this
        # ticket corrects) from the real, currently-fixed engine text, and
        # confirm the check flags it with the real values -- proves the
        # check can fail, per PAT-1429's mandatory verification.
        engine_text = (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8")
        pre_fix_engine_text = engine_text.replace(
            'expectedTeamID="HLTN5GLG99"', 'expectedTeamID="Z933746L2S"')
        self.assertNotEqual(engine_text, pre_fix_engine_text)
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        errors = team_id_contract_errors(records, pre_fix_engine_text)
        flagged = {e.split(":")[0] for e in errors}
        self.assertIn("veracrypt", flagged)
        self.assertIn("veracrypt-fuse-t", flagged)
        for e in errors:
            if e.startswith("veracrypt"):
                self.assertIn("HLTN5GLG99", e)
                self.assertIn("Z933746L2S", e)

    def test_real_manifest_has_no_confirmed_team_id_disagreement(self):
        # The real regression gate: every manifest record whose label has a
        # parseable shell stanza with a single, static expectedTeamID must
        # agree with it. This is allowed to still report labels that cannot
        # be confirmed either way (no shell stanza, ambiguous parse, etc --
        # see team_id_contract_errors()'s docstring) as long as none of them
        # is allowlisted; only a CONFIRMED disagreement, or an allowlisted
        # record that cannot be confirmed at all, fails this test.
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        engine_text = (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8")
        errors = team_id_contract_errors(records, engine_text)
        drift_errors = [e for e in errors if "Team ID drift" in e]
        # PAT-1429's first real run against the full manifest found three
        # confirmed drifts, all now fixed: veracrypt (PAT-1282) and
        # veracrypt-fuse-t (PAT-1283) under this ticket, and logseq
        # (PAT-1272, fixed after Andy independently verified that ticket's
        # own corroboration chain -- the manifest's K378MFWK59 was a
        # reviewed cert-rotation fix that shipped in PR #470). All three are
        # the same shape: an independently reviewed manifest correction
        # whose matching shell update never landed. No confirmed
        # disagreement should remain in the real manifest.
        self.assertEqual(drift_errors, [])

    def test_no_allowlisted_record_has_an_unconfirmable_team_id(self):
        # Belt-and-braces: every record that actually reaches a customer
        # endpoint today must have a shell stanza confirming its Team ID
        # one way or the other -- "cannot confirm" is only ever tolerated
        # for non-allowlisted (not-yet-live) records.
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        allowlisted_labels = {r["label"] for r in records if is_endpoint_allowlisted(r)}
        self.assertTrue(allowlisted_labels)
        engine_text = (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8")
        errors = team_id_contract_errors(records, engine_text)
        unconfirmable = [e for e in errors if "Team ID drift" not in e]
        self.assertEqual(unconfirmable, [])

    def test_the_thirteen_label_no_shell_stanza_survey_is_stable(self):
        # PAT-1429's real-corpus survey originally found 16 manifest records
        # with no shell stanza the shared arm-boundary parser could locate
        # at all -- 13 genuinely absent from engine/Installomator.sh (each
        # carrying its own "Auto-converted... requires human review" note),
        # plus 3 (displaynote, egnyte, supportapp) that DID have a real
        # runtime stanza the parser failed to recognise as a boundary (an
        # indented arm, or one glued onto the preceding ';;' on the same
        # physical line). PAT-1432 taught the arm-boundary walker both
        # missed spellings (and, while at it, confirmed -- by a
        # programmatic sweep of the whole file, not by eye -- that those
        # are the only two spellings the real corpus actually uses), so
        # those 3 now parse into real stanzas and move OUT of this set; the
        # other 13 are untouched (still genuinely absent from the shell,
        # still each carrying its own human-review note) and stay IN it.
        # None of the 13 is allowlisted today, so none fails the gate --
        # this test pins the set so a NEWLY allowlisted member of it is
        # caught by a human reading a diff, not discovered only when the
        # gate turns red. If this test breaks because the set changed, that
        # is real signal: re-survey rather than just updating the constant.
        expected = {
            "antcon", "blackhole64", "firefox-da",
            "firefox-intl", "firefoxpkg-intl", "gemini", "mackiemasterfader",
            "realvnconedemandassist", "salesforcesfdx",
            "thunderbird-intl", "toonboomharmony2024", "tortalk-en", "tortalk-se",
        }
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted((ROOT / "engine" / "labels").glob("*.json"))]
        engine_text = (ROOT / "engine" / "Installomator.sh").read_text(encoding="utf-8")
        shell_labels = parse_installomator_labels(engine_text)
        manifest_labels = {r["label"] for r in records}
        no_shell = {label for label in manifest_labels if label not in shell_labels}
        self.assertEqual(no_shell, expected)
        for label in no_shell:
            with self.subTest(label=label):
                rec = next(r for r in records if r["label"] == label)
                self.assertFalse(is_endpoint_allowlisted(rec))


if __name__ == "__main__":
    unittest.main()
