#!/usr/bin/env python3
"""
test_done_audit.py — PAT-985 unit tests for verifier/done_audit.py.

No network of any kind. The classifier tests drive is_runtime_affecting(),
find_evidence() and classify_issue() directly against hand-written fixture
issues. The orchestration tests drive execute() against a hand-written stub
client (same shape as test_alerting.py's StubLinearClient) so the
"only post when the flagged set changed" behaviour is verified without
touching linear_client.LinearClient or the network.

The live Linear query path (actual GraphQL requests, pagination against a
real workspace, rate limits) is NOT exercised here — there is no token
available in this environment. See done_audit.py's LinearClient additions
in linear_client.py for the query shapes; they are modelled closely on the
existing, already-in-production get_team_id / ensure_label /
find_open_issue_by_marker methods in the same file but have not been run
against the live API.

Run:
    python3 verifier/test_done_audit.py
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import done_audit  # noqa: E402


def _issue(identifier="PAT-100", title="Add nightly backup timer for prod-01",
           description="", labels=None, comments=None,
           completed_at="2026-07-01T00:00:00Z", url=None, **overrides):
    issue = {
        "identifier": identifier,
        "title": title,
        "description": description,
        "labels": labels or [],
        "comments": comments or [],
        "completedAt": completed_at,
        "url": url or f"https://linear.app/patchedim/issue/{identifier}",
    }
    issue.update(overrides)
    return issue


# --------------------------------------------------------------------------
# Required fixtures (per PAT-985 verification instructions)
# --------------------------------------------------------------------------

class RequiredFixtureTests(unittest.TestCase):
    def test_deployed_sha_comment_is_not_flagged(self):
        issue = _issue(
            identifier="PAT-901",
            title="Add nightly backup timer for prod-01",
            description="Adds a systemd timer that snapshots the SQLite state daily.",
            comments=[
                "Deployed abc1234def to patched-prod-01 and confirmed the "
                "timer fires.",
            ],
        )
        result = done_audit.classify_issue(issue)
        self.assertTrue(result["runtime_affecting"])
        self.assertTrue(result["has_evidence"])
        self.assertFalse(result["flagged"])

    def test_only_merged_comment_is_flagged(self):
        issue = _issue(
            identifier="PAT-902",
            title="Harden systemd unit for backup timer",
            description="Locks down the backup.timer unit's credentials.",
            comments=["merged", "PR #123"],
        )
        result = done_audit.classify_issue(issue)
        self.assertTrue(result["runtime_affecting"])
        self.assertFalse(result["has_evidence"])
        self.assertTrue(result["flagged"])
        self.assertIsNotNone(result["suggested_check"])

    def test_docs_only_issue_is_not_flagged_even_with_no_evidence(self):
        issue = _issue(
            identifier="PAT-903",
            title="docs: update README for backup process",
            description="Explains how the nightly backup timer and cron job work.",
            comments=[],
        )
        result = done_audit.classify_issue(issue)
        self.assertFalse(result["runtime_affecting"])
        self.assertFalse(result["flagged"])

    def test_hostname_and_systemctl_output_is_not_flagged(self):
        issue = _issue(
            identifier="PAT-904",
            title="Add credential rotation cron job",
            description="Rotates the R2 credential nightly via cron.",
            comments=[
                "Confirmed on patched-api-01:\n```\n"
                "systemctl status patched-cred-rotate.timer\n"
                "● patched-cred-rotate.timer - active\n```",
            ],
        )
        result = done_audit.classify_issue(issue)
        self.assertTrue(result["runtime_affecting"])
        self.assertTrue(result["has_evidence"])
        self.assertFalse(result["flagged"])


# --------------------------------------------------------------------------
# is_runtime_affecting()
# --------------------------------------------------------------------------

class RuntimeAffectingTests(unittest.TestCase):
    def test_repo_label_is_runtime_affecting(self):
        issue = _issue(title="Tweak internal wording", labels=["repo:updater"])
        runtime, reasons = done_audit.is_runtime_affecting(issue)
        self.assertTrue(runtime)
        self.assertTrue(any("label" in r for r in reasons))

    def test_pure_refactor_with_explicit_no_runtime_effect_is_excluded(self):
        issue = _issue(
            title="Refactor label loader for readability",
            description="Pure refactor, no runtime effect — same output for every input.")
        runtime, _ = done_audit.is_runtime_affecting(issue)
        self.assertFalse(runtime)

    def test_repo_label_overrides_doc_exclusion(self):
        # A docs: prefixed title would normally be excluded, but a repo:*
        # label is a stronger, explicit signal and should win.
        issue = _issue(
            title="docs: note the new deploy step",
            description="documentation only",
            labels=["repo:updater"],
        )
        runtime, reasons = done_audit.is_runtime_affecting(issue)
        self.assertTrue(runtime)
        self.assertTrue(any("label" in r for r in reasons))

    def test_no_signal_is_not_runtime_affecting(self):
        issue = _issue(title="Rename a local variable", description="Cosmetic only.")
        runtime, reasons = done_audit.is_runtime_affecting(issue)
        self.assertFalse(runtime)
        self.assertEqual(reasons, [])

    def test_keyword_stem_matches_suffixed_forms(self):
        # "deploy" must also catch "deployed"/"deployment", not just the
        # bare stem, since \bdeploy\b (trailing boundary) would miss both.
        issue = _issue(title="Automate deployment of the new endpoint config")
        runtime, reasons = done_audit.is_runtime_affecting(issue)
        self.assertTrue(runtime)


# --------------------------------------------------------------------------
# find_evidence() / _comment_evidence()
# --------------------------------------------------------------------------

class EvidenceTests(unittest.TestCase):
    def test_sha_without_deploy_language_is_not_evidence(self):
        # A bare hex-looking token with no deploy language nearby must not
        # count — e.g. quoting an unrelated hash or short PR-adjacent id.
        has_evidence, _ = done_audit.find_evidence(["See commit abc1234 for context."])
        self.assertFalse(has_evidence)

    def test_sha_with_deploy_language_is_evidence(self):
        has_evidence, reasons = done_audit.find_evidence(
            ["Deployed abc1234 to patched-portal-01."])
        self.assertTrue(has_evidence)
        self.assertTrue(any("SHA" in r for r in reasons))

    def test_merged_alone_is_not_evidence(self):
        has_evidence, reasons = done_audit.find_evidence(["merged", "PR #123", "LGTM"])
        self.assertFalse(has_evidence)
        self.assertEqual(reasons, [])

    def test_confirmed_on_phrase_is_evidence(self):
        has_evidence, _ = done_audit.find_evidence(["Confirmed on the box, all good."])
        self.assertTrue(has_evidence)

    def test_exit_0_is_evidence(self):
        has_evidence, _ = done_audit.find_evidence(["Ran the check manually, exit 0."])
        self.assertTrue(has_evidence)


# --------------------------------------------------------------------------
# run_audit() — counts + sort order
# --------------------------------------------------------------------------

class RunAuditTests(unittest.TestCase):
    def test_counts_distinguish_zero_findings_from_nothing_examined(self):
        # A clean sweep (examined > 0, flagged == 0) must be distinguishable
        # from a broken run (examined == 0) purely from the counts.
        issues = [
            _issue(identifier="PAT-1", title="docs: tidy up", comments=[]),
            _issue(identifier="PAT-2", title="Deploy the new agent build",
                   comments=["Deployed cafe123 to patched-prod-01, verified."]),
        ]
        audit = done_audit.run_audit(issues)
        self.assertEqual(audit["counts"]["examined"], 2)
        self.assertEqual(audit["counts"]["runtime_affecting"], 1)
        self.assertEqual(audit["counts"]["flagged"], 0)

    def test_protective_findings_sort_before_non_protective(self):
        other = _issue(identifier="PAT-10", title="Add new endpoint for widgets",
                        completed_at="2026-07-10T00:00:00Z", comments=["merged"])
        protective = _issue(identifier="PAT-11", title="Add backup credential rotation",
                             completed_at="2026-07-01T00:00:00Z", comments=["merged"])
        audit = done_audit.run_audit([other, protective])
        flagged = audit["flagged"]
        self.assertEqual(len(flagged), 2)
        self.assertEqual(flagged[0]["identifier"], "PAT-11")  # protective, first despite older
        self.assertEqual(flagged[1]["identifier"], "PAT-10")


# --------------------------------------------------------------------------
# State hash / marker extraction
# --------------------------------------------------------------------------

class StateHashTests(unittest.TestCase):
    def test_hash_is_order_independent(self):
        a = [{"identifier": "PAT-1"}, {"identifier": "PAT-2"}]
        b = [{"identifier": "PAT-2"}, {"identifier": "PAT-1"}]
        self.assertEqual(done_audit.compute_state_hash(a), done_audit.compute_state_hash(b))

    def test_hash_differs_for_different_sets(self):
        a = [{"identifier": "PAT-1"}]
        b = [{"identifier": "PAT-1"}, {"identifier": "PAT-2"}]
        self.assertNotEqual(done_audit.compute_state_hash(a), done_audit.compute_state_hash(b))

    def test_extract_previous_hash_picks_most_recent_marker(self):
        older_hash = done_audit.compute_state_hash([{"identifier": "PAT-1"}])
        newer_hash = done_audit.compute_state_hash([{"identifier": "PAT-2"}])
        comments = [
            {"body": f"some report\n{done_audit._marker(older_hash)}", "createdAt": "2026-07-01T00:00:00Z"},
            {"body": "unrelated human comment", "createdAt": "2026-07-05T00:00:00Z"},
            {"body": f"some report\n{done_audit._marker(newer_hash)}", "createdAt": "2026-07-10T00:00:00Z"},
        ]
        self.assertEqual(done_audit.extract_previous_hash(comments), newer_hash)

    def test_extract_previous_hash_none_when_absent(self):
        self.assertIsNone(done_audit.extract_previous_hash([{"body": "hi", "createdAt": "x"}]))
        self.assertIsNone(done_audit.extract_previous_hash([]))


# --------------------------------------------------------------------------
# execute() orchestration against a stub client
# --------------------------------------------------------------------------

class StubClient:
    """Records calls; never touches the network. `ticket_comments` seeds
    PAT-985's existing comment history (to simulate a previous run's
    marker); `posted_comments` records anything execute() posts."""

    def __init__(self, issues, ticket_comments=None, ticket_id="ticket-985"):
        self._issues = issues
        self._ticket_comments = list(ticket_comments or [])
        self._ticket_id = ticket_id
        self.posted_comments = []
        self.get_completed_issues_calls = []
        self.get_issue_by_number_calls = []

    def get_completed_issues(self, team_key, completed_after):
        self.get_completed_issues_calls.append((team_key, completed_after))
        return list(self._issues)

    def get_issue_by_number(self, team_key, number):
        self.get_issue_by_number_calls.append((team_key, number))
        if team_key == "PAT" and number == 985:
            return {"id": self._ticket_id, "identifier": "PAT-985",
                     "comments": self._ticket_comments}
        return None

    def create_comment(self, issue_id, body):
        self.posted_comments.append((issue_id, body))
        return "comment-1"


class ExecuteTests(unittest.TestCase):
    def _now(self):
        return datetime(2026, 7, 26, tzinfo=timezone.utc)

    def test_first_run_posts(self):
        issues = [_issue(identifier="PAT-950", title="Add monitor for auth drift",
                          comments=["merged"])]
        client = StubClient(issues, ticket_comments=[])
        result = done_audit.execute(client, "PAT", "PAT-985", 30, now=self._now())
        self.assertTrue(result["posted"])
        self.assertEqual(len(client.posted_comments), 1)
        issue_id, body = client.posted_comments[0]
        self.assertEqual(issue_id, "ticket-985")
        self.assertIn("PAT-950", body)
        self.assertIn(done_audit._marker(result["state_hash"]), body)

    def test_unchanged_flagged_set_does_not_post(self):
        issues = [_issue(identifier="PAT-950", title="Add monitor for auth drift",
                          comments=["merged"])]
        state_hash = done_audit.compute_state_hash(
            done_audit.run_audit(issues)["flagged"])
        prior_comment = {"body": f"old report {done_audit._marker(state_hash)}",
                          "createdAt": "2026-07-20T00:00:00Z"}
        client = StubClient(issues, ticket_comments=[prior_comment])
        result = done_audit.execute(client, "PAT", "PAT-985", 30, now=self._now())
        self.assertFalse(result["posted"])
        self.assertEqual(client.posted_comments, [])
        self.assertEqual(result["previous_hash"], state_hash)
        self.assertEqual(result["state_hash"], state_hash)

    def test_changed_flagged_set_posts(self):
        issues = [_issue(identifier="PAT-950", title="Add monitor for auth drift",
                          comments=["merged"])]
        stale_hash = done_audit.compute_state_hash([{"identifier": "PAT-1"}])
        prior_comment = {"body": f"old report {done_audit._marker(stale_hash)}",
                          "createdAt": "2026-07-20T00:00:00Z"}
        client = StubClient(issues, ticket_comments=[prior_comment])
        result = done_audit.execute(client, "PAT", "PAT-985", 30, now=self._now())
        self.assertTrue(result["posted"])
        self.assertNotEqual(result["state_hash"], stale_hash)

    def test_dry_run_never_posts(self):
        issues = [_issue(identifier="PAT-950", title="Add monitor for auth drift",
                          comments=["merged"])]
        client = StubClient(issues, ticket_comments=[])
        result = done_audit.execute(client, "PAT", "PAT-985", 30, dry_run=True, now=self._now())
        self.assertFalse(result["posted"])
        self.assertEqual(client.posted_comments, [])

    def test_missing_ticket_raises(self):
        client = StubClient([], ticket_comments=[])

        def bad_lookup(team_key, number):
            return None
        client.get_issue_by_number = bad_lookup
        with self.assertRaises(LookupError):
            done_audit.execute(client, "PAT", "PAT-985", 30, now=self._now())

    def test_clean_run_with_no_flags_still_posts_on_first_run(self):
        # examined > 0, flagged == 0 is a legitimate, distinguishable state
        # (see RunAuditTests) and should still post once so the ticket shows
        # a real zero-finding run rather than nothing at all.
        issues = [_issue(identifier="PAT-1", title="docs: tidy up", comments=[])]
        client = StubClient(issues, ticket_comments=[])
        result = done_audit.execute(client, "PAT", "PAT-985", 30, now=self._now())
        self.assertTrue(result["posted"])
        self.assertEqual(result["counts"]["flagged"], 0)
        self.assertEqual(result["counts"]["examined"], 1)


if __name__ == "__main__":
    unittest.main()


class VerificationControlVocabularyTests(unittest.TestCase):
    """Regression guard for a real blind spot.

    The classifier originally keyed only on deployment vocabulary (deploy,
    monitor, backup, systemd, cron...). Validated against known ground truth,
    it missed PAT-495 — "SHA-256 content hash pinning via signed catalogue" —
    which was the single most consequential false Done in this estate: a
    security control that sat inert for five weeks because the endpoint it
    depended on returned 404.

    Controls of this kind describe *what they protect*, not *where they run*,
    and frequently carry no repo: label. That is exactly the class of work
    where a false Done is most dangerous, so it must not regress.
    """

    def test_hash_pinning_via_signed_catalogue_is_runtime_affecting(self):
        issue = _issue(
            identifier="PAT-495",
            title="SHA-256 content hash pinning via signed catalogue (top-30 labels)",
            labels=[],
            comments=["Implemented Phase A. PR #112 merged."],
        )
        self.assertTrue(done_audit.classify_issue(issue)["flagged"])

    def test_allowlist_signing_is_runtime_affecting(self):
        issue = _issue(
            identifier="PAT-976",
            title="LAUNCH BLOCKER: nothing signs the Windows allowlist",
            labels=["repo:updater"],
            comments=["PR merged."],
        )
        self.assertTrue(done_audit.classify_issue(issue)["flagged"])

    def test_sandbox_hardening_is_runtime_affecting(self):
        issue = _issue(
            identifier="PAT-878",
            title="Nightly backup service runs as root with no sandboxing",
            labels=["code-review"],
            comments=["Hardening directives added to the unit. PR #295 merged."],
        )
        self.assertTrue(done_audit.classify_issue(issue)["flagged"])

    def test_docs_prefix_still_wins_over_the_new_vocabulary(self):
        """The wider keyword net must not start flagging documentation.

        This title contains 'deploy', 'signing' and 'rotation' — three
        separate runtime stems — but the docs: prefix is authoritative.
        """
        issue = _issue(
            identifier="PAT-DOC",
            title="docs: record the api-01 deploy and signing key rotation",
            labels=[],
            comments=["Documentation only."],
        )
        self.assertFalse(done_audit.classify_issue(issue)["flagged"])

    def test_verified_deploy_evidence_still_clears_a_signing_ticket(self):
        """Widening the net must not defeat evidence detection."""
        issue = _issue(
            identifier="PAT-SIGNED",
            title="Sign the catalogue in CI",
            labels=["repo:updater"],
            comments=[
                "Deployed and verified on patched-api-01: signing step ran, "
                "signature verified against the pinned key, exit 0."
            ],
        )
        self.assertFalse(done_audit.classify_issue(issue)["flagged"])
