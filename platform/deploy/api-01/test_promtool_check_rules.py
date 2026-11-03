"""PAT-1423: the committed rules file must pass `promtool check rules` as
committed -- this is the same gate deploy-prometheus-rules.sh runs before
installing the file on api-01 (see test_deploy_prometheus_rules.py, which
exercises that gate logic against a faked promtool so it isn't skipped in
CI). This test runs the REAL promtool against the REAL committed file, so it
skips explicitly -- printing why, via unittest's skip mechanism, which shows
up as "skipped" rather than "passed" in test output -- when promtool isn't
on PATH, instead of silently reporting green for a check that never ran.

Non-author review, PAT-1423 round 4: deploy-prometheus-rules.sh parses
promtool's "SUCCESS: N rules found" line with a regex and fails the whole
deploy loudly if it doesn't match (deliberately -- see that script's own
comment on EXPECTED_RULE_COUNT). But test_deploy_prometheus_rules.py's tests
of that parse all drive a FAKE promtool that emits exactly the expected
string, so a real promtool version bump changing that format would sail
through the whole suite and only be discovered live, mid-deploy. This test
closes that gap: it runs the real promtool against the real committed file
and asserts its actual output both matches the exact regex
deploy-prometheus-rules.sh uses, and that the extracted count is correct --
checked against an independent count of `- alert:`/`- record:` entries in
the file itself, not against promtool's own self-report, so this can't pass
by comparing promtool to promtool. A promtool format change now shows up as
a visible, named test failure here instead of a deploy blocking at the
worst possible moment.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "api-vps-artefacts" / "alerting" / "prometheus-rules-patched.yml"
RULES_TEST_FILE = REPO_ROOT / "api-vps-artefacts" / "alerting" / "prometheus-rules-patched.test.yml"

# Must stay byte-for-byte in sync with the sed pattern in
# deploy/api-01/deploy-prometheus-rules.sh's EXPECTED_RULE_COUNT line.
RULE_COUNT_PATTERN = re.compile(r"SUCCESS: ([0-9]+) rules found")


class PromtoolCheckRulesTests(unittest.TestCase):
    def test_rules_fixture_has_a_non_vacuous_positive_alert_case(self):
        """A syntactically valid empty fixture would let the deploy gate pass
        without evaluating an alert. Require the committed fixture to load the
        real rules and expect DeviceCredentialRejected to fire at least once."""
        source = RULES_TEST_FILE.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^rule_files:\n\s+-\s+prometheus-rules-patched\.yml$")
        self.assertRegex(
            source,
            r"(?s)alert_rule_test:.*?alertname:\s*DeviceCredentialRejected.*?exp_alerts:\s*\n\s*-\s+exp_labels:",
        )

    def test_committed_rules_test_file_passes_promtool(self):
        promtool = shutil.which("promtool")
        if not promtool:
            self.skipTest("promtool not found on PATH -- cannot validate rule evaluations")
        self.assertTrue(RULES_TEST_FILE.is_file(), f"missing rules test file: {RULES_TEST_FILE}")
        result = subprocess.run(
            [promtool, "test", "rules", str(RULES_TEST_FILE)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(
            result.returncode, 0,
            f"promtool test rules failed:\nstdout={result.stdout}\nstderr={result.stderr}",
        )

    def test_committed_rules_file_passes_promtool_check(self):
        promtool = shutil.which("promtool")
        if not promtool:
            self.skipTest(
                "promtool not found on PATH -- skipping explicitly rather than "
                "silently passing a check that never ran (PAT-1423)"
            )

        self.assertTrue(RULES_FILE.is_file(), f"missing rules file: {RULES_FILE}")
        result = subprocess.run(
            [promtool, "check", "rules", str(RULES_FILE)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(
            result.returncode, 0,
            f"promtool check rules failed:\nstdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertIn("SUCCESS", result.stdout)

    def test_real_promtool_output_matches_the_deploy_scripts_parse_regex(self):
        """The exact regression this closes: deploy-prometheus-rules.sh's
        EXPECTED_RULE_COUNT parse only ever gets exercised against a FAKE
        promtool elsewhere in this test suite. Here it runs against the
        real binary's real output, so a promtool version bump that changes
        this wording is caught here -- as a named, visible test failure --
        rather than as a live deploy blocked on "could not determine the
        validated rule count"."""
        promtool = shutil.which("promtool")
        if not promtool:
            self.skipTest(
                "promtool not found on PATH -- skipping explicitly rather than "
                "silently passing a check that never ran (PAT-1423)"
            )

        result = subprocess.run(
            [promtool, "check", "rules", str(RULES_FILE)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        match = RULE_COUNT_PATTERN.search(result.stdout)
        self.assertIsNotNone(
            match,
            "real promtool's output did not match the pattern "
            f"deploy-prometheus-rules.sh parses ({RULE_COUNT_PATTERN.pattern!r}) -- "
            f"a promtool version bump has changed the success-message format. "
            f"Actual stdout was:\n{result.stdout}",
        )
        parsed_count = int(match.group(1))

        # Independent ground truth: count top-level rule entries directly in
        # the YAML source, NOT via promtool -- comparing promtool's parsed
        # count to promtool's own report would prove nothing.
        rule_lines = re.findall(
            r"^\s*-\s+(?:alert|record):", RULES_FILE.read_text(encoding="utf-8"), re.MULTILINE
        )
        expected_count = len(rule_lines)
        self.assertGreater(expected_count, 0, "independent rule count came back zero -- counting regex is broken")
        self.assertEqual(
            parsed_count, expected_count,
            f"promtool reported {parsed_count} rules but the file independently "
            f"contains {expected_count} '- alert:'/'- record:' entries",
        )


if __name__ == "__main__":
    unittest.main()
