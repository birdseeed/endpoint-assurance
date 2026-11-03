#!/usr/bin/env python3
"""Static regressions for PAT-1233's dashboard-registration hardening.

PAT-987 fixed macos-agent-release.yml's "Register artifact with dashboard"
step to send an authenticated request (Authorization: Bearer <token> pulled
from prod-01, never logged, never a CLI arg) and to fail the job loudly on
any non-2xx response. release-menubar.yml's copy of that step drifted back
to the old, pre-PAT-987 shape: a bare `curl -sk -X POST` with no
Authorization header at all (guaranteed 401) piped through
`|| echo "WARN: ..."`, which swallowed the failure and kept the workflow
green regardless of whether registration actually succeeded (PAT-1233).

This test never contacts Tailscale, prod-01, or the dashboard API. It
asserts the checked-in YAML shape so a future edit to either workflow's
registration step cannot regress to the old silent-failure pattern.
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]

WORKFLOWS = {
    "release-menubar.yml": ROOT / ".github/workflows/release-menubar.yml",
    "macos-agent-release.yml": ROOT / ".github/workflows/macos-agent-release.yml",
}

STEP_NAME = "Register artifact with dashboard"

# The old, buggy shape: an unauthenticated bare curl POST whose failure (or
# non-2xx response) is swallowed by `|| echo`. `-sk` (silent + insecure) with
# no `-K`/config file means no Authorization header is possible in this form.
_OLD_BARE_CURL_RE = re.compile(r"curl\s+-sk\s+-X\s+POST\b")


class DashboardRegistrationPatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.steps = {}
        for label, path in WORKFLOWS.items():
            content = path.read_text()
            workflow = yaml.safe_load(content)
            steps = workflow["jobs"]["publish"]["steps"]
            step = next(s for s in steps if s.get("name") == STEP_NAME)
            cls.steps[label] = step["run"]

    def test_old_unauthenticated_swallowed_failure_pattern_is_absent(self):
        for label, run in self.steps.items():
            with self.subTest(workflow=label):
                self.assertNotRegex(
                    run,
                    _OLD_BARE_CURL_RE,
                    f"{label}: '{STEP_NAME}' still uses the old bare "
                    "`curl -sk -X POST` pattern with no -K config file — "
                    "this sends no Authorization header and 401s.",
                )
                self.assertNotIn(
                    '|| echo "WARN: dashboard registration failed',
                    run,
                    f"{label}: '{STEP_NAME}' still swallows registration "
                    "failure with `|| echo WARN` instead of failing the job.",
                )

    def test_registration_uses_authenticated_config_file_curl(self):
        for label, run in self.steps.items():
            with self.subTest(workflow=label):
                self.assertIn("curl -K", run, f"{label}: expected a curl -K config-file invocation")
                self.assertIn(
                    'header = "Authorization: Bearer',
                    run,
                    f"{label}: expected an Authorization: Bearer header in the curl config",
                )
                self.assertIn(
                    "ADMIN_API_TOKEN",
                    run,
                    f"{label}: expected the admin token to be read from dashboard.env on prod-01",
                )

    def test_registration_explicitly_checks_http_status_and_fails_closed(self):
        for label, run in self.steps.items():
            with self.subTest(workflow=label):
                self.assertIn(
                    "HTTP_CODE=$(curl -K",
                    run,
                    f"{label}: expected HTTP_CODE to be captured from the curl response",
                )
                self.assertIn(
                    '[ "$HTTP_CODE" -lt 200 ]',
                    run,
                    f"{label}: expected an explicit lower-bound 2xx check",
                )
                self.assertIn(
                    '[ "$HTTP_CODE" -ge 300 ]',
                    run,
                    f"{label}: expected an explicit upper-bound 2xx check",
                )
                # The non-2xx branch must actually fail the job.
                status_check = run.index('[ "$HTTP_CODE" -lt 200 ]')
                fail_branch = run[status_check:]
                self.assertIn(
                    "exit 1",
                    fail_branch[: fail_branch.index("echo \"Dashboard registration succeeded")],
                    f"{label}: the non-2xx branch must exit 1 rather than continue",
                )

    def test_menubar_payload_uses_menubar_platform_value(self):
        run = self.steps["release-menubar.yml"]
        self.assertIn("'platform':'macos-menubar'", run)

    def test_macos_agent_payload_uses_macos_platform_value(self):
        run = self.steps["macos-agent-release.yml"]
        self.assertIn("'platform':'macos'", run)


if __name__ == "__main__":
    unittest.main()
