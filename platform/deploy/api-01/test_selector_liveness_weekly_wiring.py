"""PAT-1423 item 4: selector-liveness (PAT-1389) must actually be wired into
a weekly scheduled workflow run against the deployed rules file and live
Prometheus -- its own README names this as "a deliberate follow-up, not an
oversight", and this is the regression check that the follow-up landed and
stays landed.

Reads the real .github/workflows/selector-liveness-weekly.yml from this
checkout (not a synthetic fixture) and asserts: a schedule trigger exists,
the job builds and runs the real selector-liveness binary, it queries the
DEPLOYED rules file directly on api-01 (not a copy, not the repo's own
checked-out file), and a non-zero exit from the tool is never swallowed.

PAT-1423 round 3 (non-author review): the workflow originally queried
Prometheus directly from the ubuntu-latest runner at
http://patched-api-01.example-tailnet.ts.net:9090 over Tailscale. The
version-controlled tailnet policy (api-vps-artefacts/tailscale-acl.json)
grants tag:ci -> tag:api on :22 and :8443 only -- nothing grants :9090 -- so
that request would fail on every scheduled run, and with Actions dark
(PAT-1425) that failure would not surface for a long time: a safety net
that never runs, the exact shape this whole ticket exists to close. Fixed
by running selector-liveness ON api-01 over the existing SSH channel, so it
queries Prometheus over loopback. test_does_not_reach_prometheus_directly_
over_the_tailnet is the regression check for that specifically, so this
cannot quietly regress back into needing an ACL grant.

Deliberately regex/string-based rather than a full YAML parse: PyYAML isn't
a dependency anywhere else in this repo's Python tooling (no requirements
file, nothing else imports it), and check_binary_inventory.py's own
workflow_step() helper already establishes this repo's convention of
reading workflow files as text for assertions like these -- adding a new
third-party import here would risk `unittest discover` failing to even
collect tests (an ImportError during collection fails the whole run, not
just this file) on a runner where PyYAML isn't preinstalled.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "selector-liveness-weekly.yml"
TAILNET_PROM_URL = "http://patched-api-01.example-tailnet.ts.net:9090"


class SelectorLivenessWeeklyWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_workflow_file_exists(self):
        self.assertTrue(WORKFLOW_PATH.is_file(), f"missing {WORKFLOW_PATH}")

    def test_has_a_weekly_schedule_trigger(self):
        self.assertIn("schedule:", self.raw)
        crons = re.findall(r"cron:\s*'([^']+)'", self.raw)
        self.assertTrue(crons, "no cron entries found under schedule:")
        # Weekly: must specify a single day-of-week, not '*' (every day).
        for cron in crons:
            fields = cron.split()
            self.assertEqual(len(fields), 5, f"cron {cron!r} is not a 5-field crontab expression")
            dow_field = fields[-1]
            self.assertNotEqual(dow_field, "*", f"cron {cron!r} is not weekly (day-of-week is '*')")
        # workflow_dispatch lets it be run manually too, matching this
        # repo's e2e-windows.yml convention for scheduled jobs.
        self.assertIn("workflow_dispatch:", self.raw)

    def test_builds_the_real_selector_liveness_binary(self):
        self.assertIn("api-vps-artefacts/alerting/selector-liveness", self.raw)
        self.assertIn("go build -o selector-liveness .", self.raw)

    def test_binary_is_staged_onto_api_01_over_ssh(self):
        stage_step = self.raw[
            self.raw.index("Stage selector-liveness on api-01"):
            self.raw.index("Run selector-liveness on api-01")
        ]
        self.assertIn("root@patched-api-01:/opt/patched-selector-liveness-check/selector-liveness", stage_step)
        self.assertIn("scp -i /tmp/api01_key", stage_step)
        self.assertIn("mkdir -p /opt/patched-selector-liveness-check", stage_step)

    def test_runs_against_the_deployed_rules_file_directly_on_the_box(self):
        # Must read the literal deployed file on api-01 -- not a copy
        # fetched down to the runner first, and not the repo's own checked-
        # out api-vps-artefacts/alerting/prometheus-rules-patched.yml, which
        # would defeat the point of checking what's actually deployed,
        # independent of items 2-3 (deploy-prometheus-rules.sh, the
        # maintenance-facts sidecar) actually working correctly.
        run_step = self.raw[
            self.raw.index("Run selector-liveness on api-01"):
            self.raw.index("Clean up staged binary")
        ]
        self.assertIn("-rules /etc/prometheus/rules/patched.yml", run_step)
        self.assertNotIn("-rules ../prometheus-rules-patched.yml", self.raw)
        self.assertNotIn("-rules prometheus-rules-patched.yml", self.raw)
        # No scp of a rules-file copy anywhere in this step -- the whole
        # point is reading the live file in place.
        self.assertNotIn("scp", run_step)

    def test_does_not_reach_prometheus_directly_over_the_tailnet(self):
        """PAT-1423 round 3: tag:ci has no ACL grant to tag:api:9090 (only
        :22 since PAT-2246 -- see api-vps-artefacts/tailscale-acl.json). This
        workflow must never attempt to query Prometheus at the Tailscale
        MagicDNS hostname directly from the runner -- only over loopback,
        from inside an SSH session running ON api-01.

        Checked against code lines only: the header comment legitimately
        names the old tailnet URL in prose while explaining why round 3
        moved away from it, which would otherwise false-positive here."""
        code_lines = [
            line for line in self.raw.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        code = "\n".join(code_lines)
        self.assertNotIn(TAILNET_PROM_URL, code)
        self.assertNotIn("example-tailnet.ts.net:9090", code)
        # The only place :9090 may appear at all is inside the SSH remote
        # command, targeting loopback.
        for line in code_lines:
            if ":9090" in line:
                self.assertIn("localhost:9090", line, f"unexpected :9090 reference: {line!r}")

    def test_prometheus_query_happens_inside_the_ssh_session_not_the_runner(self):
        # -prometheus-url http://localhost:9090 must be part of the single
        # quoted remote command string handed to ssh, not a bare local
        # invocation of ./selector-liveness on the runner (which is exactly
        # the shape that would silently need the tailnet ACL again).
        run_step = self.raw[self.raw.index("Run selector-liveness on api-01"):]
        self.assertIn("ssh -i /tmp/api01_key", run_step)
        self.assertIn("root@patched-api-01", run_step)
        ssh_command_start = run_step.index("root@patched-api-01")
        remote_command = run_step[ssh_command_start:]
        self.assertIn("-prometheus-url http://localhost:9090", remote_command)
        self.assertNotRegex(run_step[:ssh_command_start], r"\./selector-liveness")

    def test_staging_is_retried_but_not_swallowed(self):
        """Non-author review round 2: a transient SSH blip here used to
        fail the whole weekly job outright, with the next scheduled chance
        seven days away. A bounded retry loop must exist around staging --
        but continue-on-error must NOT appear anywhere in the workflow: a
        genuine failure (bad host, auth, permissions) still has to fail the
        job loudly once the retry budget is exhausted."""
        stage_step = self.raw[
            self.raw.index("Stage selector-liveness on api-01"):
            self.raw.index("Run selector-liveness on api-01")
        ]
        self.assertIn("while true", stage_step)
        self.assertIn("sleep", stage_step)
        self.assertIn("exit 1", stage_step)
        # Check code lines only across the whole file: prose comments
        # elsewhere legitimately explain "no continue-on-error" in words.
        code_lines = [
            line for line in self.raw.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertNotIn("continue-on-error", "\n".join(code_lines))

    def test_connects_over_tailscale_with_the_established_pattern(self):
        self.assertIn("tailscale/github-action@v3", self.raw)
        self.assertIn("secrets.TS_OAUTH_CLIENT_ID", self.raw)
        self.assertIn("secrets.TS_OAUTH_SECRET", self.raw)
        self.assertIn("secrets.DEPLOY_SSH_KEY", self.raw)

    def test_a_failing_check_is_never_swallowed(self):
        # A checker built to catch quiet failures must not itself fail
        # quietly -- no continue-on-error and no `|| true` around the run.
        # Check code lines only: the step's own trailing comment explains
        # this constraint in prose and would otherwise false-positive on
        # its own explanation.
        run_step = self.raw[
            self.raw.index("Run selector-liveness on api-01"):
            self.raw.index("Clean up staged binary")
        ]
        code_lines = [
            line for line in run_step.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        code = "\n".join(code_lines)
        self.assertNotIn("continue-on-error", code)
        self.assertNotIn("|| true", code)


if __name__ == "__main__":
    unittest.main()
