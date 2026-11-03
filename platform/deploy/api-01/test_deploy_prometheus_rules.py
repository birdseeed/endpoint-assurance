"""PAT-1423: deploy/api-01/deploy-prometheus-rules.sh.

Before this ticket nothing deployed api-vps-artefacts/alerting/prometheus-
rules-patched.yml onto api-01 at all -- it only reached the box when a
person remembered to `scp` it (api-vps-artefacts/alerting/README.md's
superseded manual "Deploy" section names the exact commands that used to be
typed by hand). That gap is what let PAT-1377's fix to two dead-on-arrival
alert rules merge and then sit unshipped on main for days. This script
closes it: gate on `promtool check rules`, back up the previous file, install
atomically, write a sidecar hash (read back by patched-maintenance-facts.sh
-- see test_maintenance_facts_prometheus_rules.py), and reload Prometheus via
`systemctl reload prometheus` (SIGHUP -- the HTTP /-/reload endpoint is
disabled on this box, no --web.enable-lifecycle, returns 403), verifying
afterwards that the reload actually took rather than trusting systemctl's
exit code.

Driven via subprocess in the script's own non-root PATCHED_PROM_TEST_MODE=1
path (mirroring deploy.sh/emergency-api-only.sh's test-mode override
convention in this same directory), with `systemctl`/`curl`/`promtool`/`jq`
shimmed on PATH so every branch -- gate failure, reload rejected, reload
that never advances its timestamp, rule-count mismatch -- is exercised
deterministically without a real Prometheus or root. `promtool` is
deliberately faked here rather than required to be installed, precisely so
these tests are not skipped in CI (where it isn't installed); the separate,
real-promtool-required check that the actual committed rules file validates
lives in test_promtool_check_rules.py in this same directory, and skips
explicitly (not silently) when promtool is absent.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("deploy-prometheus-rules.sh")
VALID_RULES = "groups:\n  - name: example\n    rules: []\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DeployPrometheusRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.staging = self.root / "staging"
        self.staging.mkdir()
        self.staged_rules = self.staging / "prometheus-rules-patched.yml"
        self.staged_rules.write_text(VALID_RULES)
        self.staged_rule_tests = self.staging / "prometheus-rules-patched.test.yml"
        self.staged_rule_tests.write_text("rule_files: []\ntests: []\n")
        self.rules_dest = self.root / "live" / "patched.yml"
        self.rules_dest.parent.mkdir()
        self.sidecar = Path(str(self.rules_dest) + ".sha256")
        self.backup_dir = self.root / "backups"
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()

        # Fixture-controlled state consumed by the fake curl/systemctl below.
        self.reload_state = self.root / "reload-timestamp"
        self.reload_state.write_text("1000")
        self.promtool_exit = self.root / "promtool-exit"
        self.promtool_exit.write_text("0")
        self.promtool_test_exit = self.root / "promtool-test-exit"
        self.promtool_test_exit.write_text("0")
        self.promtool_count = self.root / "promtool-count"
        self.promtool_count.write_text("1")
        self.reload_successful = self.root / "reload-successful"
        self.reload_successful.write_text("1")
        self.reload_advances = self.root / "reload-advances"
        self.reload_advances.write_text("1")
        self.rule_count_served = self.root / "rule-count-served"
        self.rule_count_served.write_text("1")
        self.systemctl_calls = self.root / "systemctl.log"
        self.systemctl_calls.write_text("")

        self._write_fake(
            "promtool",
            f"""
            exit_code=$(cat '{self.promtool_exit}')
            if [[ "$1" == "test" ]]; then
              exit_code=$(cat '{self.promtool_test_exit}')
            fi
            count=$(cat '{self.promtool_count}')
            if [[ "$exit_code" != "0" ]]; then
              echo "  FAILED: simulated validation failure" >&2
              exit 1
            fi
            echo "Checking $*"
            echo "  SUCCESS: ${{count}} rules found"
            exit 0
            """,
        )
        self._write_fake(
            "systemctl",
            f"""
            printf '%s\\n' "$*" >> '{self.systemctl_calls}'
            if [[ "$1" == "reload" ]]; then
              if [[ "$(cat '{self.reload_advances}')" == "1" ]]; then
                ts=$(cat '{self.reload_state}')
                echo $((ts + 1)) > '{self.reload_state}'
              fi
            fi
            exit 0
            """,
        )
        self._write_fake(
            "curl",
            f"""
            url="${{@: -1}}"
            if [[ "$url" == *"/metrics" ]]; then
              echo "prometheus_config_last_reload_successful $(cat '{self.reload_successful}')"
              echo "prometheus_config_last_reload_success_timestamp_seconds $(cat '{self.reload_state}')"
              exit 0
            elif [[ "$url" == *"/api/v1/rules" ]]; then
              n=$(cat '{self.rule_count_served}')
              rules="[]"
              if [[ "$n" != "0" ]]; then
                rules="[$(seq 1 "$n" | tr '\\n' ',' | sed 's/,$//')]"
              fi
              echo "{{\\"data\\":{{\\"groups\\":[{{\\"file\\":\\"{self.rules_dest}\\",\\"rules\\":$rules}}]}}}}"
              exit 0
            fi
            exit 1
            """,
        )

    def _write_fake(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text("#!/bin/bash\nset -e\n" + body + "\n")
        path.chmod(path.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)

    def _run(self, source_commit: str = "", extra_env: dict | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env["PATCHED_PROM_TEST_MODE"] = "1"
        env["PATCHED_PROM_STAGED_RULES"] = str(self.staged_rules)
        env["PATCHED_PROM_STAGED_RULE_TESTS"] = str(self.staged_rule_tests)
        env["PATCHED_PROM_RULES_DEST"] = str(self.rules_dest)
        env["PATCHED_PROM_BACKUP_DIR"] = str(self.backup_dir)
        env["PATCHED_PROM_RELOAD_WAIT"] = "0"
        # Bounded reload-poll timeout (PAT-1423 round 2): kept short here so
        # a test exercising the "never advances"/genuinely-stuck path (e.g.
        # test_reload_that_never_advances_timestamp_fails_loudly) doesn't
        # actually wait out the script's real 30s production default.
        # Individual tests can override via extra_env.
        env["PATCHED_PROM_RELOAD_TIMEOUT"] = "2"
        if extra_env:
            env.update(extra_env)
        args = ["bash", str(SCRIPT)]
        if source_commit:
            args.append(source_commit)
        return subprocess.run(args, env=env, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30)

    # ── happy path ────────────────────────────────────────────────────────

    def test_successful_deploy_installs_reloads_and_writes_sidecar(self):
        commit = "a" * 40
        result = self._run(source_commit=commit)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rules_dest.read_text(), VALID_RULES)
        self.assertTrue(self.sidecar.is_file())

        sidecar_lines = dict(
            line.split("=", 1) for line in self.sidecar.read_text().splitlines() if "=" in line
        )
        self.assertEqual(sidecar_lines["INSTALLED_SHA256"], _sha256(self.staged_rules))
        self.assertEqual(sidecar_lines["SOURCE_COMMIT"], commit)
        self.assertIn("INSTALLED_AT", sidecar_lines)

        self.assertIn("reload prometheus", self.systemctl_calls.read_text())

    def test_source_commit_defaults_to_unknown_when_omitted(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        sidecar_lines = dict(
            line.split("=", 1) for line in self.sidecar.read_text().splitlines() if "=" in line
        )
        self.assertEqual(sidecar_lines["SOURCE_COMMIT"], "unknown")

    def test_backup_taken_only_when_previous_file_exists(self):
        # First deploy: nothing to back up.
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.backup_dir.exists() and any(self.backup_dir.glob("patched.yml.bak-*")))

        # Second deploy: a previous file now exists and must be backed up
        # byte-for-byte before being overwritten.
        previous_content = self.rules_dest.read_text()
        self.staged_rules.write_text(VALID_RULES + "  # v2\n")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        backups = list(self.backup_dir.glob("patched.yml.bak-*"))
        self.assertEqual(len(backups), 1, backups)
        self.assertEqual(backups[0].read_text(), previous_content)

    # ── validation gate ──────────────────────────────────────────────────

    def test_promtool_failure_blocks_install(self):
        self.promtool_exit.write_text("1")
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.rules_dest.exists())
        self.assertFalse(self.sidecar.exists())

    def test_missing_staged_file_fails_before_promtool_runs(self):
        self.staged_rules.unlink()
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing staged rules file", result.stderr)

    def test_missing_staged_rule_test_file_blocks_promotion(self):
        self.staged_rule_tests.unlink()
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing staged rules test file", result.stderr)
        self.assertFalse(self.rules_dest.exists())
        self.assertFalse(self.sidecar.exists())

    def test_promtool_rule_test_failure_blocks_promotion(self):
        self.promtool_test_exit.write_text("1")
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.rules_dest.exists())
        self.assertFalse(self.sidecar.exists())

    def test_empty_staged_file_is_refused(self):
        self.staged_rules.write_text("")
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("empty", result.stderr)

    def test_invalid_source_commit_argument_is_refused(self):
        result = self._run(source_commit="not-a-sha")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.rules_dest.exists())

    # ── reload verification: the core of item 2's "fail loudly" ask ────────

    def test_reload_rejected_by_prometheus_fails_loudly(self):
        """systemctl reload can return 0 while Prometheus itself rejects the
        new config (bad promtool-adjacent semantic error, or any other
        reason prometheus_config_last_reload_successful goes to 0). This
        must fail the deploy, not report success.

        PAT-1423 round 2: the reload check became a bounded poll loop (see
        test_reload_that_is_slow_but_eventually_succeeds), which must not
        weaken this -- a genuine rejection is a definitive signal the moment
        Prometheus reports it, so this must fail on the FIRST poll rather
        than waiting out the whole poll budget. Asserted here via wall-clock
        time, well under PATCHED_PROM_RELOAD_TIMEOUT (2s in this harness)."""
        self.reload_successful.write_text("0")
        started = time.monotonic()
        result = self._run()
        elapsed = time.monotonic() - started

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REJECTED", result.stderr)
        # The file was installed (that's what triggered the reload attempt)
        # and a backup exists to recover from -- but the step itself failed.
        self.assertTrue(self.rules_dest.is_file())
        self.assertLess(elapsed, 1.5, "rejection must fail fast, not wait out the poll timeout")

    def test_reload_that_never_advances_timestamp_fails_loudly(self):
        """A systemctl reload that is a pure no-op (e.g. the unit doesn't
        actually support ExecReload the way expected) must not be mistaken
        for a successful, applied reload just because it exited 0. This now
        exercises the full poll budget (PATCHED_PROM_RELOAD_TIMEOUT=2 in
        this harness) before giving up -- a timestamp that never advances
        genuinely never resolves, unlike the "slow but eventually succeeds"
        case in test_reload_that_is_slow_but_eventually_succeeds."""
        self.reload_advances.write_text("0")
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not advance", result.stderr)

    def test_reload_that_is_slow_but_eventually_succeeds(self):
        """PAT-1423 round 2: a loaded box may not have processed the SIGHUP
        by the time of a single fixed-delay check, which used to read as a
        false deploy failure. The reload check is now a bounded poll: this
        drives a Prometheus that reports the OLD last-reload timestamp for
        the first few poll attempts (as if still mid-reload) and only
        advances it on a later attempt -- the deploy must still succeed.

        systemctl reload succeeding tells us nothing about WHEN Prometheus
        actually finishes processing it, so systemctl is overridden here
        too -- to a pure log-and-succeed no-op -- so the ONLY thing
        controlling when the timestamp advances is the curl fake's own
        counter below. (The default systemctl fake from setUp bumps
        reload_state synchronously the instant "reload" is called, which
        would defeat the "stays old for the first few polls" simulation
        this test needs.)"""
        self._write_fake(
            "systemctl",
            f"""
            printf '%s\\n' "$*" >> '{self.systemctl_calls}'
            exit 0
            """,
        )
        self._write_fake(
            "curl",
            f"""
            url="${{@: -1}}"
            counter='{self.root}/metrics-poll-count'
            if [[ "$url" == *"/metrics" ]]; then
              n=$(cat "$counter" 2>/dev/null || echo 0)
              n=$((n + 1))
              echo "$n" > "$counter"
              ts=1000
              if [[ "$n" -ge 4 ]]; then
                ts=1001
              fi
              echo "prometheus_config_last_reload_successful 1"
              echo "prometheus_config_last_reload_success_timestamp_seconds $ts"
              exit 0
            elif [[ "$url" == *"/api/v1/rules" ]]; then
              n=$(cat '{self.rule_count_served}')
              rules="[]"
              if [[ "$n" != "0" ]]; then
                rules="[$(seq 1 "$n" | tr '\\n' ',' | sed 's/,$//')]"
              fi
              echo "{{\\"data\\":{{\\"groups\\":[{{\\"file\\":\\"{self.rules_dest}\\",\\"rules\\":$rules}}]}}}}"
              exit 0
            fi
            exit 1
            """,
        )
        result = self._run(extra_env={"PATCHED_PROM_RELOAD_TIMEOUT": "10"})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.rules_dest.is_file())
        self.assertEqual(self.rules_dest.read_text(), VALID_RULES)
        self.assertIn("reload prometheus", self.systemctl_calls.read_text())
        # Confirms this test actually exercised multiple poll attempts
        # rather than passing on the first try for an unrelated reason.
        self.assertGreaterEqual(int((self.root / "metrics-poll-count").read_text().strip()), 4)

    def test_unreachable_prometheus_after_reload_fails_loudly(self):
        # The BEFORE-reload fetch must succeed here (that path has its own
        # dedicated test, test_prereload_metrics_fetch_failure_fails_closed_
        # before_reloading) so this one actually exercises the AFTER-reload
        # fetch failure it's named for, rather than failing earlier for an
        # unrelated reason and leaving the after-reload path untested.
        self._write_fake(
            "curl",
            f"""
            url="${{@: -1}}"
            count_file='{self.root}/curl-metrics-calls'
            if [[ "$url" == *"/metrics" ]]; then
              n=$(cat "$count_file" 2>/dev/null || echo 0)
              n=$((n + 1))
              echo "$n" > "$count_file"
              if [[ "$n" -eq 1 ]]; then
                echo "prometheus_config_last_reload_successful $(cat '{self.reload_successful}')"
                echo "prometheus_config_last_reload_success_timestamp_seconds $(cat '{self.reload_state}')"
                exit 0
              fi
              exit 7
            fi
            exit 1
            """,
        )
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not reach", result.stderr)
        self.assertIn("after reload", result.stderr)
        self.assertIn("reload prometheus", self.systemctl_calls.read_text())

    def test_rule_count_mismatch_after_reload_fails_loudly(self):
        """Independent confirmation on top of the successful-reload gauge:
        even if Prometheus reports a successful reload, if the live rule
        count doesn't match what promtool validated in the staged file,
        something is wrong (stale cache, wrong file served, etc.) and the
        deploy must not report success."""
        self.promtool_count.write_text("19")
        self.rule_count_served.write_text("3")
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not take the new file", result.stderr)

    def test_rule_count_check_ignores_a_second_unrelated_rule_file(self):
        """Non-author review, PAT-1423 round 4: /api/v1/rules returns rule
        groups from EVERY loaded rule file, not just ours. Comparing
        promtool's per-file count against the global total is only correct
        while patched.yml happens to be the only file Prometheus loads --
        the moment a second file exists, every deploy would start failing
        on a spurious mismatch. This is the regression test: a second,
        unrelated rule file's groups are present in the API response
        alongside ours, and the deploy must still succeed because the
        check filters by `file == RULES_DEST` before counting."""
        self.promtool_count.write_text("19")
        self._write_fake(
            "curl",
            f"""
            url="${{@: -1}}"
            if [[ "$url" == *"/metrics" ]]; then
              echo "prometheus_config_last_reload_successful $(cat '{self.reload_successful}')"
              echo "prometheus_config_last_reload_success_timestamp_seconds $(cat '{self.reload_state}')"
              exit 0
            elif [[ "$url" == *"/api/v1/rules" ]]; then
              ours="[$(seq 1 19 | tr '\\n' ',' | sed 's/,$//')]"
              other="[$(seq 1 7 | tr '\\n' ',' | sed 's/,$//')]"
              echo "{{\\"data\\":{{\\"groups\\":[{{\\"file\\":\\"/etc/prometheus/rules/other-team.yml\\",\\"rules\\":$other}},{{\\"file\\":\\"{self.rules_dest}\\",\\"rules\\":$ours}}]}}}}"
              exit 0
            fi
            exit 1
            """,
        )
        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.rules_dest.is_file())

    def test_systemctl_reload_failure_is_fatal(self):
        self._write_fake("systemctl", "exit 1\n")
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("systemctl reload prometheus failed", result.stderr)

    # ── non-author review fixes (PAT-1423) ──────────────────────────────

    def test_unrecognized_promtool_output_fails_loudly_instead_of_skipping_the_rule_count_check(self):
        """If promtool's success line ever stops matching the "SUCCESS: N
        rules found" pattern this script parses, EXPECTED_RULE_COUNT comes
        back empty. Before the fix that silently skipped the entire
        independent post-reload rule-count confirmation while the deploy
        still reported success -- verifying strictly less than it claimed
        to, the exact "a check that stops running looks identical to one
        that is running" shape this ticket exists to close. It must instead
        fail loudly and install nothing."""
        self._write_fake(
            "promtool",
            f"""
            exit_code=$(cat '{self.promtool_exit}')
            if [[ "$exit_code" != "0" ]]; then
              echo "  FAILED: simulated validation failure" >&2
              exit 1
            fi
            echo "Checking $*"
            echo "  OK: 19 rules validated"
            exit 0
            """,
        )
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not determine the validated rule count", result.stderr)
        self.assertFalse(self.rules_dest.exists(), "must not install when the rule count can't be confirmed")
        self.assertFalse(self.sidecar.exists())
        self.assertNotIn("reload", self.systemctl_calls.read_text())

    def test_prereload_metrics_fetch_failure_fails_closed_before_reloading(self):
        """A curl failure fetching /metrics BEFORE calling systemctl reload
        used to be swallowed into RELOAD_BEFORE="" with no signal, which
        silently degrades the post-reload "did the timestamp actually
        advance" check into just "is RELOAD_AFTER non-empty". Since this
        script always queries its own box's localhost Prometheus, a
        pre-reload fetch failure means something is already wrong -- fail
        closed rather than proceed with a weakened check. Reload must never
        be attempted in this case."""
        self._write_fake(
            "curl",
            f"""
            url="${{@: -1}}"
            count_file='{self.root}/curl-metrics-calls'
            if [[ "$url" == *"/metrics" ]]; then
              n=$(cat "$count_file" 2>/dev/null || echo 0)
              n=$((n + 1))
              echo "$n" > "$count_file"
              if [[ "$n" -eq 1 ]]; then
                exit 7
              fi
              echo "prometheus_config_last_reload_successful $(cat '{self.reload_successful}')"
              echo "prometheus_config_last_reload_success_timestamp_seconds $(cat '{self.reload_state}')"
              exit 0
            fi
            exit 1
            """,
        )
        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("before reloading", result.stderr)
        # Install (and the sidecar write, which precedes reload) already
        # happened by this point -- that's expected, same as every other
        # reload-stage failure in this script -- but reload itself must
        # never have been attempted.
        self.assertTrue(self.rules_dest.is_file())
        self.assertNotIn("reload", self.systemctl_calls.read_text())

    # ── root-mode safety net (mirrors deploy.sh/emergency-api-only.sh) ──────

    def test_root_forbidden_overrides_are_rejected(self):
        """A production (root) invocation must refuse to start at all if any
        test-mode override env var is present, so a misconfigured production
        job fails loudly instead of silently redirecting to a test path.
        Exercised without actually running as root: PATCHED_PROM_TEST_MODE is
        unset here (this process isn't root either), so the script's own
        root branch isn't reached -- instead this asserts the forbidden-name
        list is enforced structurally by checking it's present verbatim in
        the script, since we cannot safely re-invoke this script as EUID 0
        in a test."""
        source = SCRIPT.read_text()
        for name in (
            "PATCHED_PROM_STAGED_RULES", "PATCHED_PROM_STAGED_RULE_TESTS", "PATCHED_PROM_RULES_DEST",
            "PATCHED_PROM_SIDECAR", "PATCHED_PROM_BACKUP_DIR",
            "PATCHED_PROM_SYSTEMCTL_BIN", "PATCHED_PROM_PROMTOOL_BIN",
            "PATCHED_PROM_CURL_BIN", "PATCHED_PROM_OWNER",
        ):
            self.assertIn(name, source)
        self.assertIn("UNSAFE_OVERRIDE_NAMES", source)

    def test_non_root_without_test_mode_refuses_to_run(self):
        env = dict(os.environ)
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env.pop("PATCHED_PROM_TEST_MODE", None)
        result = subprocess.run(
            ["bash", str(SCRIPT)], env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must run as root", result.stderr)


if __name__ == "__main__":
    unittest.main()
