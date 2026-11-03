"""PAT-1237: normal api-01 deploys reject an unhardened installed unit."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "api-01" / "verify-systemd-hardening-floor.sh"
INSTALLER = REPO / "deploy" / "api-01" / "install-maintenance-systemd-units.sh"
WORKFLOW = REPO / ".github" / "workflows" / "deploy-api-01.yml"


class DeployHardeningFloorTests(unittest.TestCase):
    def run_guard(
        self,
        analysis: str,
        units: tuple[str, ...] = ("patched-maintenance-facts.service",),
        load_state: str = "loaded",
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            fakebin = Path(temporary) / "bin"
            fakebin.mkdir()
            (fakebin / "systemctl").write_text(
                "#!/usr/bin/env bash\n[[ $1 == show ]] && echo \"$HARDENING_LOAD_STATE\"\n"
            )
            (fakebin / "systemd-analyze").write_text(
                "#!/usr/bin/env bash\n"
                "[[ $LC_ALL == C && $SYSTEMD_COLORS == 0 && $SYSTEMD_EMOJI == 0 ]] || exit 4\n"
                "[[ $* == *security* ]] && printf '%s\\n' \"$HARDENING_ANALYSIS\"\n"
            )
            for command in fakebin.iterdir():
                command.chmod(command.stat().st_mode | stat.S_IXUSR)
            env = dict(
                os.environ,
                PATH=f"{fakebin}:/usr/bin:/bin",
                HARDENING_ANALYSIS=analysis,
                HARDENING_LOAD_STATE=load_state,
            )
            return subprocess.run(
                ["bash", str(SCRIPT), *units],
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )

    def test_deliberately_unhardened_unit_fails_the_deploy_guard(self):
        result = self.run_guard(
            "-> Overall exposure level for patched-maintenance-facts.service: 9.6 UNSAFE :-|"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("above scheduled-maintenance ceiling 6.0", result.stderr)

    def test_unparseable_score_fails_closed(self):
        result = self.run_guard("systemd-analyze output changed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no parseable exposure score", result.stderr)

    def test_within_and_exact_ceiling_pass(self):
        for score in ("5.9", "6.0"):
            result = self.run_guard(
                f"-> Overall exposure level for patched-maintenance-facts.service: {score} MEDIUM :-|"
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_parser_accepts_real_systemd_variants_and_scores_every_unit(self):
        result = self.run_guard(
            "\n".join(
                (
                    "→ Overall exposure level for patched-api.service: 5.5 MEDIUM 🙂",
                    "Overall exposure level for patched-maintenance-facts.service: 6.0 MEDIUM",
                )
            ),
            ("patched-api.service", "patched-maintenance-facts.service"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("within"), 2)

    def test_not_loaded_fails_closed(self):
        result = self.run_guard(
            "Overall exposure level for patched-maintenance-facts.service: 5.0 MEDIUM",
            load_state="not-found",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not loaded", result.stderr)

    def test_existing_only_preflight_skips_bootstrap_unit(self):
        result = self.run_guard(
            "systemd-analyze must not run",
            units=("--existing", "patched-maintenance-facts.service"),
            load_state="not-found",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not-found; skipped during bootstrap preflight", result.stdout)

    def test_existing_only_preflight_skips_masked_but_rejects_unknown_state(self):
        masked = self.run_guard(
            "systemd-analyze must not run",
            units=("--existing", "patched-cve-sync.service"),
            load_state="masked",
        )
        self.assertEqual(masked.returncode, 0, masked.stderr)
        broken = self.run_guard(
            "systemd-analyze must not run",
            units=("--existing", "patched-cve-sync.service"),
            load_state="error",
        )
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn("unexpected bootstrap LoadState=error", broken.stderr)

    def test_unclassified_unit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fakebin = Path(temporary) / "bin"; fakebin.mkdir()
            (fakebin / "systemctl").write_text("#!/usr/bin/env bash\necho loaded\n")
            (fakebin / "systemd-analyze").write_text("#!/usr/bin/env bash\necho '-> Overall exposure level for patched-new.service: 1.0 OK :-|'\n")
            for command in fakebin.iterdir(): command.chmod(command.stat().st_mode | stat.S_IXUSR)
            result = subprocess.run(["bash", str(SCRIPT), "patched-new.service"], text=True, capture_output=True, env=dict(os.environ, PATH=f"{fakebin}:/usr/bin:/bin"))
            self.assertNotEqual(result.returncode, 0)

    def test_workflow_preflights_before_binary_deploy_then_installs_transactionally(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Preflight current systemd hardening floor on api-01", workflow)
        self.assertIn("install-maintenance-systemd-units.sh", workflow)
        self.assertIn('"$guard" patched-api.service patched-extractor.service patched-cve-sync.service', workflow)
        self.assertIn('"$guard" --existing patched-maintenance-facts.service', workflow)
        self.assertIn('[ "$(stat -c "%U:%G %a" "$staging")" = "root:root 755" ]', workflow)
        self.assertIn("rsync -av --chown=root:root", workflow)
        self.assertIn("install -d -o root -g root -m 0700 /opt/patched-systemd-staging", workflow)
        self.assertLess(workflow.index("Preflight current systemd hardening floor on api-01"), workflow.index("Run deploy.sh on api-01"))
        self.assertLess(workflow.index("Run deploy.sh on api-01"), workflow.index("Deploy maintenance facts systemd units on api-01"))

    def test_transactional_installer_restores_both_units_on_guard_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            systemd = root / "systemd"
            source.mkdir()
            systemd.mkdir()
            units = ("patched-maintenance-facts.service", "patched-maintenance-facts.timer")
            for unit in units:
                (source / unit).write_text(f"new {unit}\n")
                (systemd / unit).write_text(f"old {unit}\n")
                (systemd / unit).chmod(0o600)
            guard = source / "verify-systemd-hardening-floor.sh"
            guard.write_text("#!/usr/bin/env bash\nexit 1\n")
            guard.chmod(0o755)
            fake_systemctl = root / "systemctl"
            fake_systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "case $1 in is-enabled) echo enabled; exit 0;; is-active) echo active; exit 0;; *) exit 0;; esac\n"
            )
            fake_systemctl.chmod(0o755)
            result = subprocess.run(
                ["bash", str(INSTALLER), str(source)],
                text=True,
                capture_output=True,
                env=dict(
                    os.environ,
                    PATCHED_SYSTEMD_DIR=str(systemd),
                    PATCHED_SYSTEMCTL=str(fake_systemctl),
                ),
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            for unit in units:
                self.assertEqual((systemd / unit).read_text(), f"old {unit}\n")
                self.assertEqual(stat.S_IMODE((systemd / unit).stat().st_mode), 0o600)
            self.assertFalse(list(systemd.glob("*.pat1237-*")))

    def test_early_first_unit_install_failure_preserves_untouched_timer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            systemd = root / "systemd"
            fakebin = root / "bin"
            source.mkdir()
            systemd.mkdir()
            fakebin.mkdir()
            units = ("patched-maintenance-facts.service", "patched-maintenance-facts.timer")
            for unit in units:
                (source / unit).write_text(f"new {unit}\n")
                (systemd / unit).write_text(f"old {unit}\n")
            guard = source / "verify-systemd-hardening-floor.sh"
            guard.write_text("#!/usr/bin/env bash\nexit 0\n")
            guard.chmod(0o755)
            fake_systemctl = fakebin / "systemctl"
            fake_systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "case $1 in is-enabled) echo disabled; exit 1;; is-active) echo inactive; exit 3;; *) exit 0;; esac\n"
            )
            fake_install = fakebin / "install"
            fake_install.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${@: -1}\" in *patched-maintenance-facts.service.pat1237-new) exit 9;; esac\n"
                "exec /usr/bin/install \"$@\"\n"
            )
            for command in fakebin.iterdir():
                command.chmod(command.stat().st_mode | stat.S_IXUSR)
            result = subprocess.run(
                ["bash", str(INSTALLER), str(source)],
                text=True,
                capture_output=True,
                env=dict(
                    os.environ,
                    PATH=f"{fakebin}:/usr/bin:/bin",
                    PATCHED_SYSTEMD_DIR=str(systemd),
                    PATCHED_SYSTEMCTL=str(fake_systemctl),
                ),
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            for unit in units:
                self.assertEqual((systemd / unit).read_text(), f"old {unit}\n")

    def test_fresh_install_guard_failure_ignores_already_absent_runtime_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            systemd = root / "systemd"
            source.mkdir()
            systemd.mkdir()
            for unit in ("patched-maintenance-facts.service", "patched-maintenance-facts.timer"):
                (source / unit).write_text(f"new {unit}\n")
            guard = source / "verify-systemd-hardening-floor.sh"
            guard.write_text("#!/usr/bin/env bash\nexit 1\n")
            guard.chmod(0o755)
            fake_systemctl = root / "systemctl"
            fake_systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "case $1 in is-enabled) echo disabled; exit 1;; is-active) echo inactive; exit 3;; disable|stop) exit 5;; *) exit 0;; esac\n"
            )
            fake_systemctl.chmod(0o755)
            result = subprocess.run(
                ["bash", str(INSTALLER), str(source)], text=True, capture_output=True,
                env=dict(os.environ, PATCHED_SYSTEMD_DIR=str(systemd), PATCHED_SYSTEMCTL=str(fake_systemctl)),
                timeout=10,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn("CRITICAL", result.stderr)
            self.assertFalse(any(systemd.iterdir()))

    def test_timer_state_query_error_aborts_before_touching_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "source"; systemd = root / "systemd"
            source.mkdir(); systemd.mkdir()
            for unit in ("patched-maintenance-facts.service", "patched-maintenance-facts.timer"):
                (source / unit).write_text(f"new {unit}\n")
                (systemd / unit).write_text(f"old {unit}\n")
            guard = source / "verify-systemd-hardening-floor.sh"
            guard.write_text("#!/usr/bin/env bash\nexit 0\n"); guard.chmod(0o755)
            fake_systemctl = root / "systemctl"
            fake_systemctl.write_text("#!/usr/bin/env bash\nexit 5\n"); fake_systemctl.chmod(0o755)
            result = subprocess.run(
                ["bash", str(INSTALLER), str(source)], text=True, capture_output=True,
                env=dict(os.environ, PATCHED_SYSTEMD_DIR=str(systemd), PATCHED_SYSTEMCTL=str(fake_systemctl)), timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot determine prior enabled state", result.stderr)
            for unit in ("patched-maintenance-facts.service", "patched-maintenance-facts.timer"):
                self.assertEqual((systemd / unit).read_text(), f"old {unit}\n")

    def test_guard_policy_matches_documented_units_and_ceilings(self):
        guard = SCRIPT.read_text(encoding="utf-8")
        documented = (REPO / "docs" / "systemd-hardening-floor.md").read_text(encoding="utf-8")
        for unit in (
            "patched-backup.service", "patched-prod-backup.service", "patched-portal-backup.service",
            "patched-prod-restore-test.service", "patched-api.service", "patched-dashboard.service",
            "patched-portal.service", "patched-extractor.service", "patched-scan.service",
            "patched-cve-sync.service", "patched-tooling-cve-refresh.service", "patched-partitions.service", "patched-alert-metrics.service",
            "patched-dashboard-prune-reports.service", "patched-prod-alerts.service",
            "patched-maintenance-facts.service", "patched-scan-nvd-refresh.service",
        ):
            self.assertIn(unit, guard)
            self.assertIn(f"`{unit}`", documented)
        self.assertIn("credential-handling) printf '%s\\n' 6.7", guard)
        self.assertIn("application|scheduled-maintenance) printf '%s\\n' 6.0", guard)
        self.assertIn("| 6.7 MEDIUM |", documented)
        self.assertEqual(documented.count("| 6.0 MEDIUM |"), 2)

    def test_binary_deploy_runs_guard_inside_rollback_boundary(self):
        deploy = (REPO / "deploy" / "api-01" / "deploy.sh").read_text(encoding="utf-8")
        self.assertLess(deploy.index("trap 'rollback"), deploy.index('"$HARDENING_GUARD" patched-api.service'))
        self.assertLess(deploy.index('"$HARDENING_GUARD" patched-api.service'), deploy.index("DEPLOY_PHASE=committed"))


if __name__ == "__main__":
    unittest.main()
