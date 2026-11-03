"""PAT-1439/PAT-1438: workflow-level assertions that api-vps-artefacts/
patched-maintenance-facts.service and .timer -- hardened under PAT-1439 --
actually have a deploy path, including the daemon-reload and timer
enable/restart a copied unit file needs to actually take effect.

Before this ticket, `grep -rn "patched-maintenance-facts.service"
.github/workflows/` returned zero matches: nothing shipped these unit files
to /etc/systemd/system/ on api-01, ever -- the exact same gap PAT-1436
closed for the emitter script itself (see
test_maintenance_facts_deploy_wiring.py, this directory). Hardening the
unit files by hand without also closing this gap would have left them
correct-by-luck: the next edit to the unit would silently not apply,
because nothing installs it.

A unit file is not live just because it was copied -- unlike the emitter
script (a plain executable systemd just re-execs on the next timer fire),
installing a NEW unit definition requires `systemctl daemon-reload` before
systemd will even see it, and the TIMER must be re-enabled/restarted to
pick up the change. Restarting the oneshot .service directly would just
fire an off-schedule run, not "activate" anything -- so this test also pins
that the deploy step never does that.

Same technique as test_maintenance_facts_deploy_wiring.py: read the real
.github/workflows/deploy-api-01.yml from this checkout and assert the unit
files are actually staged, daemon-reload is issued, and the timer (never
the service) is what gets enabled/restarted -- rather than adding a YAML
parser or a second CI job.

Run with: python3 -m unittest deploy.api-01.test_pat1439_maintenance_facts_units_deploy_wiring -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-api-01.yml"
SERVICE_PATH = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.service"
TIMER_PATH = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.timer"
INSTALLER_PATH = REPO_ROOT / "deploy" / "api-01" / "install-maintenance-systemd-units.sh"

_CHECK_MODULE_PATH = Path(__file__).with_name("check_binary_inventory.py")
_SPEC = importlib.util.spec_from_file_location("check_binary_inventory", _CHECK_MODULE_PATH)
assert _SPEC and _SPEC.loader
_CHECK_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CHECK_MODULE)
workflow_step = _CHECK_MODULE.workflow_step


class MaintenanceFactsUnitsDeployWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_unit_files_exist_in_the_checkout(self):
        self.assertTrue(SERVICE_PATH.is_file(), f"{SERVICE_PATH} is missing")
        self.assertTrue(TIMER_PATH.is_file(), f"{TIMER_PATH} is missing")

    # ── the workflow actually ships both unit files to /etc/systemd/system ──

    def test_a_step_ships_both_unit_files_to_etc_systemd_system(self):
        deploy_step = workflow_step(self.workflow, "Deploy maintenance facts systemd units on api-01")
        self.assertTrue(deploy_step, "expected a 'Deploy maintenance facts systemd units on api-01' step")
        self.assertIn("api-vps-artefacts/patched-maintenance-facts.service", deploy_step)
        self.assertIn("api-vps-artefacts/patched-maintenance-facts.timer", deploy_step)
        self.assertIn("root@patched-api-01", deploy_step)
        self.assertIn("install-maintenance-systemd-units.sh", deploy_step)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn('PATCHED_SYSTEMD_DIR:-/etc/systemd/system', installer)

    # ── installing a unit is not enough: systemd must be told to reread it ──

    def test_the_deploy_step_issues_a_daemon_reload(self):
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn('"$SYSTEMCTL" daemon-reload', installer)

    def test_the_deploy_step_enables_and_restarts_the_timer(self):
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn('"$SYSTEMCTL" enable --now "$TIMER"', installer)

    def test_transactional_helper_is_non_vacuous(self):
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        for required in (
            'install -m 0644 "$SOURCE_DIR/$unit"',
            '"$SYSTEMCTL" daemon-reload',
            '"$SYSTEMCTL" enable --now "$TIMER"',
            '"$GUARD" "$SERVICE"',
            "rollback_units",
        ):
            self.assertIn(required, installer)

    def test_the_deploy_step_never_restarts_the_oneshot_service_directly(self):
        # Restarting a oneshot .service just fires an out-of-schedule run --
        # it does not "activate" anything the way restarting a long-running
        # service would. Only the timer should ever be told to (re)start.
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertNotIn('restart "$SERVICE"', installer)
        self.assertNotIn('start "$SERVICE"', installer)
        self.assertNotIn("restart patched-maintenance-facts.service", installer)
        self.assertNotIn("start patched-maintenance-facts.service", installer)

    def test_daemon_reload_precedes_the_timer_enable_in_the_same_step(self):
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        reload_idx = installer.rindex('"$SYSTEMCTL" daemon-reload')
        enable_idx = installer.index('"$SYSTEMCTL" enable --now "$TIMER"')
        self.assertLess(
            reload_idx, enable_idx,
            "daemon-reload must run before the timer is (re)enabled, or systemd may act "
            "on the unit definition it already had loaded rather than the new one",
        )

    # ── verified for real, not just assumed to have landed correctly ──────

    def test_a_step_verifies_the_timer_is_enabled_and_active(self):
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts timer is enabled and active"
        )
        self.assertTrue(
            verify_step,
            "expected a 'Verify the maintenance facts timer is enabled and active' step",
        )
        self.assertIn("root@patched-api-01", verify_step)
        self.assertIn("is-enabled --quiet patched-maintenance-facts.timer", verify_step)
        self.assertIn("is-active --quiet patched-maintenance-facts.timer", verify_step)

    def test_error_annotations_go_to_stdout_not_stderr(self):
        # `::error::` is a GitHub Actions workflow command, parsed only from
        # stdout -- the same lesson PAT-1436's own step learned the hard way
        # (test_maintenance_facts_deploy_wiring.py pins it for that step).
        for step_name in (
            "Deploy maintenance facts systemd units on api-01",
            "Verify the maintenance facts timer is enabled and active",
        ):
            step = workflow_step(self.workflow, step_name)
            for line in step.splitlines():
                if "::error::" in line:
                    self.assertNotIn(">&2", line, f"{step_name}: {line.strip()}")

    def test_an_unreachable_box_is_not_reported_as_a_broken_timer(self):
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts timer is enabled and active"
        )
        self.assertIn("SSH/network failure", verify_step)

    def test_verification_failure_actually_fails_the_job(self):
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts timer is enabled and active"
        )
        self.assertIn("exit 1", verify_step)

    def test_steps_run_after_deploy_sh_and_before_the_always_readback(self):
        deploy_sh_idx = self.workflow.index("- name: Run deploy.sh on api-01")
        units_idx = self.workflow.index("- name: Deploy maintenance facts systemd units on api-01")
        verify_idx = self.workflow.index(
            "- name: Verify the maintenance facts timer is enabled and active"
        )
        readback_idx = self.workflow.index(
            "- name: Read back three-binary provenance and timer state"
        )
        self.assertLess(deploy_sh_idx, units_idx)
        self.assertLess(units_idx, verify_idx)
        self.assertLess(verify_idx, readback_idx)


if __name__ == "__main__":
    unittest.main()
