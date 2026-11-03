"""PAT-1439/PAT-1438: deploy/install.sh must actually install
patched-maintenance-facts.service + .timer (hardened under PAT-1439),
issue a daemon-reload, and re-enable/restart the TIMER -- never the
oneshot .service directly.

Before this ticket, `grep -n "patched-maintenance-facts" deploy/install.sh`
returned zero matches: the unit pair only reached portal-01 when a person
copied it by hand. Hardening the unit file (PAT-1439) without also closing
this gap would have left it correct-by-luck -- the next edit to the unit
would silently not apply, because nothing installs it.

deploy/install.sh is not root-runnable or systemd-drivable in this dev
environment (no real systemctl, requires root for apt/useradd/ufw), so
this is a static content check over the checked-in script -- the same
technique patched.im's test_maintenance_facts_deploy_wiring.py uses for
its GitHub Actions workflow, applied here to a plain shell script instead
of YAML. It does not replace actually running deploy/install.sh on
portal-01, which is the deploy step that follows this ticket.

Run with: pytest tests/test_pat1439_maintenance_facts_install_wiring.py -v
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "deploy" / "install.sh"
SERVICE_PATH = REPO_ROOT / "deploy" / "patched-maintenance-facts.service"
TIMER_PATH = REPO_ROOT / "deploy" / "patched-maintenance-facts.timer"
HELPER_PATH = REPO_ROOT / "deploy" / "install-verified-systemd-service.sh"


def _text() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


class TestMaintenanceFactsInstallWiring:
    def test_unit_files_exist_in_the_checkout(self):
        assert SERVICE_PATH.is_file(), f"{SERVICE_PATH} is missing"
        assert TIMER_PATH.is_file(), f"{TIMER_PATH} is missing"

    def test_installer_ships_both_unit_files_to_etc_systemd_system(self):
        text = _text()
        assert "deploy/patched-maintenance-facts.service" in text
        assert "deploy/patched-maintenance-facts.timer" in text
        helper = HELPER_PATH.read_text(encoding="utf-8")
        assert 'printf \'%s\\n\' /etc/systemd/system' in helper
        assert 'PATCHED_SYSTEMD_TEST_MODE' in helper
        assert "install_and_verify_service patched-maintenance-facts.service || exit 1" in text
        assert "install_systemd_timer_atomically patched-maintenance-facts.timer || exit 1" in text

    def test_installer_issues_a_daemon_reload(self):
        helper = HELPER_PATH.read_text(encoding="utf-8")
        assert "systemctl daemon-reload" in helper

    def test_daemon_reload_precedes_the_timer_enable(self):
        text = _text()
        helper = HELPER_PATH.read_text(encoding="utf-8")
        install_idx = text.index("install_systemd_timer_atomically patched-maintenance-facts.timer")
        enable_idx = text.index("systemctl enable --now patched-maintenance-facts.timer")
        assert install_idx < enable_idx
        assert "systemctl daemon-reload" in helper, (
            "daemon-reload must run before the timer is (re)enabled, or systemd may act "
            "on the unit definition it already had loaded rather than the new one"
        )

    def test_installer_enables_and_restarts_the_timer(self):
        text = _text()
        assert "systemctl enable --now patched-maintenance-facts.timer" in text
        assert "systemctl restart patched-maintenance-facts.timer" in text

    def test_installer_never_restarts_the_oneshot_service_directly(self):
        # Restarting a oneshot .service just fires an out-of-schedule run --
        # it does not "activate" anything the way restarting a long-running
        # service would. Only the timer should ever be told to (re)start.
        text = _text()
        assert "restart patched-maintenance-facts.service" not in text
        assert "start patched-maintenance-facts.service" not in text

    def test_installer_verifies_the_timer_is_enabled_and_active(self):
        # Verify the result rather than trusting the copy: a daemon-reload
        # or enable that silently no-op'd would leave the box running a
        # stale in-memory unit definition even though the step "succeeded".
        text = _text()
        assert "is-enabled --quiet patched-maintenance-facts.timer" in text
        assert "is-active --quiet patched-maintenance-facts.timer" in text

    def test_verification_failure_actually_fails_the_install(self):
        text = _text()
        # install.sh runs under `set -euo pipefail`, so `exit 1` inside the
        # `if ! systemctl ...` guards is what makes a failed verification
        # actually abort the install rather than silently continuing.
        idx = text.index("is-enabled --quiet patched-maintenance-facts.timer")
        following = text[idx:idx + 400]
        assert "exit 1" in following

    def test_install_step_runs_after_the_portal_unit_and_before_nginx(self):
        text = _text()
        portal_unit_idx = text.index("install_and_verify_service patched-portal.service")
        mf_unit_idx = text.index("install_and_verify_service patched-maintenance-facts.service")
        nginx_idx = text.index('cp "$REPO_DIR/deploy/nginx-portal.conf"')
        assert portal_unit_idx < mf_unit_idx < nginx_idx

    def test_script_still_parses_as_valid_bash(self):
        import subprocess
        result = subprocess.run(
            ["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
