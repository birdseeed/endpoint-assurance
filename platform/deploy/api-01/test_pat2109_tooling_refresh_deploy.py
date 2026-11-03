"""PAT-2109 deployment ownership for the prompt tooling refresh timer."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy/api-01/deploy.sh"
INSTALL = ROOT / "deploy/api-01/install-tooling-cve-refresh-units.sh"
WORKFLOW = ROOT / ".github/workflows/deploy-api-01.yml"
SERVICE = "patched-tooling-cve-refresh.service"
TIMER = "patched-tooling-cve-refresh.timer"
SERVICE_TEXT = (ROOT / "api-vps-artefacts" / SERVICE).read_text(encoding="utf-8")
TIMER_TEXT = (ROOT / "api-vps-artefacts" / TIMER).read_text(encoding="utf-8")


class ToolingRefreshDeployTests(unittest.TestCase):
    def test_scripts_parse_and_transactional_installer_is_used(self) -> None:
        subprocess.run(["bash", "-n", str(DEPLOY), str(INSTALL)], check=True)
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("install-tooling-cve-refresh-units.sh", workflow)
        self.assertNotIn("install -o root -g root -m 0644 /opt/patched-cve-systemd-staging/patched-tooling", workflow)
        installer = INSTALL.read_text(encoding="utf-8")
        for evidence in ("trap rollback EXIT", "trap 'exit 143' TERM", "daemon-reload", "is not idle"):
            self.assertIn(evidence, installer)

    def test_normal_deploy_quiesces_and_proves_prompt_service_idle(self) -> None:
        text = DEPLOY.read_text(encoding="utf-8")
        for evidence in (
            "stop patched-tooling-cve-refresh.timer",
            "tooling_sync_state_is_safe",
            "TOOLING_INVOCATION_BEFORE",
            "TOOLING_INVOCATION_AFTER",
            "start patched-tooling-cve-refresh.timer",
            "patched-tooling-cve-refresh.timer was not restored",
        ):
            self.assertIn(evidence, text)

    def run_installer(self, *, existing_units: bool) -> tuple[tempfile.TemporaryDirectory, Path, subprocess.CompletedProcess[str], str]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        source = root / "source"
        systemd = root / "systemd"
        fakebin = root / "bin"
        for directory in (source, systemd, fakebin):
            directory.mkdir()
        (source / SERVICE).write_text(SERVICE_TEXT, encoding="utf-8")
        (source / TIMER).write_text(TIMER_TEXT, encoding="utf-8")
        guard = source / "verify-systemd-hardening-floor.sh"
        guard.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        guard.chmod(0o755)
        if existing_units:
            (systemd / SERVICE).write_text("old service\n", encoding="utf-8")
            (systemd / TIMER).write_text("old timer\n", encoding="utf-8")

        sync_bin = root / "patched-cve-sync"
        sync_bin.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        sync_bin.chmod(0o755)
        systemctl_log = root / "systemctl.log"
        enabled = root / "enabled"
        active = root / "active"
        fake_systemctl = fakebin / "systemctl"
        fake_systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_SYSTEMCTL_LOG\"\n"
            "case \"${1:-}\" in\n"
            "  is-enabled) [[ -f \"$FAKE_ENABLED\" ]] ;;\n"
            "  is-active) [[ -f \"$FAKE_ACTIVE\" ]] ;;\n"
            "  show) echo inactive ;;\n"
            "  daemon-reload) ;;\n"
            "  enable) [[ -f \"$FAKE_SYSTEMD_DIR/${2:-}\" ]] && touch \"$FAKE_ENABLED\" ;;\n"
            "  start) [[ -f \"$FAKE_SYSTEMD_DIR/${2:-}\" ]] && touch \"$FAKE_ACTIVE\" ;;\n"
            "  stop)\n"
            "    [[ -f \"$FAKE_SYSTEMD_DIR/${2:-}\" ]] || exit 5\n"
            "    rm -f \"$FAKE_ACTIVE\"\n"
            "    ;;\n"
            "  disable) rm -f \"$FAKE_ENABLED\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_systemctl.chmod(0o755)
        fake_install = fakebin / "install"
        fake_install.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "args=()\n"
            "while (($#)); do\n"
            "  case \"$1\" in -o|-g) shift 2 ;; *) args+=(\"$1\"); shift ;; esac\n"
            "done\n"
            "exec /usr/bin/install \"${args[@]}\"\n",
            encoding="utf-8",
        )
        fake_install.chmod(0o755)
        fake_mktemp = fakebin / "mktemp"
        fake_mktemp.write_text(
            "#!/usr/bin/env bash\n"
            "exec /usr/bin/mktemp -d \"$FAKE_MKTEMP_DIR/rollback.XXXXXX\"\n",
            encoding="utf-8",
        )
        fake_mktemp.chmod(0o755)
        if existing_units:
            enabled.touch()
            active.touch()
        env = os.environ | {
            "PATCHED_INSTALL_TEST_ROOT": "1",
            "PATCHED_SYSTEMCTL": str(fake_systemctl),
            "PATCHED_SYSTEMD_DIR": str(systemd),
            "PATCHED_TOOLING_CVE_SYNC_BIN": str(sync_bin),
            "FAKE_SYSTEMCTL_LOG": str(systemctl_log),
            "FAKE_SYSTEMD_DIR": str(systemd),
            "FAKE_MKTEMP_DIR": str(root),
            "FAKE_ENABLED": str(enabled),
            "FAKE_ACTIVE": str(active),
            "PATH": f"{fakebin}:/usr/bin:/bin",
        }
        result = subprocess.run(
            ["bash", str(INSTALL), str(source)],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        return temporary, systemd, result, systemctl_log.read_text(encoding="utf-8")

    def test_first_install_skips_absent_timer_stop_then_enables_and_starts_it(self) -> None:
        temporary, systemd, result, calls = self.run_installer(existing_units=False)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((systemd / SERVICE).read_text(encoding="utf-8"), SERVICE_TEXT)
        self.assertEqual((systemd / TIMER).read_text(encoding="utf-8"), TIMER_TEXT)
        self.assertNotIn(f"stop {TIMER}", calls)
        self.assertIn(f"enable {TIMER}", calls)
        self.assertIn(f"start {TIMER}", calls)
        self.assertIn(f"is-active --quiet {TIMER}", calls)

    def test_upgrade_still_quiesces_existing_timer_before_installing(self) -> None:
        temporary, _, result, calls = self.run_installer(existing_units=True)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"stop {TIMER}", calls)
        self.assertLess(calls.index(f"stop {TIMER}"), calls.index("daemon-reload"))


if __name__ == "__main__":
    unittest.main()
