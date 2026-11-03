import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SERVICE_TEXT = (ROOT / "api-vps-artefacts" / "patched-cve-sync.service").read_text()
TIMER_TEXT = (ROOT / "api-vps-artefacts" / "patched-cve-sync.timer").read_text()
SERVICE_SHA = hashlib.sha256(SERVICE_TEXT.encode()).hexdigest()
TIMER_SHA = hashlib.sha256(TIMER_TEXT.encode()).hexdigest()


class CVEPipelineDeploymentTests(unittest.TestCase):
    def run_installer(
        self,
        fail_service_start: bool = False,
        receipt_text: str | None = None,
        prior_service_result: str = "success",
        force_full: bool = False,
        source_service_text: str | None = None,
    ):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        source = root / "source"
        systemd = root / "systemd"
        runtime = root / "runtime"
        for directory in (source, systemd, runtime):
            directory.mkdir()
        service = "patched-cve-sync.service"
        timer = "patched-cve-sync.timer"
        (source / service).write_text(
            source_service_text if source_service_text is not None else SERVICE_TEXT
        )
        (source / timer).write_text(TIMER_TEXT)
        (systemd / service).write_text("legacy service\n")
        (systemd / timer).write_text("legacy timer\n")
        guard = source / "verify-systemd-hardening-floor.sh"
        guard.write_text("#!/usr/bin/env bash\nexit 0\n")
        guard.chmod(0o755)
        service_started_marker = root / "service-started"
        fake_systemctl = root / "systemctl"
        fake_systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            'printf \'%s\\n\' "$*" >> "$FAKE_SYSTEMCTL_LOG"\n'
            'case "${1:-}" in\n'
            "  is-enabled) echo enabled ;;\n"
            "  is-active) echo active ;;\n"
            "  show)\n"
            '    if [[ "${2:-}" == patched-cve-sync.service ]]; then\n'
            '      if [[ -f "$FAKE_SERVICE_STARTED_MARKER" ]]; then\n'
            "        echo success\n"
            "      else\n"
            '        echo "${FAKE_PRIOR_SERVICE_RESULT:-success}"\n'
            "      fi\n"
            "    else\n"
            "      echo success\n"
            "    fi ;;\n"
            "  start)\n"
            '    if [[ "${2:-}" == patched-cve-sync.service ]]; then\n'
            '      [[ "${FAIL_SERVICE_START:-0}" != 1 ]] || exit 1\n'
            '      touch "$FAKE_SERVICE_STARTED_MARKER"\n'
            "    fi ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n"
        )
        fake_systemctl.chmod(0o755)
        test_bin = root / "bin"
        test_bin.mkdir()
        fake_stat = test_bin / "stat"
        fake_stat.write_text(
            "#!/usr/bin/env python3\n"
            "import os, stat, sys\n"
            "value = os.stat(sys.argv[3])\n"
            "fields = {'%a': format(stat.S_IMODE(value.st_mode), 'o'), '%u': str(value.st_uid), '%g': str(value.st_gid)}\n"
            "out = sys.argv[2]\n"
            "for key, replacement in fields.items(): out = out.replace(key, replacement)\n"
            "print(out)\n"
        )
        fake_stat.chmod(0o755)
        receipt = root / "CVE_PIPELINE_ACTIVATED"
        receipt.write_text(
            receipt_text if receipt_text is not None else "DEPLOYED_SHA=previous\n"
        )
        env = os.environ.copy()
        env.update(
            {
                "PATCHED_INSTALL_TEST_ROOT": "1",
                "PATCHED_SYSTEMD_DIR": str(systemd),
                "PATCHED_RUNTIME_SYSTEMD_DIR": str(runtime),
                "PATCHED_SYSTEMCTL": str(fake_systemctl),
                "PATCHED_CVE_ACTIVATION_RECEIPT": str(receipt),
                "FAKE_SYSTEMCTL_LOG": str(root / "systemctl.log"),
                "FAKE_SERVICE_STARTED_MARKER": str(service_started_marker),
                "FAKE_PRIOR_SERVICE_RESULT": prior_service_result,
                "FAIL_SERVICE_START": "1" if fail_service_start else "0",
                "PATCHED_CVE_FORCE_FULL_ACTIVATION": "1" if force_full else "0",
                "PATH": str(test_bin) + os.pathsep + env["PATH"],
            }
        )
        result = subprocess.run(
            [
                "bash",
                str(ROOT / "deploy/api-01/install-cve-sync-systemd-units.sh"),
                str(source),
                "a" * 40,
            ],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        systemctl_log = (root / "systemctl.log").read_text() if (root / "systemctl.log").exists() else ""
        return tmp, root, systemd, receipt, result, systemctl_log

    def test_service_runs_explicit_serial_mode(self) -> None:
        service = (ROOT / "api-vps-artefacts/patched-cve-sync.service").read_text()
        self.assertIn(
            "ExecStart=/opt/patched-api/bin/patched-cve-sync --mode=scheduled",
            service,
        )

    def test_installer_preflights_before_swapping_units(self) -> None:
        script = (ROOT / "deploy/api-01/install-cve-sync-systemd-units.sh").read_text()
        preflight = script.index("--mode=os-sync --dry-run")
        swap = script.index('install -m 0644 -o root -g root "$SOURCE_DIR/$unit"')
        self.assertLess(preflight, swap)
        for required in (
            "rollback_units",
            '"$SYSTEMCTL" stop "$TIMER"',
            '"$SYSTEMCTL" daemon-reload',
            '"$SYSTEMCTL" start "$SERVICE"',
            "CVE_PIPELINE_ACTIVATED",
            "cmp -s",
        ):
            self.assertIn(required, script)

    def test_installer_success_atomically_replaces_units_and_receipt(self) -> None:
        # Default receipt ("DEPLOYED_SHA=previous\n") has no recorded unit
        # hashes at all, which is the "first activation" case: full run.
        tmp, _, systemd, receipt, result, systemctl_log = self.run_installer()
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "--mode=scheduled", (systemd / "patched-cve-sync.service").read_text()
        )
        self.assertIn("DEPLOYED_SHA=" + "a" * 40, receipt.read_text())
        self.assertIn("ACTIVATION_RUN=full", receipt.read_text())
        self.assertIn("start patched-cve-sync.service", systemctl_log)

    def test_installer_failure_restores_units_and_previous_receipt(self) -> None:
        tmp, _, systemd, receipt, result, _ = self.run_installer(
            fail_service_start=True
        )
        self.addCleanup(tmp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            (systemd / "patched-cve-sync.service").read_text(), "legacy service\n"
        )
        self.assertEqual(
            (systemd / "patched-cve-sync.timer").read_text(), "legacy timer\n"
        )
        self.assertEqual(receipt.read_text(), "DEPLOYED_SHA=previous\n")

    def _matching_receipt(self, extra: str = "") -> str:
        return (
            "DEPLOYED_SHA=" + "b" * 40 + "\n"
            f"patched-cve-sync.service={SERVICE_SHA}\n"
            f"patched-cve-sync.timer={TIMER_SHA}\n"
            "ACTIVATED_AT=2026-09-01T00:00:00Z\n"
            "ACTIVATION_RUN=full\n" + extra
        )

    def test_unchanged_units_and_prior_success_skips_full_run(self) -> None:
        tmp, _, systemd, receipt, result, systemctl_log = self.run_installer(
            receipt_text=self._matching_receipt(),
            prior_service_result="success",
        )
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("start patched-cve-sync.service", systemctl_log)
        self.assertIn("start patched-cve-sync.timer", systemctl_log)
        receipt_body = receipt.read_text()
        self.assertIn("DEPLOYED_SHA=" + "a" * 40, receipt_body)
        self.assertIn("ACTIVATION_RUN=skipped-units-unchanged", receipt_body)
        self.assertIn(f"patched-cve-sync.service={SERVICE_SHA}", receipt_body)
        self.assertIn(f"patched-cve-sync.timer={TIMER_SHA}", receipt_body)
        self.assertIn(
            "--mode=scheduled", (systemd / "patched-cve-sync.service").read_text()
        )

    def test_changed_unit_file_runs_full(self) -> None:
        tmp, _, _, receipt, result, systemctl_log = self.run_installer(
            receipt_text=self._matching_receipt(),
            prior_service_result="success",
            source_service_text=SERVICE_TEXT + "\n# a deliberate unit change\n",
        )
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("start patched-cve-sync.service", systemctl_log)
        self.assertIn("ACTIVATION_RUN=full", receipt.read_text())

    def test_prior_result_failed_runs_full(self) -> None:
        tmp, _, _, receipt, result, systemctl_log = self.run_installer(
            receipt_text=self._matching_receipt(),
            prior_service_result="failed",
        )
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("start patched-cve-sync.service", systemctl_log)
        self.assertIn("ACTIVATION_RUN=full", receipt.read_text())

    def test_malformed_receipt_runs_full(self) -> None:
        # A duplicate patched-cve-sync.service= line makes the hash ambiguous
        # (grep -c != 1), which must be treated as "cannot trust this", not
        # as a match on the first occurrence.
        malformed = self._matching_receipt(
            extra=f"patched-cve-sync.service={SERVICE_SHA}\n"
        )
        tmp, _, _, receipt, result, systemctl_log = self.run_installer(
            receipt_text=malformed,
            prior_service_result="success",
        )
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("start patched-cve-sync.service", systemctl_log)
        self.assertIn("ACTIVATION_RUN=full", receipt.read_text())

    def test_force_full_activation_override(self) -> None:
        tmp, _, _, receipt, result, systemctl_log = self.run_installer(
            receipt_text=self._matching_receipt(),
            prior_service_result="success",
            force_full=True,
        )
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("start patched-cve-sync.service", systemctl_log)
        self.assertIn("ACTIVATION_RUN=full", receipt.read_text())

    def test_workflow_stages_and_reads_back_activation(self) -> None:
        workflow = (ROOT / ".github/workflows/deploy-api-01.yml").read_text()
        deploy = workflow.index("- name: Run deploy.sh on api-01")
        activate = workflow.index(
            "- name: Preflight and activate serial CVE pipeline units"
        )
        verify = workflow.index("- name: Verify serial CVE pipeline activation receipt")
        self.assertLess(deploy, activate)
        self.assertLess(activate, verify)
        self.assertIn("install-cve-sync-systemd-units.sh", workflow)
        self.assertIn("CVE_PIPELINE_ACTIVATED", workflow)

    def test_migration_and_rollback_preserve_advisory_rows(self) -> None:
        migration = (
            ROOT / "go-service/migrations/0150_os_cve_pipeline_reconcile.sql"
        ).read_text()
        rollback = (
            ROOT / "go-service/migrations/0150_os_cve_pipeline_reconcile_rollback.sql"
        ).read_text()
        self.assertIn("unknown os_cve_advisories shape", migration)
        self.assertIn("numeric_precision", migration)
        self.assertIn("source_document_id", migration)
        self.assertIn("GRANT SELECT, INSERT, UPDATE, DELETE", migration)
        self.assertNotIn("DROP TABLE IF EXISTS os_cve_advisories", rollback)
        self.assertIn("DROP COLUMN IF EXISTS source_document_id", rollback)
        self.assertIn("REVOKE DELETE ON os_cve_advisories", rollback)


if __name__ == "__main__":
    unittest.main()
