"""PAT-1788 regression checks for prod-01 backup executable ownership.

The dashboard deployment recursively changes /opt/patched-dashboard to
www-data:www-data. These root systemd units must therefore execute scripts
installed into the administrator-owned libexec directory, with their source
installer pinning root:root mode 0750. This is a source-level contract test:
it is deterministic and runs before the production deploy workflow connects to
the host.

Run with: python3 -m unittest deploy.api-01.test_pat1788_prod01_backup_operational_path -v
"""

from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_DIR = REPO_ROOT / "api-vps-artefacts" / "prod-01-backup"
INSTALLER = BACKUP_DIR / "install.sh"
BACKUP_UNIT = BACKUP_DIR / "patched-prod-backup.service"
RESTORE_UNIT = BACKUP_DIR / "patched-prod-restore-test.service"
BACKUP_SCRIPT = BACKUP_DIR / "prod-backup.sh"
ENV_TEMPLATE = BACKUP_DIR / "backup.env.template"
OPERATIONAL_DIR = "/usr/local/libexec/patched-prod-backup"
LEGACY_DIR = "/opt/patched-dashboard/bin"
CANONICAL_DB_DIR = "/var/lib/patched-dashboard"
STATE_REPORTS_DIR = f"{CANONICAL_DB_DIR}/reports"


class Prod01BackupOperationalPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = INSTALLER.read_text(encoding="utf-8")
        cls.backup_unit = BACKUP_UNIT.read_text(encoding="utf-8")
        cls.restore_unit = RESTORE_UNIT.read_text(encoding="utf-8")
        cls.backup_script = BACKUP_SCRIPT.read_text(encoding="utf-8")
        cls.env_template = ENV_TEMPLATE.read_text(encoding="utf-8")

    def test_both_active_execstarts_use_the_root_owned_operational_directory(self):
        expected = {
            self.backup_unit: f"ExecStart={OPERATIONAL_DIR}/prod-backup.sh",
            self.restore_unit: f"ExecStart={OPERATIONAL_DIR}/restore-test.sh",
        }
        for unit, execstart in expected.items():
            self.assertIn(execstart, unit)
            self.assertNotIn(f"ExecStart={LEGACY_DIR}/", unit)

    def test_installer_provisions_directory_and_scripts_root_owned_mode_0750(self):
        self.assertIn(f"LIBEXEC={OPERATIONAL_DIR}", self.installer)
        self.assertIn('install -d -m 750 -o root -g root "$LIBEXEC"', self.installer)
        for script in ("prod-backup.sh", "restore-test.sh"):
            self.assertIn(
                f'install -m 750 -o root -g root "$HERE/{script}"', self.installer
            )
            self.assertIn(f'"$LIBEXEC/{script}"', self.installer)

    def test_upgrade_removes_only_the_two_superseded_checkout_copies_after_reload(self):
        self.assertIn(f"LEGACY_BIN={LEGACY_DIR}", self.installer)
        removal = 'rm -f -- "$LEGACY_BIN/prod-backup.sh" "$LEGACY_BIN/restore-test.sh"'
        self.assertIn(removal, self.installer)
        self.assertNotIn('rm -rf "$LEGACY_BIN"', self.installer)
        self.assertGreater(
            self.installer.index(removal), self.installer.index("systemctl daemon-reload"),
            "remove legacy files only after systemd has loaded the new ExecStart paths",
        )

    def test_restore_unit_keeps_the_empty_capability_set(self):
        self.assertIn("NoNewPrivileges=true", self.restore_unit)
        self.assertIn("CapabilityBoundingSet=", self.restore_unit)
        self.assertNotIn("CapabilityBoundingSet=CAP_DAC_OVERRIDE", self.restore_unit)

    def test_backup_unit_grants_wal_write_access_only_to_the_canonical_database_directory(self):
        read_write_paths = next(
            line for line in self.backup_unit.splitlines() if line.startswith("ReadWritePaths=")
        )
        self.assertEqual(
            read_write_paths,
            f"ReadWritePaths=-/srv/backup/health {CANONICAL_DB_DIR}",
        )
        self.assertNotIn("/opt/patched-dashboard", read_write_paths)
        self.assertIn("DASHBOARD_DB_PATH", self.backup_unit)

    # -- PAT-2313: the backup reads the dashboard's state directory -----------

    def test_backup_sources_are_the_state_dir_reports_and_database(self):
        code = [
            line.strip() for line in self.backup_script.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertIn(f"STATE_DIR=${{DASHBOARD_STATE_DIR:-{CANONICAL_DB_DIR}}}", code)
        self.assertIn('REPORTS_DIR="${STATE_DIR}/reports"', code)
        self.assertIn('REPORT_SOURCES=("$REPORTS_DIR")', code)
        # The code-tree path survives only as the optional legacy source.
        tree_reports = [line for line in code if "/opt/patched-dashboard/reports" in line]
        self.assertEqual(
            tree_reports,
            ["LEGACY_REPORTS_DIR=${DASHBOARD_LEGACY_REPORTS_DIR:-/opt/patched-dashboard/reports}"],
        )
        # The database is the configured DASHBOARD_DB_PATH, which the template
        # points at the state directory.
        self.assertIn(f"DASHBOARD_DB_PATH={CANONICAL_DB_DIR}/dashboard.db", self.env_template.splitlines())

    def test_backup_unit_sandbox_lets_root_read_the_state_dir(self):
        directives = [
            line.strip() for line in self.backup_unit.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        def values(key: str) -> list[str]:
            return [line.split("=", 1)[1] for line in directives if line.startswith(f"{key}=")]

        self.assertEqual(values("User"), ["root"])
        # ProtectSystem=strict makes the file system read-only, not unreadable,
        # and the state directory is granted outright for the WAL sidecars.
        self.assertEqual(values("ProtectSystem"), ["strict"])
        granted = " ".join(values("ReadWritePaths")).split()
        self.assertIn(CANONICAL_DB_DIR, granted)
        # Nothing may hide or replace the state directory or its reports/.
        for key in ("InaccessiblePaths", "TemporaryFileSystem", "BindPaths", "BindReadOnlyPaths"):
            for value in values(key):
                for entry in value.split():
                    path = entry.lstrip("-+").split(":", 1)[0]
                    self.assertFalse(
                        STATE_REPORTS_DIR.startswith(path.rstrip("/") + "/")
                        or STATE_REPORTS_DIR == path,
                        f"{key}={value} covers {STATE_REPORTS_DIR}",
                    )
        # /var/lib/patched-dashboard and reports/ are www-data 0750 on the box.
        # Root reads them only with DAC override (or read-search) in its
        # bounding set; an empty set, like the restore unit's, cannot.
        caps = " ".join(values("CapabilityBoundingSet")).split()
        self.assertTrue(
            {"CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"} & set(caps),
            f"CapabilityBoundingSet={caps} cannot read a www-data 0750 directory",
        )
        self.assertFalse(values("DynamicUser"))

    def test_backup_unit_sandbox_does_not_hide_the_config_snapshot_paths(self):
        # PAT-2314: the config snapshot reads the env files, the Origin
        # Certificate and key, and the nginx site config. ProtectSystem=strict
        # leaves /etc readable; only a directive that hides or replaces a
        # directory would break the read, so none may cover these.
        config_dirs = ("/etc/patched-dashboard", "/etc/ssl", "/etc/nginx/sites-available")
        directives = [
            line.strip() for line in self.backup_unit.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        for key in ("InaccessiblePaths", "TemporaryFileSystem", "BindPaths", "BindReadOnlyPaths"):
            for line in directives:
                if not line.startswith(f"{key}="):
                    continue
                for entry in line.split("=", 1)[1].split():
                    path = entry.lstrip("-+").split(":", 1)[0].rstrip("/")
                    for config_dir in config_dirs:
                        self.assertFalse(
                            config_dir == path or config_dir.startswith(path + "/"),
                            f"{line} covers {config_dir}",
                        )
        self.assertIn("ProtectSystem=strict", self.backup_unit)


if __name__ == "__main__":
    unittest.main()
