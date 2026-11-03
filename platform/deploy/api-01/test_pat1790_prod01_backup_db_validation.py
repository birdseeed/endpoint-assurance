"""PAT-1790 regression tests for the prod-01 dashboard backup contract.

The real scripts run against command shims in a temporary directory. This
reproduces the live incident without Restic, credentials, a SQLite database or
root: a checkout-local source makes the shim create an empty snapshot, and a
failed count query is a real non-zero sqlite3 exit instead of a mocked Python
branch.

PAT-2313 added the backup's reports sources: the dashboard's state directory
(/var/lib/patched-dashboard/reports since PAT-2307) always, and the pre-move
code-tree copy (/opt/patched-dashboard/reports) only while it exists. The same
shims record which paths reach `restic backup`; the state directory and the
legacy directory are pointed into the temporary root through the script's
DASHBOARD_STATE_DIR and DASHBOARD_LEGACY_REPORTS_DIR defaults.

PAT-2314 covers the config snapshot: the live nginx site config and the
dashboard Origin Certificate and key, in place of a Caddy-era list that named
files this box no longer has and that restic skipped without complaint. A
configured path that is missing, a symlink or not a regular file must fail the
run and name the path. The script's PATCHED_BACKUP_CONFIG_ROOT prefix points the
list at a temporary directory, the way DASHBOARD_STATE_DIR does for reports.

The retention checks record the real script's Restic arguments: timestamped
database paths must share one host group, scoped to dashboard-db on prod-01,
before the original policy runs with default grouping for the other classes.

Run with: python3 -m unittest deploy.api-01.test_pat1790_prod01_backup_db_validation -v
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_DIR = REPO_ROOT / "api-vps-artefacts" / "prod-01-backup"
BACKUP_SCRIPT = BACKUP_DIR / "prod-backup.sh"
RESTORE_SCRIPT = BACKUP_DIR / "restore-test.sh"

# PAT-2314: what the "config" snapshot must hold on patched-prod-01. The box
# serves through nginx (sites-enabled/dashboard.patched.im is a symlink to the
# sites-available file, which restic would store as a symlink), with the
# Cloudflare Origin Certificate and key that site names.
CONFIG_SOURCES = (
    "/etc/patched-dashboard/dashboard.env",
    "/etc/patched-dashboard/backup.env",
    "/etc/ssl/dashboard.patched.im.pem",
    "/etc/ssl/dashboard.patched.im.key",
    "/etc/nginx/sites-available/dashboard.patched.im",
)
# The Caddy-era paths the list used to name. None exists on the box.
DEAD_CONFIG_SOURCES = (
    "/etc/ssl/patched.im.pem",
    "/etc/ssl/patched.im.key",
    "/etc/caddy/Caddyfile",
)


class Prod01BackupDatabaseValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.log = self.root / "commands.log"
        # The state directory as PAT-2307 lays it out; the legacy code-tree
        # reports directory is absent unless a test creates it.
        self.state_dir = self.root / "var" / "lib" / "patched-dashboard"
        self.reports_dir = self.state_dir / "reports"
        self.reports_dir.mkdir(parents=True)
        self.legacy_reports_dir = self.root / "opt" / "patched-dashboard" / "reports"
        # Every configured config file exists unless a test removes it.
        self.config_root = self.root / "config"
        for source in CONFIG_SOURCES:
            path = self._config_path(source)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("config\n", encoding="utf-8")
        self._write_shim("id", """#!/bin/bash
if [ \"${1:-}\" = \"-u\" ]; then
  echo 0
  exit 0
fi
exec /usr/bin/id \"$@\"
""")
        self._write_shim("sqlite3", """#!/bin/bash
set -euo pipefail
if [ "${1:-}" = "-bail" ]; then shift; fi
db=\"$1\"
query=\"${2:-}\"
if [[ \"$query\" == .backup\\ * ]]; then
  target=\"${query#.backup }\"
  if [ \"$db\" = \"${EXPECTED_DB:-}\" ]; then
    printf 'sqlite snapshot\\n' > \"$target\"
  else
    : > \"$target\"
  fi
  exit 0
fi
case \"$query\" in
  'PRAGMA integrity_check;')
    if [ \"${FAKE_SQLITE_INTEGRITY:-ok}\" = \"ok\" ]; then echo ok; else echo corrupt; fi
    ;;
  *'FROM scans;'*)
    schema=\"${FAKE_SQLITE_SCHEMA:-ok}\"
    case \"$db\" in /tmp/dashboard-*) schema=\"${FAKE_SNAPSHOT_SCHEMA:-$schema}\" ;; esac
    [ \"$schema\" != \"missing-scans\" ] || exit 1
    echo 0
    ;;
  *'FROM clients;'*)
    schema=\"${FAKE_SQLITE_SCHEMA:-ok}\"
    case \"$db\" in /tmp/dashboard-*) schema=\"${FAKE_SNAPSHOT_SCHEMA:-$schema}\" ;; esac
    [ \"$schema\" != \"missing-clients\" ] || exit 1
    echo 0
    ;;
  *) exit 1 ;;
esac
""")
        self._write_shim("restic", """#!/bin/bash
set -euo pipefail
printf '%s:%s\\n' \"$1\" \"$*\" >> \"$FAKE_LOG\"
case \"$1\" in
  snapshots)
    printf '%s' \"${RESTIC_SNAPSHOTS_JSON:?}\"
    ;;
  restore)
    snapshot=\"$2\"
    shift 2
    target=\"\"
    while [ \"$#\" -gt 0 ]; do
      if [ \"$1\" = \"--target\" ]; then target=\"$2\"; break; fi
      shift
    done
    mkdir -p \"$target/tmp\"
    if [ \"${RESTORE_DB_MODE:-valid}\" = \"empty\" ]; then
      : > \"$target/tmp/dashboard-${snapshot}.db\"
    else
      printf 'restored snapshot %s\\n' \"$snapshot\" > \"$target/tmp/dashboard-${snapshot}.db\"
    fi
    ;;
  forget)
    scope=general
    case " $* " in *' --tag dashboard-db '*) scope=database ;; esac
    if [ "${FAKE_RESTIC_FORGET_FAIL:-}" = "$scope" ]; then exit 42; fi
    ;;
  backup|check) : ;;
  *) exit 1 ;;
esac
""")
        self._write_shim("scp", """#!/bin/bash
set -euo pipefail
printf 'scp:%s\\n' "$*" >> "$FAKE_LOG"
exit "${FAKE_SCP_EXIT:-0}"
""")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _config_path(self, source: str) -> Path:
        return Path(str(self.config_root) + source)

    def _write_shim(self, name: str, content: str) -> None:
        path = self.bin_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _env(self, **overrides: str) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:{env['PATH']}",
                "FAKE_LOG": str(self.log),
                "PATCHED_BACKUP_HEALTH_DIR": str(self.root / "health"),
                "API01_TAILSCALE_IP": "",
                "ADMIN_API_TOKEN": "",
                "DASHBOARD_STATE_DIR": str(self.state_dir),
                "DASHBOARD_LEGACY_REPORTS_DIR": str(self.legacy_reports_dir),
                "PATCHED_BACKUP_CONFIG_ROOT": str(self.config_root),
            }
        )
        env.update(overrides)
        return env

    def _live_db(self) -> Path:
        live_db = self.state_dir / "dashboard.db"
        live_db.write_text("real dashboard database", encoding="utf-8")
        return live_db

    def _backups(self) -> dict[str, list[str]]:
        """Each `restic backup` call's source paths, keyed by its kind tag."""
        calls: dict[str, list[str]] = {}
        if not self.log.exists():
            return calls
        for line in self.log.read_text(encoding="utf-8").splitlines():
            if not line.startswith("backup:"):
                continue
            argv = shlex.split(line[len("backup:"):])[1:]
            sources = [arg for arg in argv if not arg.startswith("--")]
            tags = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--tag"]
            sources = [arg for arg in sources if arg not in tags]
            kind = next(tag for tag in tags if not tag[:1].isdigit())
            self.assertNotIn(kind, calls, f"two backups tagged {kind}")
            calls[kind] = sources
        return calls

    def _backup_health(self) -> dict[str, object]:
        return json.loads((self.root / "health" / "prod-r2.json").read_text(encoding="utf-8"))

    def _run(self, script: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(script)], cwd=REPO_ROOT, env=env,
            capture_output=True, text=True, timeout=20,
        )

    def _health(self) -> dict[str, object]:
        return json.loads((self.root / "health" / "prod-r2-drill.json").read_text(encoding="utf-8"))

    def test_backup_uses_configured_live_database_not_checkout_local_path(self) -> None:
        live_db = self.root / "var" / "lib" / "patched-dashboard" / "dashboard.db"
        live_db.parent.mkdir(parents=True, exist_ok=True)
        live_db.write_text("real dashboard database", encoding="utf-8")

        result = self._run(
            BACKUP_SCRIPT,
            self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        first_backup = next(line for line in self.log.read_text().splitlines() if line.startswith("backup:"))
        self.assertIn("/tmp/dashboard-", first_backup)

    def test_backup_fails_before_upload_for_an_empty_configured_database(self) -> None:
        live_db = self.root / "empty-dashboard.db"
        live_db.touch()

        result = self._run(
            BACKUP_SCRIPT,
            self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists(), "an invalid source must not reach Restic")

    def test_backup_fails_closed_when_database_path_is_not_configured(self) -> None:
        result = self._run(BACKUP_SCRIPT, self._env())

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DASHBOARD_DB_PATH", result.stderr)
        self.assertFalse(self.log.exists(), "an unconfigured source must not reach Restic")

    def test_backup_rejects_a_snapshot_missing_required_schema_before_upload(self) -> None:
        live_db = self.root / "dashboard.db"
        live_db.write_text("real dashboard database", encoding="utf-8")

        result = self._run(
            BACKUP_SCRIPT,
            self._env(
                DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db),
                FAKE_SNAPSHOT_SCHEMA="missing-scans",
            ),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists(), "a schema-invalid snapshot must not reach Restic")

    # -- PAT-2313: what the backup covers ------------------------------------

    def test_backup_covers_the_state_dir_reports_and_database(self) -> None:
        live_db = self._live_db()

        result = self._run(
            BACKUP_SCRIPT, self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        backups = self._backups()
        self.assertEqual(backups["dashboard-reports"], [str(self.reports_dir)])
        # The database goes up only as its sqlite3 .backup snapshot, never as
        # the live WAL-mode file.
        self.assertEqual(len(backups["dashboard-db"]), 1)
        self.assertRegex(backups["dashboard-db"][0], r"^/tmp/dashboard-\d{8}_\d{6}\.db$")
        for sources in backups.values():
            self.assertNotIn(str(live_db), sources)
        self.assertNotIn("/opt/patched-dashboard/reports", " ".join(backups["dashboard-reports"]))
        self.assertIn("backing up " + str(self.reports_dir) + " only", result.stdout)
        self.assertEqual(self._backup_health()["status"], "ok")

    def test_backup_keeps_the_legacy_reports_dir_while_it_exists(self) -> None:
        live_db = self._live_db()
        self.legacy_reports_dir.mkdir(parents=True)

        result = self._run(
            BACKUP_SCRIPT, self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._backups()["dashboard-reports"],
            [str(self.reports_dir), str(self.legacy_reports_dir)],
        )

    def test_backup_ignores_a_legacy_reports_symlink(self) -> None:
        live_db = self._live_db()
        self.legacy_reports_dir.parent.mkdir(parents=True)
        self.legacy_reports_dir.symlink_to(self.root / "bin")

        result = self._run(
            BACKUP_SCRIPT, self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._backups()["dashboard-reports"], [str(self.reports_dir)])

    def test_backup_defaults_to_the_production_state_dir(self) -> None:
        # Without the test override the script must look in the production
        # state directory, not the code tree. That path does not exist here,
        # so the run stops at the reports step and names it.
        live_db = self._live_db()
        env = self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db))
        del env["DASHBOARD_STATE_DIR"]

        result = self._run(BACKUP_SCRIPT, env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/var/lib/patched-dashboard/reports", result.stderr)
        self.assertNotIn("dashboard-reports", self._backups())

    def test_backup_fails_and_reports_fail_when_the_reports_dir_is_missing(self) -> None:
        live_db = self._live_db()
        self.reports_dir.rmdir()
        self.legacy_reports_dir.mkdir(parents=True)

        result = self._run(
            BACKUP_SCRIPT, self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"reports directory {self.reports_dir} is missing", result.stderr)
        backups = self._backups()
        # The database snapshot was already uploaded; the reports and the rest
        # of the run were not, and the heartbeat says so.
        self.assertIn("dashboard-db", backups)
        self.assertNotIn("dashboard-reports", backups)
        self.assertEqual(self._backup_health()["status"], "fail")

    def test_backup_fails_when_the_reports_dir_is_a_symlink(self) -> None:
        live_db = self._live_db()
        self.reports_dir.rmdir()
        self.reports_dir.symlink_to(self.root / "bin")

        result = self._run(
            BACKUP_SCRIPT, self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db)),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("dashboard-reports", self._backups())
        self.assertEqual(self._backup_health()["status"], "fail")

    # -- PAT-2314: what the config snapshot covers ---------------------------

    def _run_backup(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        live_db = self._live_db()
        return self._run(
            BACKUP_SCRIPT,
            self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db), **overrides),
        )

    def test_backup_retention_groups_only_prod01_database_snapshots_by_host(self) -> None:
        result = self._run_backup()

        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [
            shlex.split(line.split(":", 1)[1])
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]
        policy = ["--keep-daily", "7", "--keep-weekly", "4", "--keep-monthly", "3"]
        self.assertEqual(
            [argv for argv in commands if argv[0] == "forget"],
            [
                ["forget", "--group-by", "host", "--host", "patched-prod-01", "--tag", "dashboard-db", *policy],
                ["forget", *policy, "--prune"],
            ],
            "database retention must ignore unique paths/month tags without grouping config or reports together",
        )
        self.assertEqual([argv[0] for argv in commands], ["backup"] * 3 + ["forget"] * 2 + ["check"])
        self.assertEqual(self._backup_health()["status"], "ok")

    def test_backup_stops_and_reports_failure_when_either_retention_command_fails(self) -> None:
        for scope, expected_forgets in (("database", 1), ("general", 2)):
            with self.subTest(scope=scope):
                self.log.unlink(missing_ok=True)
                result = self._run_backup(FAKE_RESTIC_FORGET_FAIL=scope)

                self.assertEqual(result.returncode, 42, result.stderr)
                commands = self.log.read_text(encoding="utf-8").splitlines()
                self.assertEqual(sum(line.startswith("forget:") for line in commands), expected_forgets)
                self.assertFalse(any(line.startswith("check:") for line in commands))
                self.assertEqual(self._backup_health()["status"], "fail")
                self.assertNotIn("patched-prod-backup: done", result.stdout)

    def test_backup_config_snapshot_holds_the_live_nginx_and_cert_paths(self) -> None:
        result = self._run_backup()

        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = str(self.config_root)
        sources = self._backups()["config"]
        self.assertEqual(sources, [prefix + source for source in CONFIG_SOURCES])
        stripped = [source[len(prefix):] for source in sources]
        for dead in DEAD_CONFIG_SOURCES:
            self.assertNotIn(dead, stripped)
        # The real site file, not the sites-enabled symlink to it.
        self.assertNotIn("/etc/nginx/sites-enabled/dashboard.patched.im", stripped)
        self.assertEqual(self._backup_health()["status"], "ok")

    def test_backup_config_snapshot_defaults_to_the_production_paths(self) -> None:
        # Without the test prefix the list is the absolute production paths.
        # None of them exists on a development machine or CI runner, so the
        # run stops at the config check and names every one, in order.
        if any(Path(source).exists() for source in CONFIG_SOURCES + DEAD_CONFIG_SOURCES):
            self.skipTest("this machine has production config paths")
        live_db = self._live_db()
        env = self._env(DASHBOARD_DB_PATH=str(live_db), EXPECTED_DB=str(live_db))
        del env["PATCHED_BACKUP_CONFIG_ROOT"]

        result = self._run(BACKUP_SCRIPT, env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(": " + " ".join(CONFIG_SOURCES), result.stderr)
        for dead in DEAD_CONFIG_SOURCES:
            self.assertNotIn(dead, result.stderr)
        self.assertNotIn("config", self._backups())

    def test_backup_fails_and_names_each_configured_config_path_that_is_missing(self) -> None:
        for source in CONFIG_SOURCES:
            with self.subTest(source=source):
                self.log.unlink(missing_ok=True)
                path = self._config_path(source)
                path.rename(path.with_name(path.name + ".gone"))
                try:
                    result = self._run_backup()
                finally:
                    path.with_name(path.name + ".gone").rename(path)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(path), result.stderr)
                backups = self._backups()
                # The database and reports were already uploaded; the config
                # snapshot, retention and the integrity check were not, and the
                # heartbeat says so rather than recording a smaller backup.
                self.assertIn("dashboard-db", backups)
                self.assertIn("dashboard-reports", backups)
                self.assertNotIn("config", backups)
                self.assertNotIn("forget:", self.log.read_text(encoding="utf-8"))
                self.assertEqual(self._backup_health()["status"], "fail")

    def test_backup_names_every_missing_config_path_not_only_the_first(self) -> None:
        missing = [self._config_path(source) for source in CONFIG_SOURCES[2:4]]
        for path in missing:
            path.unlink()

        result = self._run_backup()

        self.assertNotEqual(result.returncode, 0)
        for path in missing:
            self.assertIn(str(path), result.stderr)
        self.assertNotIn(str(self._config_path(CONFIG_SOURCES[0])), result.stderr)
        self.assertNotIn("config", self._backups())

    def test_backup_fails_when_a_configured_config_path_is_a_symlink(self) -> None:
        # sites-enabled/dashboard.patched.im is a symlink on the box, and restic
        # would store a symlink as a symlink, not the file behind it.
        site = self._config_path("/etc/nginx/sites-available/dashboard.patched.im")
        site.rename(site.with_name("moved"))
        site.symlink_to(site.with_name("moved"))

        result = self._run_backup()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(site), result.stderr)
        self.assertNotIn("config", self._backups())
        self.assertEqual(self._backup_health()["status"], "fail")

    def test_backup_fails_when_a_configured_config_path_is_a_directory(self) -> None:
        key = self._config_path("/etc/ssl/dashboard.patched.im.key")
        key.unlink()
        key.mkdir()

        result = self._run_backup()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(key), result.stderr)
        self.assertNotIn("config", self._backups())

    def test_backup_records_the_missing_config_path_in_the_automations_record(self) -> None:
        body = self.root / "record-body.json"
        self._write_shim("curl", """#!/bin/bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data" ]; then printf '%s' "$2" > "$FAKE_CURL_BODY"; fi
  shift
done
printf 200
""")
        missing = self._config_path("/etc/nginx/sites-available/dashboard.patched.im")
        missing.unlink()

        result = self._run_backup(ADMIN_API_TOKEN="test-token", FAKE_CURL_BODY=str(body))

        self.assertNotEqual(result.returncode, 0)
        record = json.loads(body.read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "failed")
        self.assertIn(str(missing), record["error_msg"])

    def test_restore_selects_the_newest_snapshot_by_timestamp_not_json_position(self) -> None:
        backup_env = self.root / "backup.env"
        backup_env.write_text("API01_TAILSCALE_IP=100.64.10.1\n", encoding="utf-8")
        snapshots = [
            {"id": "newest", "time": "2026-09-15T12:00:00Z"},
            {"id": "older", "time": "2026-09-01T12:00:00Z"},
        ]

        result = self._run(
            RESTORE_SCRIPT,
            self._env(
                PATCHED_BACKUP_ENV=str(backup_env),
                RESTIC_SNAPSHOTS_JSON=json.dumps(snapshots),
                API01_TAILSCALE_IP="100.64.10.1",
            ),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        command_log = self.log.read_text(encoding="utf-8")
        self.assertIn("restore:restore newest", command_log)
        scp_args = shlex.split(next(line for line in command_log.splitlines() if line.startswith("scp:"))[4:])
        self.assertEqual(
            scp_args[:12],
            ["-q", "-O", "-i", "/root/.ssh/id_prod_backup", "-P", "2222", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes"],
        )
        self.assertEqual(scp_args[-1], "root@100.64.10.1:/srv/backup/health/prod-r2-drill.json")
        self.assertEqual(self._health()["status"], "ok")

    def test_restore_logs_but_does_not_fail_when_heartbeat_replication_fails(self) -> None:
        backup_env = self.root / "backup.env"
        backup_env.write_text("API01_TAILSCALE_IP=100.64.10.1\n", encoding="utf-8")
        snapshots = [{"id": "snapshot", "time": "2026-09-15T12:00:00Z"}]

        result = self._run(
            RESTORE_SCRIPT,
            self._env(
                PATCHED_BACKUP_ENV=str(backup_env),
                RESTIC_SNAPSHOTS_JSON=json.dumps(snapshots),
                FAKE_SCP_EXIT="1",
            ),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("restore heartbeat replication failed", result.stderr)
        self.assertEqual(self._health()["status"], "ok")

    def test_restore_fails_and_reports_fail_when_a_required_table_query_fails(self) -> None:
        backup_env = self.root / "backup.env"
        backup_env.write_text("API01_TAILSCALE_IP=\n", encoding="utf-8")
        snapshots = [{"id": "snapshot", "time": "2026-09-15T12:00:00Z"}]

        result = self._run(
            RESTORE_SCRIPT,
            self._env(
                PATCHED_BACKUP_ENV=str(backup_env),
                RESTIC_SNAPSHOTS_JSON=json.dumps(snapshots),
                FAKE_SQLITE_SCHEMA="missing-scans",
            ),
        )

        self.assertNotEqual(result.returncode, 0)
        health = self._health()
        self.assertEqual(health["status"], "fail")
        self.assertIn("scans", health["detail"])

    def test_restore_fails_and_reports_fail_for_an_empty_restored_database(self) -> None:
        backup_env = self.root / "backup.env"
        backup_env.write_text("API01_TAILSCALE_IP=\n", encoding="utf-8")
        snapshots = [{"id": "snapshot", "time": "2026-09-15T12:00:00Z"}]

        result = self._run(
            RESTORE_SCRIPT,
            self._env(
                PATCHED_BACKUP_ENV=str(backup_env),
                RESTIC_SNAPSHOTS_JSON=json.dumps(snapshots),
                RESTORE_DB_MODE="empty",
            ),
        )

        self.assertNotEqual(result.returncode, 0)
        health = self._health()
        self.assertEqual(health["status"], "fail")
        self.assertIn("empty", health["detail"])


if __name__ == "__main__":
    unittest.main()
