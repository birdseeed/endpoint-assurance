"""PAT-1431: api-vps-artefacts/patched-maintenance-facts.sh's
stray_config_backups reporting.

Ported identically from dashboard/deploy/patched-maintenance-facts.sh's
PAT-1408 addition (dashboard/tests/test_pat1408_stray_config_backups.py is
the model this file mirrors) -- same field set, same broadened naming-match
rules, same fail-closed-on-unparseable-mode semantics. Before this ticket,
api-01's row read "stray config backups: not reported by this emitter" even
though /etc/patched-api is exactly where PAT-1361 originally found stray
credential copies. This closes that gap for api-01; portal/deploy/patched-
maintenance-facts.sh (PAT-1431, sibling repo) closes it for portal-01.

Driven the same way test_maintenance_facts_prometheus_rules.py (same
directory) already drives this script from Python: subprocess against the
real script, PATH-shimmed rather than mocked in Python, run against a temp
tree.

  `id` -> shimmed to satisfy the script's root preflight check (this runs as
      an ordinary user in CI and locally).
  `stat` -> a GNU `stat -c` shim (this Mac's BSD stat has no -c, and the
      script's own PAT-1431 section calls `stat -c '%a'/'%U'/'%G'` to read
      each stray's mode/owner/group). Honours two env vars,
      FAKE_STAT_BROKEN_BASENAME and FAKE_STAT_BROKEN_MODE, letting a test
      simulate `stat -c '%a'` returning something unparseable for one
      specific file -- the mode-parse-failure-must-fail-closed case.

apt-check/pro/kernel/apt-config/systemctl all fail gracefully under the
script's own `|| true`/`2>/dev/null` guards on this non-Linux/non-apt dev
machine (same as test_maintenance_facts_prometheus_rules.py relies on) --
nothing else needs shimming.

Run with: python3 -m unittest deploy.api-01.test_pat1431_stray_config_backups -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import json
import os
import stat as stat_module
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.sh"


class MaintenanceFactsStrayConfigBackupsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()

        id_shim = self.fake_bin / "id"
        id_shim.write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
            'exec /usr/bin/id "$@"\n'
        )

        stat_shim = self.fake_bin / "stat"
        stat_shim.write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "-c" ]; then\n'
            '    fmt="$2"; path="$3"; base="$(basename "$path")"\n'
            '    if [ "$fmt" = "%a" ] && [ -n "${FAKE_STAT_BROKEN_BASENAME:-}" ] '
            '&& [ "$base" = "$FAKE_STAT_BROKEN_BASENAME" ]; then\n'
            '        printf "%s" "${FAKE_STAT_BROKEN_MODE:-}"\n'
            '        exit 0\n'
            '    fi\n'
            '    exec python3 -c "\n'
            "import os, sys, grp, pwd\n"
            "fmt, path = sys.argv[1], sys.argv[2]\n"
            "st = os.stat(path)\n"
            "out = fmt.replace(\\\"%a\\\", format(st.st_mode & 0o7777, \\\"o\\\"))\n"
            "out = out.replace(\\\"%U\\\", pwd.getpwuid(st.st_uid).pw_name)\n"
            "out = out.replace(\\\"%G\\\", grp.getgrgid(st.st_gid).gr_name)\n"
            'print(out)\n'
            '" "$fmt" "$path"\n'
            "    exit 0\n"
            "fi\n"
            "exit 1\n"
        )

        for f in (id_shim, stat_shim):
            f.chmod(f.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)

        self.out_file = self.root / "out" / "maintenance.json"
        self.config_root = self.root / "etcroot"

    def _run(self, broken_stat_basename=None, broken_stat_mode=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env["OUT_FILE"] = str(self.out_file)
        env["CONFIG_BACKUP_ROOT"] = str(self.config_root)
        if broken_stat_basename is not None:
            env["FAKE_STAT_BROKEN_BASENAME"] = broken_stat_basename
            env["FAKE_STAT_BROKEN_MODE"] = broken_stat_mode or ""
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.out_file.exists(), result.stderr)
        data = json.loads(self.out_file.read_text())
        return result, data

    @staticmethod
    def _chmod_octal(path: Path, mode: int) -> None:
        path.chmod(mode)

    # ── basic detection across dirs, permission classification ──────────

    def test_finds_group_readable_and_root_only_strays_across_dirs(self):
        (self.config_root / "patched-dashboard").mkdir(parents=True)
        (self.config_root / "patched-api").mkdir(parents=True)
        # portal-01's directory doesn't exist on this box -- must be
        # silently skipped, not an error.

        readable = self.config_root / "patched-dashboard" / "dashboard.env.bak-pat687"
        readable.write_text("SECRET=1\n")
        self._chmod_octal(readable, 0o640)

        root_only = self.config_root / "patched-api" / "api.env.pre-pat909-config"
        root_only.write_text("SECRET=2\n")
        self._chmod_octal(root_only, 0o600)

        (self.config_root / "patched-dashboard" / "notes.txt").write_text("irrelevant\n")

        _, data = self._run()
        strays = {e["path"]: e for e in data["stray_config_backups"]}
        self.assertIn(str(readable), strays)
        self.assertIn(str(root_only), strays)
        self.assertEqual(len(strays), 2)

        r = strays[str(readable)]
        self.assertEqual(r["mode"], "0640")
        self.assertTrue(r["group_readable"])
        self.assertFalse(r["world_readable"])
        self.assertFalse(r["mode_unknown"])

        ro = strays[str(root_only)]
        self.assertEqual(ro["mode"], "0600")
        self.assertFalse(ro["group_readable"])
        self.assertFalse(ro["world_readable"])

    def test_world_readable_stray_is_flagged(self):
        (self.config_root / "patched-portal").mkdir(parents=True)
        f = self.config_root / "patched-portal" / "portal.env.bak-<timestamp>pat936"
        f.write_text("SECRET=3\n")
        self._chmod_octal(f, 0o644)

        _, data = self._run()
        self.assertEqual(len(data["stray_config_backups"]), 1)
        self.assertTrue(data["stray_config_backups"][0]["world_readable"])

    # ── scope exclusions ─────────────────────────────────────────────────

    def test_does_not_scan_the_backup_job_directory(self):
        """patched-portal-backup is the backup job's own config directory,
        not a service config directory -- its *.bak* contents (e.g. the real
        backup.env.bak-preconfig on portal-01) are legitimate and must never
        be flagged."""
        (self.config_root / "patched-portal-backup").mkdir(parents=True)
        legit = self.config_root / "patched-portal-backup" / "backup.env.bak-preconfig"
        legit.write_text("legit\n")
        self._chmod_octal(legit, 0o600)

        _, data = self._run()
        self.assertEqual(data["stray_config_backups"], [])

    def test_portal_backup_directory_still_not_scanned_after_broadening(self):
        (self.config_root / "patched-portal-backup").mkdir(parents=True)
        for name in ("backup.env.bak-preconfig", "backup.env.old", "bak-anything"):
            (self.config_root / "patched-portal-backup" / name).write_text("legit\n")

        _, data = self._run()
        self.assertEqual(data["stray_config_backups"], [])

    def test_no_strays_is_empty_list_and_valid_json(self):
        (self.config_root / "patched-dashboard").mkdir(parents=True)
        (self.config_root / "patched-dashboard" / "config.yaml").write_text("fine\n")

        _, data = self._run()
        self.assertEqual(data["stray_config_backups"], [])
        for key in (
            "generated_at", "hostname", "pending_updates", "security_updates",
            "esm_updates", "pro_attached", "reboot_required", "running_kernel",
            "newest_kernel", "automatic_reboot_configured", "third_party_pending",
            "timers", "prometheus_rules_live_sha256", "prometheus_rules_sidecar_sha256",
            "prometheus_rules_status", "stray_config_backups",
        ):
            self.assertIn(key, data)

    def test_missing_config_dirs_are_silently_skipped(self):
        self.config_root.mkdir()
        _, data = self._run()
        self.assertEqual(data["stray_config_backups"], [])

    # ── broadened naming styles ──────────────────────────────────────────

    def test_broadened_naming_styles_are_now_caught(self):
        (self.config_root / "patched-dashboard").mkdir(parents=True)
        for filename in (
            "bak-pat687",              # bare, no dot
            "dashboard.env-backup",    # dash, not dot
            "dashboard.env.old",
            "dashboard.env.orig",
            "dashboard.env.save",
            "dashboard.env.20260819",  # separator + timestamp suffix
            "dashboard.env20260819",   # PAT-1433: truly bare (glued, no
                                        # separator) timestamp suffix
        ):
            f = self.config_root / "patched-dashboard" / filename
            f.write_text("SECRET\n")
            self._chmod_octal(f, 0o600)

        _, data = self._run()
        paths = {e["path"] for e in data["stray_config_backups"]}
        for filename in (
            "bak-pat687", "dashboard.env-backup", "dashboard.env.old",
            "dashboard.env.orig", "dashboard.env.save", "dashboard.env.20260819",
            "dashboard.env20260819",
        ):
            f = self.config_root / "patched-dashboard" / filename
            self.assertIn(
                str(f), paths,
                f"{filename!r} was not detected -- the broadened stray-name "
                f"match regressed. Full result: {data['stray_config_backups']}",
            )

    # ── PAT-1433: /etc/patched-* glob replaces the hardcoded directory list ──

    def test_glob_picks_up_new_patched_dir_automatically(self):
        """CONFIG_BACKUP_DIRS used to be a hardcoded three-entry array -- a
        future /etc/patched-<newservice> would silently go unscanned. It is
        now a glob over /etc/patched-*, so a directory not on the old list
        must be picked up with zero code change."""
        (self.config_root / "patched-newservice").mkdir(parents=True)
        f = self.config_root / "patched-newservice" / "newservice.env.bak-pat1433"
        f.write_text("SECRET\n")
        self._chmod_octal(f, 0o640)

        _, data = self._run()
        paths = [e["path"] for e in data["stray_config_backups"]]
        self.assertIn(
            str(f), paths,
            f"a stray in a /etc/patched-* directory not on the old "
            f"hardcoded list was not detected -- the glob regressed. Full "
            f"result: {data['stray_config_backups']}",
        )

    def test_backup_suffixed_dirs_always_excluded(self):
        """The glob's one deliberate exclusion -- any /etc/patched-*-backup
        directory -- must hold generically, not just for the one real-world
        example (patched-portal-backup) that motivated it."""
        for dirname in ("patched-portal-backup", "patched-api-backup", "patched-dashboard-backup"):
            with self.subTest(dirname=dirname):
                self.config_root = self.root / f"etcroot-{dirname}"
                (self.config_root / dirname).mkdir(parents=True)
                f = self.config_root / dirname / "config.env.bak-preconfig"
                f.write_text("legit\n")
                self._chmod_octal(f, 0o600)

                _, data = self._run()
                self.assertEqual(
                    data["stray_config_backups"], [],
                    f"{dirname!r} should be excluded by its -backup suffix "
                    f"but was scanned: {data['stray_config_backups']}",
                )

    def test_pre_plus_digit_live_basename_would_be_flagged_deliberately(self):
        """Documents a conscious trade-off in _stray_name_matches
        (PAT-1433): `pre`/`bak` immediately followed by a digit is
        deliberately in scope (to catch a human gluing `pre`/`bak` straight
        onto a ticket number), and that same rule would also flag a
        hypothetical live file named `pre1.env`. No such file exists in
        KNOWN_LIVE_CONFIG_BASENAMES today; if one is ever added, extend that
        allowlist rather than narrowing this regex."""
        (self.config_root / "patched-dashboard").mkdir(parents=True)
        f = self.config_root / "patched-dashboard" / "pre1.env"
        f.write_text("not actually live in this test\n")
        self._chmod_octal(f, 0o600)

        _, data = self._run()
        paths = [e["path"] for e in data["stray_config_backups"]]
        self.assertIn(str(f), paths)

    # ── live-config exclusion ────────────────────────────────────────────

    def test_live_config_filenames_are_never_flagged(self):
        """The broadened matching above must not start flagging the actual
        live config files it exists to protect -- backup.env genuinely
        exists in /etc/patched-api on this box, so flagging it would leave
        this field permanently degraded."""
        cases = [
            ("patched-dashboard", "dashboard.env"),
            ("patched-api", "env"),
            ("patched-api", "api.env"),
            ("patched-portal", "portal.env"),
            ("patched-api", "backup.env"),
            ("patched-dashboard", "config.env"),
        ]
        for dirname, filename in cases:
            (self.config_root / dirname).mkdir(parents=True, exist_ok=True)
            f = self.config_root / dirname / filename
            f.write_text("SECRET=live\n")
            self._chmod_octal(f, 0o640)  # even group-readable -- must still not flag

        _, data = self._run()
        self.assertEqual(
            data["stray_config_backups"], [],
            f"a live config file was incorrectly flagged as a stray: "
            f"{data['stray_config_backups']}",
        )

    # ── mode-parse failure fails closed ──────────────────────────────────

    def test_unparseable_mode_is_reported_unknown_not_defaulted_safe(self):
        """Before this fix, an unparseable `stat -c '%a'` result would
        silently become mode3="000" -- group_readable=false,
        world_readable=false -- which reads exactly like a confirmed-safe
        0600 root:root file. Permissions we failed to read must escalate,
        not be assumed safe."""
        for broken_mode in ("", "64", "899"):
            with self.subTest(broken_mode=broken_mode):
                self.config_root = self.root / f"etcroot-{broken_mode or 'empty'}"
                (self.config_root / "patched-dashboard").mkdir(parents=True)
                f = self.config_root / "patched-dashboard" / "dashboard.env.bak-pat687"
                f.write_text("SECRET\n")
                self._chmod_octal(f, 0o600)  # real mode irrelevant -- stat is shimmed broken

                _, data = self._run(broken_stat_basename=f.name, broken_stat_mode=broken_mode)
                self.assertEqual(len(data["stray_config_backups"]), 1)
                entry = data["stray_config_backups"][0]
                self.assertTrue(entry["mode_unknown"])
                self.assertEqual(entry["mode"], "unknown")
                # PAT-1433: JSON null, not a "000"-derived false -- a
                # consumer reading only these two booleans must not be able
                # to conclude "not readable" for a mode we never determined.
                self.assertIsNone(entry["group_readable"])
                self.assertIsNone(entry["world_readable"])

    def test_normal_mode_is_not_flagged_unknown(self):
        """Positive control: a file `stat` CAN read must report
        mode_unknown=false, so a script that always set mode_unknown=true
        would not pass the test above for the right reason."""
        (self.config_root / "patched-dashboard").mkdir(parents=True)
        f = self.config_root / "patched-dashboard" / "dashboard.env.bak-pat687"
        f.write_text("SECRET\n")
        self._chmod_octal(f, 0o600)

        _, data = self._run()
        self.assertEqual(len(data["stray_config_backups"]), 1)
        self.assertFalse(data["stray_config_backups"][0]["mode_unknown"])
        self.assertEqual(data["stray_config_backups"][0]["mode"], "0600")


if __name__ == "__main__":
    unittest.main()
