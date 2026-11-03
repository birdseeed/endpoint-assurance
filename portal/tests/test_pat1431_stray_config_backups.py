"""PAT-1431: deploy/patched-maintenance-facts.sh's stray_config_backups
reporting.

Ported identically from dashboard/deploy/patched-maintenance-facts.sh's
PAT-1408 addition (dashboard/tests/test_pat1408_stray_config_backups.py is
the model this file mirrors) -- same field set, same broadened naming-match
rules, same fail-closed-on-unparseable-mode semantics. Before this ticket,
portal-01's row read "stray config backups: not reported by this emitter"
even though /etc/patched-portal is exactly where PAT-1361 originally found a
stray credential copy group-readable by the `portal` service account.
patched.im/api-vps-artefacts/patched-maintenance-facts.sh (PAT-1431, sibling
repo) closes the equivalent gap for api-01.

Driven the same way dashboard's test drives its script from Python via
subprocess: the real script, PATH-shimmed, run against a temp directory tree
(CONFIG_BACKUP_ROOT, an env override added by this ticket for exactly this
purpose). This script's preflight root check and OUT_FILE path were also
made overridable/shimmable by this ticket (see the script's own comments at
the top of the file) -- previously it read `$EUID` directly (unshimmable
from a test harness) and always wrote to /var/lib/patched with no override,
which is why no test for this script existed before now.

  `id` -> shimmed to satisfy the script's `id -u` root preflight check (this
      runs as an ordinary user in CI and locally).
  `stat` -> a GNU `stat -c` shim (this Mac's BSD stat has no -c), used by the
      stray_config_backups section to read each match's mode/owner/group.
      Honours FAKE_STAT_BROKEN_BASENAME / FAKE_STAT_BROKEN_MODE the same way
      dashboard's test does, to simulate `stat -c '%a'` returning something
      unparseable for one specific file (the mode-parse-failure-must-fail-
      closed case).

apt-check/pro/kernel/apt-config/systemctl all fail gracefully under the
script's own `|| true`/`2>/dev/null` guards on this non-Linux/non-apt dev
machine -- nothing else needs shimming.

Run with: pytest tests/test_pat1431_stray_config_backups.py -v
"""

import json
import os
import stat as stat_module
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"


def _fake_bin(tmp_path) -> Path:
    bindir = tmp_path / "fakebin"
    bindir.mkdir()

    (bindir / "id").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
        'exec /usr/bin/id "$@"\n'
    )
    (bindir / "stat").write_text(
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

    for f in bindir.iterdir():
        f.chmod(f.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)
    return bindir


def _run_script(tmp_path, config_root: Path, broken_stat_basename=None, broken_stat_mode=None):
    bindir = _fake_bin(tmp_path)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["OUT_FILE"] = str(tmp_path / "maintenance.json")
    env["CONFIG_BACKUP_ROOT"] = str(config_root)
    if broken_stat_basename is not None:
        env["FAKE_STAT_BROKEN_BASENAME"] = broken_stat_basename
        env["FAKE_STAT_BROKEN_MODE"] = broken_stat_mode or ""

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env=env, cwd=str(REPO),
        capture_output=True, text=True, timeout=15,
    )
    return result, tmp_path / "maintenance.json"


def _chmod_octal(path: Path, mode: int):
    path.chmod(mode)


class TestEmitterScript:
    def test_finds_group_readable_and_root_only_strays_across_dirs(self, tmp_path):
        root = tmp_path / "etcroot"
        (root / "patched-dashboard").mkdir(parents=True)
        (root / "patched-api").mkdir(parents=True)
        # portal-01 itself doesn't have a /etc/patched-dashboard directory in
        # real life -- must be silently skipped, not an error.

        readable = root / "patched-dashboard" / "dashboard.env.bak-pat687"
        readable.write_text("SECRET=1\n")
        _chmod_octal(readable, 0o640)  # group-readable

        root_only = root / "patched-api" / "api.env.pre-pat909-config"
        root_only.write_text("SECRET=2\n")
        _chmod_octal(root_only, 0o600)  # root-only

        (root / "patched-dashboard" / "notes.txt").write_text("irrelevant\n")

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr
        assert out_file.exists()

        data = json.loads(out_file.read_text())
        strays = {e["path"]: e for e in data["stray_config_backups"]}
        assert str(readable) in strays
        assert str(root_only) in strays
        assert len(strays) == 2

        r = strays[str(readable)]
        assert r["mode"] == "0640"
        assert r["group_readable"] is True
        assert r["world_readable"] is False
        assert r["mode_unknown"] is False

        ro = strays[str(root_only)]
        assert ro["mode"] == "0600"
        assert ro["group_readable"] is False
        assert ro["world_readable"] is False

    def test_world_readable_stray_is_flagged(self, tmp_path):
        root = tmp_path / "etcroot"
        (root / "patched-portal").mkdir(parents=True)
        f = root / "patched-portal" / "portal.env.bak-<timestamp>pat936"
        f.write_text("SECRET=3\n")
        _chmod_octal(f, 0o644)  # world-readable

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert len(data["stray_config_backups"]) == 1
        entry = data["stray_config_backups"][0]
        assert entry["world_readable"] is True

    def test_does_not_scan_the_backup_job_directory(self, tmp_path):
        """patched-portal-backup is the backup job's own config directory,
        not a service config directory -- its *.bak* contents (the real
        backup.env.bak-preconfig on this box) are legitimate and must never
        be flagged."""
        root = tmp_path / "etcroot"
        (root / "patched-portal-backup").mkdir(parents=True)
        legit = root / "patched-portal-backup" / "backup.env.bak-preconfig"
        legit.write_text("legit\n")
        _chmod_octal(legit, 0o600)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == []

    def test_portal_backup_directory_still_not_scanned_after_broadening(self, tmp_path):
        root = tmp_path / "etcroot"
        (root / "patched-portal-backup").mkdir(parents=True)
        for name in ("backup.env.bak-preconfig", "backup.env.old", "bak-anything"):
            (root / "patched-portal-backup" / name).write_text("legit\n")

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == []

    # ── PAT-1433: /etc/patched-* glob replaces the hardcoded directory list ──

    def test_glob_picks_up_new_patched_dir_automatically(self, tmp_path):
        """CONFIG_BACKUP_DIRS used to be a hardcoded three-entry array -- a
        future /etc/patched-<newservice> would silently go unscanned. It is
        now a glob over /etc/patched-*, so a directory not on the old list
        must be picked up with zero code change."""
        root = tmp_path / "etcroot"
        (root / "patched-newservice").mkdir(parents=True)
        f = root / "patched-newservice" / "newservice.env.bak-pat1433"
        f.write_text("SECRET\n")
        _chmod_octal(f, 0o640)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        paths = [e["path"] for e in data["stray_config_backups"]]
        assert str(f) in paths, (
            "a stray in a /etc/patched-* directory not on the old hardcoded "
            f"list was not detected -- the glob regressed. Full result: "
            f"{data['stray_config_backups']}"
        )

    @pytest.mark.parametrize(
        "dirname",
        ["patched-portal-backup", "patched-api-backup", "patched-dashboard-backup"],
    )
    def test_backup_suffixed_dirs_always_excluded(self, tmp_path, dirname):
        """The glob's one deliberate exclusion -- any /etc/patched-*-backup
        directory -- must hold generically, not just for the one real-world
        example (patched-portal-backup) that motivated it."""
        root = tmp_path / "etcroot"
        (root / dirname).mkdir(parents=True)
        f = root / dirname / "config.env.bak-preconfig"
        f.write_text("legit\n")
        _chmod_octal(f, 0o600)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == [], (
            f"{dirname!r} should be excluded by its -backup suffix but was "
            f"scanned: {data['stray_config_backups']}"
        )

    def test_pre_plus_digit_live_basename_would_be_flagged_deliberately(self, tmp_path):
        """Documents a conscious trade-off in _stray_name_matches
        (PAT-1433): `pre`/`bak` immediately followed by a digit is
        deliberately in scope (to catch a human gluing `pre`/`bak` straight
        onto a ticket number), and that same rule would also flag a
        hypothetical live file named `pre1.env`. No such file exists in
        KNOWN_LIVE_CONFIG_BASENAMES today; if one is ever added, extend that
        allowlist rather than narrowing this regex."""
        root = tmp_path / "etcroot"
        (root / "patched-dashboard").mkdir(parents=True)
        f = root / "patched-dashboard" / "pre1.env"
        f.write_text("not actually live in this test\n")
        _chmod_octal(f, 0o600)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        paths = [e["path"] for e in data["stray_config_backups"]]
        assert str(f) in paths

    def test_no_strays_is_empty_list_and_valid_json(self, tmp_path):
        root = tmp_path / "etcroot"
        (root / "patched-portal").mkdir(parents=True)
        (root / "patched-portal" / "config.yaml").write_text("fine\n")

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == []
        for key in (
            "generated_at", "hostname", "pending_updates", "security_updates",
            "esm_updates", "pro_attached", "reboot_required", "running_kernel",
            "newest_kernel", "automatic_reboot_configured", "third_party_pending",
            "timers", "stray_config_backups",
        ):
            assert key in data

    def test_missing_config_dirs_are_silently_skipped(self, tmp_path):
        root = tmp_path / "etcroot"
        root.mkdir()

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == []

    @pytest.mark.parametrize(
        "filename",
        [
            "bak-pat687",              # bare, no dot
            "portal.env-backup",       # dash, not dot
            "portal.env.old",
            "portal.env.orig",
            "portal.env.save",
            "portal.env.20260819",     # separator + timestamp suffix
            "portal.env20260819",      # PAT-1433: truly bare (glued, no
                                        # separator) timestamp suffix -- the
                                        # ticket's own example of a spelling
                                        # the old regex silently missed.
        ],
    )
    def test_broadened_naming_styles_are_now_caught(self, tmp_path, filename):
        root = tmp_path / "etcroot"
        (root / "patched-portal").mkdir(parents=True)
        f = root / "patched-portal" / filename
        f.write_text("SECRET\n")
        _chmod_octal(f, 0o600)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        paths = [e["path"] for e in data["stray_config_backups"]]
        assert str(f) in paths, (
            f"{filename!r} was not detected -- the broadened stray-name "
            f"match regressed. Full result: {data['stray_config_backups']}"
        )

    @pytest.mark.parametrize(
        "dirname,filename",
        [
            ("patched-dashboard", "dashboard.env"),
            ("patched-api", "env"),
            ("patched-api", "api.env"),
            ("patched-portal", "portal.env"),
            ("patched-api", "backup.env"),
            ("patched-dashboard", "config.env"),
        ],
    )
    def test_live_config_filenames_are_never_flagged(self, tmp_path, dirname, filename):
        """The broadened matching above must not start flagging the actual
        live config file it exists to protect -- backup.env genuinely exists
        in /etc/patched-api, so flagging it would leave this field
        permanently degraded and get it ignored."""
        root = tmp_path / "etcroot"
        (root / dirname).mkdir(parents=True)
        f = root / dirname / filename
        f.write_text("SECRET=live\n")
        _chmod_octal(f, 0o640)  # even group-readable -- must still not flag

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == [], (
            f"live config file {filename!r} was incorrectly flagged as a "
            f"stray: {data['stray_config_backups']}"
        )

    @pytest.mark.parametrize(
        "broken_mode",
        ["", "64", "899"],
        ids=["empty_stat_output", "truncated_2char_mode", "invalid_octal_digits"],
    )
    def test_unparseable_mode_is_reported_unknown_not_defaulted_safe(self, tmp_path, broken_mode):
        """Before this fix, an unparseable `stat -c '%a'` result silently
        became mode3="000" -- group_readable=false, world_readable=false --
        which reads exactly like a confirmed-safe 0600 root:root file.
        Permissions we failed to read must escalate, not be assumed safe."""
        root = tmp_path / "etcroot"
        (root / "patched-portal").mkdir(parents=True)
        f = root / "patched-portal" / "portal.env.bak-pat687"
        f.write_text("SECRET\n")
        _chmod_octal(f, 0o600)  # real mode is irrelevant -- stat is shimmed broken

        result, out_file = _run_script(
            tmp_path, root,
            broken_stat_basename=f.name, broken_stat_mode=broken_mode,
        )
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert len(data["stray_config_backups"]) == 1
        entry = data["stray_config_backups"][0]
        assert entry["mode_unknown"] is True
        assert entry["mode"] == "unknown"
        # PAT-1433: JSON null, not a "000"-derived false -- a consumer
        # reading only these two booleans must not conclude "not readable"
        # for a mode we never determined.
        assert entry["group_readable"] is None
        assert entry["world_readable"] is None

    def test_normal_mode_is_not_flagged_unknown(self, tmp_path):
        """Positive control for the two tests above: a file `stat` CAN read
        must report mode_unknown=false, so a script that always set
        mode_unknown=true would not pass these tests for the wrong reason."""
        root = tmp_path / "etcroot"
        (root / "patched-portal").mkdir(parents=True)
        f = root / "patched-portal" / "portal.env.bak-pat687"
        f.write_text("SECRET\n")
        _chmod_octal(f, 0o600)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert len(data["stray_config_backups"]) == 1
        assert data["stray_config_backups"][0]["mode_unknown"] is False
        assert data["stray_config_backups"][0]["mode"] == "0600"

    # ── a stray's own filename must not be able to corrupt the record ────
    # This script's tab-delimited env-var-to-Python serialization is
    # portal's own house style (dashboard/api-01 assemble via jq and have
    # no analogous risk). The field being serialized here is a filesystem
    # path taken from a directory this section scans *because* a human once
    # typed an ad-hoc filename by hand -- so unlike the package-name/
    # timer-unit lines elsewhere in this script, the delimiter character
    # itself is data an attacker-or-just-a-weird-filename could embed. A
    # tab embedded in a stray's basename used to split the record into more
    # than 7 fields, which the Python parser silently `continue`d past --
    # the stray vanished from stray_config_backups entirely, no entry, no
    # error. That is indistinguishable from no stray existing, which is
    # exactly the failure mode this whole guard exists to close
    # (PAT-912/837/960; PAT-1408's three-state design). The fix moved the
    # field separator to \x1f (a byte a path cannot realistically contain),
    # so a tab in the filename is now just an ordinary character inside the
    # `path` field rather than a delimiter collision.

    def test_tab_in_stray_filename_does_not_vanish_from_output(self, tmp_path):
        root = tmp_path / "etcroot"
        (root / "patched-portal").mkdir(parents=True)
        # A literal tab byte is a legal filename character on both macOS
        # and Linux filesystems.
        f = root / "patched-portal" / "dashboard.env.bak-pat687\tEXTRA"
        f.write_text("SECRET\n")
        _chmod_octal(f, 0o640)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        strays = data["stray_config_backups"]
        assert len(strays) == 1, (
            "a stray whose filename contains a tab vanished from the "
            f"output instead of being reported: {strays}"
        )
        entry = strays[0]
        assert entry["path"] == str(f)
        assert entry["mode"] == "0640"
        assert entry["group_readable"] is True
        assert entry["mode_unknown"] is False

    def test_record_that_still_fails_to_split_surfaces_as_unparseable(self, tmp_path, monkeypatch):
        """Belt-and-braces for the parser itself, independent of the \\x1f
        delimiter change above: if a record ever fails to split into
        exactly 7 fields for any reason, it must surface as an explicit
        unparseable/unknown entry rather than being silently dropped.
        Exercised directly against the Python assembly step (bypassing the
        bash scan) since a filename containing the new delimiter byte
        itself is not something `find`/a real filesystem scan can be
        coaxed into producing in a portable test."""
        import importlib.util
        import re

        script_text = SCRIPT.read_text()
        match = re.search(r"python3 - <<'PYEOF'\n(.*)\nPYEOF", script_text, re.DOTALL)
        assert match, "could not locate the embedded python3 heredoc in the script"
        py_source = match.group(1)

        out_file = tmp_path / "maintenance.json"
        env = {
            "FACTS_HOSTNAME": "test-host",
            "FACTS_OUT_FILE": str(out_file),
            # One well-formed record, one record with a stray \x1f dropped
            # in the middle -- 8 fields instead of 7, simulating "the
            # split still went wrong somehow".
            "FACTS_STRAY_CONFIG_BACKUPS": (
                "/etc/patched-portal/portal.env.bak-pat1\x1f0600\x1froot\x1froot\x1ffalse\x1ffalse\x1ffalse\n"
                "/etc/patched-portal/portal.env.bak-pat2\x1f0600\x1froot\x1froot\x1ffalse\x1ffalse\x1ffalse\x1fEXTRA\n"
            ),
        }
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        spec = importlib.util.spec_from_loader("pat1431_embedded_assembly", loader=None)
        module = importlib.util.module_from_spec(spec)
        exec(compile(py_source, str(SCRIPT), "exec"), module.__dict__)  # noqa: S102

        data = json.loads(out_file.read_text())
        strays = data["stray_config_backups"]
        assert len(strays) == 2

        good = next(e for e in strays if "pat1" in e["path"])
        assert good["mode"] == "0600"
        assert good["mode_unknown"] is False

        bad = next(e for e in strays if e is not good)
        assert bad["mode_unknown"] is True
        assert bad["mode"] == "unknown"
        # PAT-1433: a record the parser itself couldn't split is exactly as
        # unknown as an unparseable stat mode -- null, not a confirmed-false
        # reading, for the same reason.
        assert bad["group_readable"] is None
        assert bad["world_readable"] is None
        # The raw record is preserved rather than dropped -- a human can
        # still see something happened and investigate.
        assert "pat2" in bad["path"]
