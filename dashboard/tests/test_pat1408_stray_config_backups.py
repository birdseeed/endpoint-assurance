"""
PAT-1408: detect stray config-backup copies (`*.bak*`/`*.pre-*`) left behind
in /etc/patched-{dashboard,api,portal} by ad-hoc per-ticket commands.

The ticket's stated premise ("a deploy/config-edit script writes a
timestamped copy into the live directory") is wrong -- grepping this repo's
and the sibling repos' deploy/scripts trees for anything writing into
/etc/patched-* returns nothing, and the historical filenames on-box
(bak-pat687, pre-pat909-..., bak-20260723-pat936) encode ticket ids, meaning
a human/session typed them by hand, documented after the fact in runbooks.
There is no writer to fix. This is a detective guard: deploy/patched-
maintenance-facts.sh now scans for stray copies and reports each one's
readability; the dashboard-side checker (_stray_config_backup_findings in
main.py, wired into _run_maintenance_drift_check_tick's existing
maintenance_prod01/api01/portal01 rows) surfaces them.

Two halves, mirroring tests/test_pat1426_truth_report_loadstate.py's model
for driving a real bash script from Python via subprocess:

  * TestEmitterScript -- drives the real deploy/patched-maintenance-facts.sh
    end-to-end against a temp directory tree (CONFIG_BACKUP_ROOT, an env
    override added by this ticket for exactly this purpose) and asserts the
    JSON it writes. `id`/`apt-cache`/`systemctl`/`stat` are shimmed on PATH:
    the script requires root (checks `id -u`) and `apt-cache` at preflight,
    and calls GNU `stat -c` (this dev machine's BSD `stat` has no -c) to read
    each stray's mode/owner/group. `systemctl` is shimmed to simply fail
    every call, which drives the script down its already-guarded "no timers
    found" path (list-unit-files returns nothing -> timers stays [] -- see
    the script's own `|| true` guards), keeping this test focused on the
    stray_config_backups addition rather than re-deriving the full timers
    shim tests/test_pat1426 already exists for a different script.

  * TestConsumer -- exercises _stray_config_backup_findings() and
    _run_maintenance_drift_check_tick()'s handling of the field directly,
    the same way tests/test_pat989_maintenance_drift_check.py exercises the
    rest of that tick. The single most important case here is field-absent:
    a missing `stray_config_backups` key must read as "not reported", NEVER
    as "zero found" -- the exact absence-reads-as-clean shape PAT-912/837/
    960 already caught this estate doing elsewhere (root AGENTS.md). Every
    existing maintenance-drift fixture in test_pat989 already omits this
    field (it predates PAT-1408), so those existing tests are themselves a
    live regression check that absence isn't misread -- this file adds the
    explicit, named assertion for it.

Run with: pytest tests/test_pat1408_stray_config_backups.py -v
"""

import json
import os
import stat as stat_module
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"


# ═════════════════════════════════════════════════════════════════════════
# Part 1: the emitter script itself
# ═════════════════════════════════════════════════════════════════════════


def _fake_bin(tmp_path) -> Path:
    """Shim directory for running deploy/patched-maintenance-facts.sh on a
    macOS dev box against a temp directory tree instead of the real /etc
    and real systemd. Prepend this to PATH.

    `id -u` -> 0: the script's root preflight check.
    `apt-cache` -> success no-op: only needs to exist for the preflight
        `command -v` check and for `apt-cache policy` inside the third-party-
        package loop, which is never reached here because `apt list
        --upgradable` (real `apt`, absent on macOS) fails silently under the
        script's own `2>/dev/null || true` guard and leaves upgradable_list
        empty -- every package in THIRD_PARTY_PACKAGES is skipped before
        apt-cache would ever be invoked.
    `systemctl` -> always fails: drives the script's pre-existing
        `list-unit-files ... 2>/dev/null | awk ... || true` guard to an
        empty timer_units, so timers stays `[]`. Out of scope for this
        ticket -- deploy/truth-report.sh and this repo's other tests already
        cover timer/systemd behaviour elsewhere.
    `stat` -> a GNU `stat -c` shim (this Mac's BSD stat has no -c), used by
        the new stray_config_backups section to read each match's
        mode/owner/group. Honours two env vars, FAKE_STAT_BROKEN_BASENAME
        and FAKE_STAT_BROKEN_MODE (defaulting to unset/empty): when the `-c
        %a` query's target file's basename matches the former, the shim
        prints FAKE_STAT_BROKEN_MODE (e.g. "" or a truncated "64") instead
        of the real mode, simulating the emitter's `stat -c '%a'` call
        returning something unparseable (PAT-1408 non-author review round
        3 -- the mode-parse-failure-must-fail-closed case). %U/%G queries
        for that same file are untouched, matching a real `stat` where a
        malformed `%a` value doesn't imply owner/group also failed.
    """
    bindir = tmp_path / "fakebin"
    bindir.mkdir()

    (bindir / "id").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
        'exec /usr/bin/id "$@"\n'
    )
    (bindir / "apt-cache").write_text("#!/bin/bash\nexit 0\n")
    (bindir / "systemctl").write_text("#!/bin/bash\nexit 1\n")
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
        # portal-01's directory doesn't exist on this box -- must be
        # silently skipped, not an error.

        readable = root / "patched-dashboard" / "dashboard.env.bak-pat687"
        readable.write_text("SECRET=1\n")
        _chmod_octal(readable, 0o640)  # group-readable

        root_only = root / "patched-api" / "api.env.pre-pat909-config"
        root_only.write_text("SECRET=2\n")
        _chmod_octal(root_only, 0o600)  # root-only

        # Must NOT be picked up: no bak/pre/old/orig/save/backup/copy/
        # timestamp token anywhere in the name.
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
        not a service config directory -- its *.bak* contents (e.g. the real
        backup.env.bak-preconfig on portal-01) are legitimate and must never
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

    def test_no_strays_is_empty_list_and_valid_json(self, tmp_path):
        root = tmp_path / "etcroot"
        (root / "patched-dashboard").mkdir(parents=True)
        (root / "patched-dashboard" / "config.yaml").write_text("fine\n")

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == []
        # Whole document must still be well-formed JSON with the rest of the
        # existing schema intact.
        for key in (
            "generated_at", "hostname", "pending_updates", "security_updates",
            "esm_updates", "pro_attached", "reboot_required", "running_kernel",
            "newest_kernel", "automatic_reboot_configured", "third_party_pending",
            "timers", "stray_config_backups",
        ):
            assert key in data

    def test_missing_config_dirs_are_silently_skipped(self, tmp_path):
        # CONFIG_BACKUP_ROOT points at an empty directory -- none of
        # patched-{dashboard,api,portal} exist under it at all.
        root = tmp_path / "etcroot"
        root.mkdir()

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        assert data["stray_config_backups"] == []

    # ── PAT-1408 non-author review: the original `*.bak*`/`*.pre-*` glob
    # only caught the exact spelling seen in the historical incidents. A
    # human inventing a filename ad hoc under time pressure is just as
    # likely to reach for any of these styles instead -- a guard that only
    # catches the one style already observed reports clean on the next,
    # differently-spelled incident. Every case the reviewer's empirical
    # probe listed as a MISS against the old pattern is covered here.
    @pytest.mark.parametrize(
        "filename",
        [
            "bak-pat687",              # bare, no dot
            "dashboard.env-backup",    # dash, not dot
            "dashboard.env.old",
            "dashboard.env.orig",
            "dashboard.env.save",
            "dashboard.env.20260819",  # separator + timestamp suffix
            "dashboard.env20260819",   # PAT-1433: truly bare (glued, no
                                        # separator at all) timestamp suffix
                                        # -- the comment above
                                        # _stray_name_matches always claimed
                                        # to catch this, but the regex
                                        # required a preceding [.-] and
                                        # silently missed it until PAT-1433.
        ],
    )
    def test_broadened_naming_styles_are_now_caught(self, tmp_path, filename):
        root = tmp_path / "etcroot"
        (root / "patched-dashboard").mkdir(parents=True)
        f = root / "patched-dashboard" / filename
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
            ("patched-dashboard", "backup.env"),
            ("patched-dashboard", "config.env"),
        ],
    )
    def test_live_config_filenames_are_never_flagged(self, tmp_path, dirname, filename):
        """The broadened matching in test_broadened_naming_styles_are_now_
        caught above must not start flagging the actual live config file it
        exists to protect -- that would make the check permanently degraded
        and get it ignored, the opposite of the point of a detective guard."""
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

    def test_portal_backup_directory_still_not_scanned_after_broadening(self, tmp_path):
        """Re-confirms the existing test_does_not_scan_the_backup_job_
        directory guarantee still holds now that matching is broader -- the
        directory-scope exclusion (any /etc/patched-*-backup directory is
        skipped by the glob, PAT-1433) is independent of the filename
        pattern, but broadening the pattern is exactly the kind of change
        that could have papered over a scope regression, so it's worth a
        named, post-broadening assertion rather than relying on the older
        test."""
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
        future /etc/patched-<newservice> would silently go unscanned until
        someone remembered to add a fourth line to all three emitters. It is
        now a glob over /etc/patched-*, so a directory this test invents on
        the spot (not dashboard/api/portal) must be picked up with zero code
        change."""
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
        directory -- has to hold for more than just the one real-world
        example (patched-portal-backup) that motivated it, since the glob
        itself is generic. A regression that only special-cased the literal
        string "patched-portal-backup" would pass the older, portal-specific
        test but still degrade this row permanently for any other backup-job
        directory using the same naming convention."""
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
        """Documents a conscious, not accidental, trade-off in
        _stray_name_matches (PAT-1433): `pre`/`bak` immediately followed by
        a digit (no separator) is deliberately in scope, to catch a human
        gluing `pre`/`bak` straight onto a ticket number. That same rule
        would also flag a hypothetical live config file literally named
        `pre1.env` -- no such file exists in KNOWN_LIVE_CONFIG_BASENAMES
        today, and this test is the named decision record: if `pre1.env`
        (or similar) ever becomes a real live basename, add it to that
        allowlist rather than narrowing this regex, which exists precisely
        to catch glued-digit spellings of a real incident."""
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

    # ── PAT-1408 non-author review round 3: unparseable stat -> fail closed ──

    @pytest.mark.parametrize(
        "broken_mode",
        ["", "64"],
        ids=["empty_stat_output", "truncated_2char_mode"],
    )
    def test_unparseable_mode_is_reported_unknown_not_defaulted_safe(self, tmp_path, broken_mode):
        """Before this fix, an unparseable `stat -c '%a'` result silently
        became mode3="000" -- group_readable=false, world_readable=false --
        which reads exactly like a confirmed-safe 0600 root:root file. That
        is backwards: permissions we failed to read must escalate, not be
        assumed safe. The emitter must instead set mode_unknown=true and
        mode="unknown" so the dashboard-side consumer can fail closed."""
        root = tmp_path / "etcroot"
        (root / "patched-dashboard").mkdir(parents=True)
        f = root / "patched-dashboard" / "dashboard.env.bak-pat687"
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
        # PAT-1433: the fallback internal mode3="000" must not leak out as a
        # confirmed-*false* reading in either boolean either -- False would
        # let a consumer that only checks these two fields (never looking at
        # mode_unknown) conclude "not readable" for a file whose permissions
        # were never actually read. Both must be JSON null.
        assert entry["group_readable"] is None
        assert entry["world_readable"] is None

    def test_normal_mode_is_not_flagged_unknown(self, tmp_path):
        """Positive control for the two tests above: a file `stat` CAN read
        must report mode_unknown=false, so a script that always set
        mode_unknown=true would not pass these tests for the wrong reason."""
        root = tmp_path / "etcroot"
        (root / "patched-dashboard").mkdir(parents=True)
        f = root / "patched-dashboard" / "dashboard.env.bak-pat687"
        f.write_text("SECRET\n")
        _chmod_octal(f, 0o600)

        result, out_file = _run_script(tmp_path, root)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert len(data["stray_config_backups"]) == 1
        assert data["stray_config_backups"][0]["mode_unknown"] is False
        assert data["stray_config_backups"][0]["mode"] == "0600"


# ═════════════════════════════════════════════════════════════════════════
# Part 2: the dashboard-side consumer
# ═════════════════════════════════════════════════════════════════════════


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


class _FakeResp:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        return self._payload


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _healthy_full_facts(generated_at: datetime, stray_config_backups=None) -> dict:
    """prod-01/api-01 shape. `stray_config_backups` is omitted entirely by
    default (the field-absence case), matching every fixture in
    test_pat989_maintenance_drift_check.py -- those tests predate PAT-1408
    and never set it, so they already double as a live "absence must not be
    misread" regression check."""
    facts = {
        "generated_at": _iso(generated_at),
        "hostname": "patched-prod-01",
        "pending_updates": 3,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "reboot_required": False,
        "running_kernel": "6.8.0-124-generic",
        "newest_kernel": "6.8.0-124-generic",
        "automatic_reboot_configured": True,
        "third_party_pending": [],
        "timers": [],
    }
    if stray_config_backups is not None:
        facts["stray_config_backups"] = stray_config_backups
    return facts


def _install_http(monkeypatch, api_facts, portal_body):
    def fake_get(url, timeout=None, verify=None):
        if url == f"{dashboard.PATCHED_API_INTERNAL}/admin/ops/maintenance":
            return _FakeResp(api_facts, status_code=200)
        if url == "https://app.patched.im/healthz":
            return _FakeResp(portal_body, status_code=200)
        raise AssertionError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _run(monkeypatch, now, prod01_path, prod01_facts):
    """Mirrors test_pat989_maintenance_drift_check.py's `_run`: calls the
    tick function directly to capture its return value, then also routes it
    through _run_tick exactly as scheduler_loop registers it, so
    tick_maintenance_drift_check gets recorded too. Both calls are
    idempotent (check_statuses upserts by name)."""
    prod01_path.parent.mkdir(parents=True, exist_ok=True)
    prod01_path.write_text(json.dumps(prod01_facts))
    monkeypatch.setattr(dashboard, "MAINTENANCE_FACTS_FILE", str(prod01_path))
    # api-01/portal-01 don't need to matter for these tests: give them
    # trivially healthy, field-absent facts so only prod-01's state varies.
    other_facts = _healthy_full_facts(now)
    _install_http(
        monkeypatch,
        api_facts=other_facts,
        portal_body={"status": "ok", "maintenance": other_facts},
    )
    reason = dashboard._run_maintenance_drift_check_tick(now)
    dashboard._run_tick(
        "maintenance-drift-check",
        lambda: dashboard._run_maintenance_drift_check_tick(now),
        now,
    )
    return reason


# ── unit tests: _stray_config_backup_findings ───────────────────────────────


def test_findings_field_absent_is_not_reported_not_clean():
    """The single most important case in this ticket: a dict with no
    `stray_config_backups` key at all must read as unknown/not-reported,
    explicitly distinct from an empty list (which reads as clean)."""
    degraded, info = dashboard._stray_config_backup_findings({"generated_at": "x"})
    assert degraded == []
    assert "not reported" in info
    assert "none found" not in info


@pytest.mark.parametrize("bad_facts", [None, [], "not a dict", 42], ids=["none", "list", "str", "int"])
def test_findings_non_dict_facts_reports_not_reported_without_raising(bad_facts):
    """Coordinator review finding: the old guard checked
    `isinstance(facts, dict)` for `raw` but then did an unguarded
    `"stray_config_backups" not in facts`, which raises TypeError for
    facts=None (and is inconsistent -- a caller passing a non-dict should
    get the same graceful "not reported" result as every other
    non-conforming input, not a crash). Not reachable from today's call
    sites (the tick's own facts parsing already guarantees a dict by the
    time this is called), but this function's whole purpose is that
    absence must never read as clean -- a crash is a worse failure than
    that, so the guard must actually hold for any input shape."""
    degraded, info = dashboard._stray_config_backup_findings(bad_facts)
    assert degraded == []
    assert "not reported" in info
    assert "none found" not in info


def test_findings_empty_list_is_clean():
    degraded, info = dashboard._stray_config_backup_findings({"stray_config_backups": []})
    assert degraded == []
    assert "none found" in info
    assert "not reported" not in info


def test_findings_group_readable_stray_is_degraded_and_names_file():
    facts = {
        "stray_config_backups": [
            {"path": "/etc/patched-dashboard/x.env.bak-pat1", "mode": "0640",
             "owner": "root", "group": "www-data",
             "group_readable": True, "world_readable": False},
        ]
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert len(degraded) == 1
    assert "/etc/patched-dashboard/x.env.bak-pat1" in degraded[0]
    assert "readable beyond owner" in degraded[0]


def test_findings_world_readable_stray_is_degraded_and_names_file():
    facts = {
        "stray_config_backups": [
            {"path": "/etc/patched-api/y.env.pre-pat2", "mode": "0644",
             "owner": "root", "group": "root",
             "group_readable": False, "world_readable": True},
        ]
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert len(degraded) == 1
    assert "/etc/patched-api/y.env.pre-pat2" in degraded[0]


def test_findings_root_only_stray_is_reported_but_not_degraded():
    facts = {
        "stray_config_backups": [
            {"path": "/etc/patched-portal/z.env.bak-pat3", "mode": "0600",
             "owner": "root", "group": "root",
             "group_readable": False, "world_readable": False},
        ]
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert degraded == []
    assert "/etc/patched-portal/z.env.bak-pat3" in info
    assert "0600" in info


def test_findings_unknown_mode_stray_escalates_to_degraded_fail_closed():
    """PAT-1408 non-author review round 3: an entry the emitter could not
    determine the mode of (mode_unknown=true, group_readable/world_readable
    JSON null -- PAT-1433 changed these from a "000"-derived false to null,
    see below) must escalate to degraded, NOT be folded into the root-only/
    safe bucket just because both booleans are falsy. Unknown must fail
    closed, matching the missing-field discipline one level up."""
    facts = {
        "stray_config_backups": [
            {"path": "/etc/patched-dashboard/dashboard.env.bak-pat687", "mode": "unknown",
             "owner": "root", "group": "root",
             "group_readable": None, "world_readable": None, "mode_unknown": True},
        ]
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert len(degraded) == 1
    assert "/etc/patched-dashboard/dashboard.env.bak-pat687" in degraded[0]
    assert "could not be determined" in degraded[0]
    # Must NOT be described as a confirmed leak -- it's an unconfirmed one.
    assert "readable beyond owner" not in degraded[0]


def test_findings_null_booleans_escalate_even_without_mode_unknown_flag():
    """PAT-1433: defence in depth, independent of test_findings_
    unknown_mode_stray_escalates_to_degraded_fail_closed above. This
    simulates a malformed/future entry where group_readable/world_readable
    are JSON null but mode_unknown itself is missing or false -- the
    function must still fail closed on the null booleans alone, not rely
    solely on mode_unknown being set correctly. `None or None` is falsy in
    Python, so a naive `entry.get("group_readable") or
    entry.get("world_readable")` check would silently read this as
    "not readable" -- that is precisely the shape this test guards against."""
    facts = {
        "stray_config_backups": [
            {"path": "/etc/patched-api/api.env.bak-pat1", "mode": "0600",
             "owner": "root", "group": "root",
             "group_readable": None, "world_readable": None},
        ]
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert len(degraded) == 1
    assert "/etc/patched-api/api.env.bak-pat1" in degraded[0]
    assert "could not be determined" in degraded[0]


def test_findings_a_consumer_reading_only_the_booleans_cannot_conclude_safe():
    """PAT-1433, the ticket's own framing: prove that a hypothetical
    consumer that reads ONLY group_readable/world_readable -- the exact
    "future view, script, or other box's tooling" the ticket warns about,
    skipping mode_unknown entirely -- cannot walk away with "not a
    permission leak" for an entry whose permissions were never actually
    read. The naive truthy check is deliberately reproduced here (not
    imported from anywhere) to show what it WOULD conclude, then asserted
    against what the real fail-closed emitter data looks like."""
    entry = {
        "path": "/etc/patched-portal/portal.env.bak-pat1", "mode": "unknown",
        "owner": "root", "group": "root",
        "group_readable": None, "world_readable": None, "mode_unknown": True,
    }
    # The naive shape: `entry.get(...) or entry.get(...)` on two Nones is
    # falsy, so a consumer using only this line would (wrongly) conclude
    # "not readable".
    naive_readable_beyond_owner = bool(entry.get("group_readable") or entry.get("world_readable"))
    assert naive_readable_beyond_owner is False, (
        "this assertion documents the trap, not the desired behaviour -- "
        "see the real consumer below"
    )
    # The real consumer must not make that mistake: it escalates to
    # "could not be determined", never asserts "safe".
    degraded, info = dashboard._stray_config_backup_findings({"stray_config_backups": [entry]})
    assert len(degraded) == 1
    assert "could not be determined" in degraded[0]
    assert "not a permission leak" not in degraded[0]
    assert info == ""  # nothing safe to report in the info_note either


def test_findings_unknown_mode_is_distinct_from_confirmed_root_only():
    """Positive control: a genuinely confirmed 0600 root:root entry
    (mode_unknown=false/absent) must still land in the low-severity
    info_note path, not get swept into the new unknown-mode degraded
    bucket -- otherwise every root-only stray would spuriously degrade."""
    facts = {
        "stray_config_backups": [
            {"path": "/etc/patched-api/api.env.pre-pat909-config", "mode": "0600",
             "owner": "root", "group": "root",
             "group_readable": False, "world_readable": False, "mode_unknown": False},
        ]
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert degraded == []
    assert "api.env.pre-pat909-config" in info
    assert "0600" in info


# ── integration: wired into the maintenance_prod01 check_statuses row ──────


def test_prod01_group_readable_stray_is_degraded(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, stray_config_backups=[
        {"path": "/etc/patched-dashboard/dashboard.env.bak-pat687", "mode": "0640",
         "owner": "root", "group": "www-data",
         "group_readable": True, "world_readable": False},
    ])
    prod01_path = tmp_path / "maintenance.json"

    reason = _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert "dashboard.env.bak-pat687" in row["reason"]
    assert reason is not None
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"


def test_prod01_root_only_stray_is_reported_not_degraded(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, stray_config_backups=[
        {"path": "/etc/patched-api/api.env.pre-pat909-config", "mode": "0600",
         "owner": "root", "group": "root",
         "group_readable": False, "world_readable": False},
    ])
    prod01_path = tmp_path / "maintenance.json"

    reason = _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "ok"
    assert "api.env.pre-pat909-config" in row["reason"]
    assert "0600" in row["reason"]
    assert reason is None
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


def test_prod01_unknown_mode_stray_is_degraded_fail_closed(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, stray_config_backups=[
        {"path": "/etc/patched-dashboard/dashboard.env.bak-pat687", "mode": "unknown",
         "owner": "root", "group": "root",
         # PAT-1433: real emitter output is JSON null here, not false.
         "group_readable": None, "world_readable": None, "mode_unknown": True},
    ])
    prod01_path = tmp_path / "maintenance.json"

    reason = _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert "dashboard.env.bak-pat687" in row["reason"]
    assert "could not be determined" in row["reason"]
    assert reason is not None
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"


def test_prod01_no_strays_is_clean(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, stray_config_backups=[])
    prod01_path = tmp_path / "maintenance.json"

    _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "ok"
    assert "none found" in row["reason"]


def test_prod01_field_absent_entirely_is_reported_as_unknown_not_clean(db, tmp_path, monkeypatch):
    """The ticket's core backwards-compatibility requirement: a box whose
    emitter predates this field (or api-01/portal-01, which don't have it
    yet at all) must have that absence show up explicitly in the reason
    string, not be silently indistinguishable from "confirmed clean"."""
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now)  # no stray_config_backups key at all
    assert "stray_config_backups" not in facts
    prod01_path = tmp_path / "maintenance.json"

    _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "ok"
    assert "not reported" in row["reason"]
    assert "none found" not in row["reason"]
