"""PAT-2311: deploy hardening follow-ups to PAT-2307, box-side config.

- The reports-pruning timer was hand-installed; sync_box_config now installs,
  enables and verifies it the same way it does the patched-maintenance-facts
  timer, and restores its state if the sync fails.
- deploy/removed-artifacts.txt removes the stale standalone deploy copy and
  the runtime data PAT-2307 left in the code tree.
- The backup unit in the repo matches the one live on patched-prod-01.
- CI runs the deploy hook's rollback dry run.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import yaml

from tests.retired_account_box import absent_account_assignments

REPO = Path(__file__).resolve().parent.parent
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
MANIFEST =REPO / "deploy" / "removed-artifacts.txt"
ROLLBACK_TEST = REPO / "scripts" / "test-post-receive-rollback.sh"
CI = REPO / "ci-archive" / "workflows" / "ci.yml"
TIMER = "patched-dashboard-prune-reports.timer"
MANAGED_UNITS = (
    "patched-dashboard.service", "patched-dashboard-prune-reports.service",
    "patched-maintenance-facts.service", "patched-maintenance-facts.timer",
)


# ── the prune timer in sync_box_config ─────────────────────────────────────


def _sync_box_config_function() -> str:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("\nsync_box_config() (\n") + 1
    return text[start:text.index("\n# rollback REASON", start)]


def _run_sync(
    tmp_path: Path, *, ship_timer: bool = True, installed_timer: str | None = None,
    timer_state: str = "on",
) -> tuple[subprocess.CompletedProcess[str], Path, list[str], str]:
    """Drive the real sync_box_config against scratch directories.

    timer_state is what the fake systemctl reports for the prune timer's
    is-enabled and is-active: "on" (both succeed) or "off" (both fail, as
    for a disabled, stopped timer). Every other query succeeds.
    """
    repo = tmp_path / "repo"
    deploy_dir = repo / "deploy"
    systemd_dir = tmp_path / "systemd"
    fakebin = tmp_path / "bin"
    for directory in (deploy_dir, systemd_dir, tmp_path / "polkit", fakebin):
        directory.mkdir(parents=True)
    for unit in MANAGED_UNITS:
        (deploy_dir / unit).write_text(f"{unit}\n")
        (systemd_dir / unit).write_text(f"{unit}\n")
    if ship_timer:
        (deploy_dir / TIMER).write_text("new timer\n")
    if installed_timer is not None:
        (systemd_dir / TIMER).write_text(installed_timer)
    events = tmp_path / "events"
    (fakebin / "systemctl").write_text(
        "#!/usr/bin/env bash\n"
        "echo \"$*\" >> \"$EVENTS\"\n"
        "case \"$1\" in\n"
        "  show) echo loaded ;;\n"
        f"  is-enabled|is-active) [[ \"$*\" == *{TIMER}* && $TIMER_STATE == off ]] && exit 1; exit 0 ;;\n"
        "esac\n"
        "exit 0\n"
    )
    guard = deploy_dir / "verify-systemd-hardening-floor.sh"
    guard.write_text("#!/usr/bin/env bash\nexit 0\n")
    for executable in (fakebin / "systemctl", guard):
        executable.chmod(0o755)
    log = tmp_path / "deploy.log"
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\nset -eu\n"
        f"REPO_DIR={shlex.quote(str(repo))}\nSYSTEMD_DIR={shlex.quote(str(systemd_dir))}\n"
        f"POLKIT_RULES_DIR={shlex.quote(str(tmp_path / 'polkit'))}\nLOG={shlex.quote(str(log))}\n"
        "CONFIG_OWNER=$(id -un)\nCONFIG_GROUP=$(id -gn)\n"
        f"REMOVED_ARTIFACTS_MANIFEST={shlex.quote(str(deploy_dir / 'removed-artifacts.txt'))}\n"
        # PAT-2312: scratch paths, so the sync never touches a real hcloud
        # or origin TLS key.
        f"HCLOUD_BIN={shlex.quote(str(tmp_path / 'no-hcloud'))}\n"
        f"ORIGIN_KEY={shlex.quote(str(tmp_path / 'no-origin-key'))}\n"
        # PAT-2312: a scratch account that does not exist, so the sync can
        # never reach a real one.
        + absent_account_assignments(tmp_path, fakebin)
        + "log() { echo \"$*\" >> \"$LOG\"; }\n" + _sync_box_config_function() + "\nsync_box_config\n"
    )
    env = dict(
        os.environ, PATH=f"{fakebin}:/usr/bin:/bin", EVENTS=str(events),
        TIMER_STATE=timer_state, TMPDIR=str(tmp_path),
    )
    result = subprocess.run(["bash", str(harness)], text=True, capture_output=True, env=env, timeout=30)
    calls = events.read_text().splitlines() if events.exists() else []
    return result, systemd_dir, calls, log.read_text() if log.exists() else ""


def test_a_missing_timer_is_installed_enabled_and_verified(tmp_path):
    result, systemd_dir, calls, log = _run_sync(tmp_path)
    assert result.returncode == 0, log
    assert (systemd_dir / TIMER).read_text() == "new timer\n"
    assert calls.index("daemon-reload") < calls.index(f"enable --now {TIMER}")
    assert f"is-enabled --quiet {TIMER}" in calls[calls.index(f"enable --now {TIMER}"):]
    assert f"is-active --quiet {TIMER}" in calls[calls.index(f"enable --now {TIMER}"):]
    assert f"{TIMER} enabled and started" in log


def test_an_unchanged_timer_is_left_alone_but_still_verified(tmp_path):
    """The state of patched-prod-01 when this lands: the hand-installed timer
    is byte-identical to the repo's, enabled and active."""
    result, _, calls, log = _run_sync(tmp_path, installed_timer="new timer\n")
    assert result.returncode == 0, log
    assert f"Installing systemd unit: {tmp_path}/repo/deploy/{TIMER}" not in log
    assert f"systemd unit unchanged ({tmp_path}/systemd/{TIMER})" in log
    assert f"enable --now {TIMER}" not in calls
    assert not any(call.startswith(("start ", "stop ", "restart ", "enable ", "disable ")) for call in calls)
    assert calls.count(f"is-enabled --quiet {TIMER}") >= 2, "snapshot, then verify"
    assert calls.count(f"is-active --quiet {TIMER}") >= 2


def test_a_changed_timer_is_reinstalled_and_re_enabled(tmp_path):
    result, systemd_dir, calls, log = _run_sync(tmp_path, installed_timer="old timer\n")
    assert result.returncode == 0, log
    assert (systemd_dir / TIMER).read_text() == "new timer\n"
    assert f"enable --now {TIMER}" in calls


def test_a_timer_that_is_not_enabled_fails_the_sync_and_is_restored(tmp_path):
    """Fail loudly rather than leave the reports unpruned, and leave the box
    as it was: the previous file back, and the timer's enabled and active
    state back to what it was before the sync."""
    result, systemd_dir, calls, log = _run_sync(tmp_path, installed_timer="old timer\n", timer_state="off")
    assert result.returncode != 0
    assert f"ERROR: {TIMER} is not enabled after box-config sync" in log
    assert f"ERROR: {TIMER} is not active after box-config sync" in log
    assert (systemd_dir / TIMER).read_text() == "old timer\n"
    restore = calls[calls.index(f"enable --now {TIMER}") + 1:]
    assert f"disable {TIMER}" in restore
    assert f"stop {TIMER}" in restore
    assert "restored changed units and timer state" in log
    assert "CRITICAL" not in log


def test_a_checkout_without_the_timer_leaves_the_installed_one_untouched(tmp_path):
    """A rollback to a commit from before this change: its sync neither
    removes nor touches the timer the box already has."""
    result, systemd_dir, calls, log = _run_sync(tmp_path, ship_timer=False, installed_timer="live timer\n")
    assert result.returncode == 0, log
    assert (systemd_dir / TIMER).read_text() == "live timer\n"
    assert not any(TIMER in call for call in calls)
    assert "leaving the installed timer as it is" in log


def test_the_repo_ships_the_timer_the_sync_manages():
    timer = REPO / "deploy" / TIMER
    assert timer.is_file() and not timer.is_symlink()
    text = timer.read_text(encoding="utf-8")
    assert "[Install]\nWantedBy=timers.target" in text
    assert "OnCalendar=*-*-* 03:42:00 UTC" in text


# ── deploy/removed-artifacts.txt ───────────────────────────────────────────


def _manifest_paths() -> list[str]:
    return [
        line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_the_stale_standalone_deploy_copy_is_removed():
    assert "/usr/local/bin/patched-deploy.sh" in _manifest_paths()


def test_the_runtime_data_left_in_the_tree_is_removed():
    paths = _manifest_paths()
    assert "/opt/patched-dashboard/nvd.db" in paths
    assert "/opt/patched-dashboard/dashboard.db" in paths


def test_the_manifest_never_names_production_data_or_a_directory():
    """sync_box_config removes each entry with `rm -f` as root on every
    deploy. The state directory holds the live database and reports; a
    directory entry would fail every deploy (rm -f cannot remove one); and the
    code tree's reports/ is still what the live backup reads."""
    for path in _manifest_paths():
        assert path.startswith("/"), path
        assert ".." not in path.split("/"), path
        assert not path.startswith("/var/lib/patched-dashboard"), path
        assert not path.endswith("/"), path
        assert path not in ("/opt/patched-dashboard", "/opt/patched-dashboard/reports"), path


def test_no_manifest_entry_in_the_code_tree_is_a_tracked_file():
    """Removing a tracked file would leave the checkout dirty, which
    deploy_drift reports as a hand edit. Only untracked leftovers belong."""
    for path in _manifest_paths():
        if not path.startswith("/opt/patched-dashboard/"):
            continue
        relative = path[len("/opt/patched-dashboard/"):]
        tracked = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "--error-unmatch", relative],
            capture_output=True, text=True,
        )
        assert tracked.returncode != 0, f"{path} is tracked in the repo"


def test_the_deploy_script_header_no_longer_offers_the_standalone_copy():
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert "is still supported for on-demand redeploys" not in text


# ── the backup unit ────────────────────────────────────────────────────────


def test_the_backup_unit_matches_the_box_and_is_not_installed_by_the_deploy():
    """Read from patched-prod-01 on 2026-09-30: the script runs from
    /usr/local/libexec, outside the code tree. sync_box_config does not
    install this unit, so the repo copy is a record, not a deploy input."""
    unit = (REPO / "deploy" / "patched-prod-backup.service").read_text(encoding="utf-8")
    exec_start = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
    assert exec_start == ["ExecStart=/usr/local/libexec/patched-prod-backup/prod-backup.sh"]
    assert "patched-prod-backup" not in _sync_box_config_function()


# ── CI runs the rollback dry run ───────────────────────────────────────────


def test_ci_runs_the_post_receive_rollback_dry_run():
    steps = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["test"]["steps"]
    runs = [step.get("run", "") for step in steps]
    assert "bash scripts/test-post-receive-rollback.sh" in runs


def test_the_dry_run_does_not_depend_on_the_callers_umask_or_git_config():
    """A GitHub runner has no init.defaultBranch (macOS's Xcode git sets main
    system-wide) and may run with umask 002. Without these two lines the dry
    run fails there on every check (reproduced with GIT_CONFIG_NOSYSTEM=1 and
    umask 002 before they were added). The CI step itself is the real proof."""
    text = ROLLBACK_TEST.read_text(encoding="utf-8")
    assert "\numask 022\n" in text
    assert 'git -C "$MIRROR" symbolic-ref HEAD refs/heads/main' in text
