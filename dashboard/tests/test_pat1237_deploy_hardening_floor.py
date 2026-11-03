"""PAT-1237: normal prod-01 deploys reject an unhardened installed unit."""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
import tempfile
from pathlib import Path

from tests.retired_account_box import absent_account_assignments

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "verify-systemd-hardening-floor.sh"
DEPLOY = REPO / "scripts" / "deploy.sh"


def _sync_box_config_function() -> str:
    text = DEPLOY.read_text(encoding="utf-8")
    start = text.index("\nsync_box_config() (\n") + 1
    end = text.index("\n# rollback REASON", start)
    return text[start:end]


def _run_sync_box_config(
    *, include_units: bool = True, guard_rc: int = 0, existing: bool = False,
    load_state: str = "loaded", restore_fail: bool = False, existing_matches: bool = False,
    inactive_commands_fail: bool = False, symlink_source: bool = False,
    include_polkit: bool = False, guard_present: bool = True, rollback_sync: bool = False,
):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    repo = root / "repo"
    deploy_dir = repo / "deploy"
    systemd_dir = root / "systemd"
    polkit_dir = root / "polkit"
    fakebin = root / "bin"
    for directory in (deploy_dir, systemd_dir, polkit_dir, fakebin):
        directory.mkdir(parents=True, exist_ok=True)
    units = ("patched-dashboard.service", "patched-maintenance-facts.service", "patched-maintenance-facts.timer")
    if include_units:
        for unit in units:
            (deploy_dir / unit).write_text(f"new {unit}\n")
    if symlink_source:
        source = deploy_dir / "patched-dashboard.service"
        source.unlink(missing_ok=True)
        source.symlink_to(deploy_dir / "patched-maintenance-facts.service")
    if include_polkit:
        (deploy_dir / "49-patched-test.rules").write_text("new rule\n")
    if existing:
        for unit in units:
            prefix = "new" if existing_matches else "old"
            (systemd_dir / unit).write_text(f"{prefix} {unit}\n")
    events = root / "events"
    log = root / "deploy.log"
    (fakebin / "systemctl").write_text(
        "#!/usr/bin/env bash\n"
        "echo systemctl:$* >> \"$EVENTS\"\n"
        "case $1 in\n"
        "  show) echo \"$LOAD_STATE\";;\n"
        "  is-enabled|is-active) [[ $INACTIVE_COMMANDS_FAIL == 1 ]] && exit 1; exit 0;;\n"
        "  disable|stop) [[ $INACTIVE_COMMANDS_FAIL == 1 ]] && exit 5; exit 0;;\n"
        "  *) exit 0;;\n"
        "esac\n"
    )
    (fakebin / "systemctl").chmod(0o755)
    (fakebin / "mv").write_text(
        "#!/usr/bin/env bash\n"
        "if [[ $RESTORE_FAIL == 1 && ${@: -2:1} == *.pat1237-restore.* ]]; then exit 8; fi\n"
        "exec /bin/mv \"$@\"\n"
    )
    (fakebin / "mv").chmod(0o755)
    if guard_present:
        guard = deploy_dir / "verify-systemd-hardening-floor.sh"
        guard.write_text(
            "#!/usr/bin/env bash\n"
            "echo guard:$* >> \"$EVENTS\"\n"
            "exit \"$GUARD_RC\"\n"
        )
        guard.chmod(0o755)
    harness = root / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\nset -eu\n"
        f"REPO_DIR={shlex.quote(str(repo))}\nSYSTEMD_DIR={shlex.quote(str(systemd_dir))}\nPOLKIT_RULES_DIR={shlex.quote(str(polkit_dir))}\n"
        f"LOG={shlex.quote(str(log))}\nCONFIG_OWNER=$(id -un)\nCONFIG_GROUP=$(id -gn)\n"
        f"REMOVED_ARTIFACTS_MANIFEST={shlex.quote(str(deploy_dir / 'removed-artifacts.txt'))}\n"
        # PAT-2312: scratch paths, so the sync never touches a real hcloud
        # or origin TLS key.
        f"HCLOUD_BIN={shlex.quote(str(root / 'no-hcloud'))}\n"
        f"ORIGIN_KEY={shlex.quote(str(root / 'no-origin-key'))}\n"
        # PAT-2312: a scratch account that does not exist, so the sync can
        # never reach a real one.
        + absent_account_assignments(root, fakebin)
        + "log() { echo \"$*\" >> \"$LOG\"; }\n"
        + _sync_box_config_function()
        + "\nsync_box_config\n"
    )
    harness.chmod(0o755)
    env = dict(
        os.environ, PATH=f"{fakebin}:/usr/bin:/bin", EVENTS=str(events),
        GUARD_RC=str(guard_rc), LOAD_STATE=load_state,
        RESTORE_FAIL="1" if restore_fail else "0",
        INACTIVE_COMMANDS_FAIL="1" if inactive_commands_fail else "0",
        DEPLOY_ROLLBACK_SYNC="1" if rollback_sync else "0",
        TMPDIR=str(root),
    )
    result = subprocess.run(["bash", str(harness)], text=True, capture_output=True, env=env, timeout=10)
    return temporary, result, systemd_dir, events, log


def _run_guard(
    analysis: str,
    load_state: str = "loaded",
    units: tuple[str, ...] = ("patched-dashboard.service",),
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        fakebin = Path(temporary) / "bin"
        fakebin.mkdir()
        (fakebin / "systemctl").write_text(
            "#!/usr/bin/env bash\n[[ $1 == show ]] && echo \"$HARDENING_LOAD_STATE\"\n"
        )
        (fakebin / "systemd-analyze").write_text(
            "#!/usr/bin/env bash\n"
            "[[ $LC_ALL == C && $SYSTEMD_COLORS == 0 && $SYSTEMD_EMOJI == 0 ]] || exit 4\n"
            "[[ $* == *security* ]] && printf '%s\\n' \"$HARDENING_ANALYSIS\"\n"
        )
        for command in fakebin.iterdir():
            command.chmod(command.stat().st_mode | stat.S_IXUSR)
        env = dict(os.environ, PATH=f"{fakebin}:/usr/bin:/bin", HARDENING_ANALYSIS=analysis, HARDENING_LOAD_STATE=load_state)
        return subprocess.run(
            ["bash", str(SCRIPT), *units],
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )


def test_deliberately_unhardened_unit_fails_the_deploy_guard():
    result = _run_guard("-> Overall exposure level for patched-dashboard.service: 9.6 UNSAFE :-|")
    assert result.returncode != 0
    assert "above application ceiling 6.0" in result.stderr


def test_unparseable_score_fails_closed():
    result = _run_guard("systemd-analyze output changed")
    assert result.returncode != 0
    assert "no parseable exposure score" in result.stderr


def test_within_and_exact_ceiling_pass():
    for score in ("5.9", "6.0"):
        result = _run_guard(f"-> Overall exposure level for patched-dashboard.service: {score} MEDIUM :-|")
        assert result.returncode == 0, result.stderr


def test_unclassified_and_not_loaded_fail_closed():
    assert _run_guard("-> Overall exposure level for patched-unknown.service: 1.0 OK :-|", units=("patched-unknown.service",)).returncode != 0
    assert _run_guard("-> Overall exposure level for patched-dashboard.service: 1.0 OK :-|", load_state="not-found").returncode != 0


def test_parser_accepts_real_systemd_presentation_variants_and_multiple_units():
    result = _run_guard(
        "\n".join(
            (
                "→ Overall exposure level for patched-dashboard.service: 5.9 MEDIUM 🙂",
                "Overall exposure level for patched-maintenance-facts.service: 6.0 MEDIUM",
            )
        ),
        units=("patched-dashboard.service", "patched-maintenance-facts.service"),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("within") == 2


def test_box_config_sync_accumulates_service_units_without_errexit_sensitive_and():
    text = DEPLOY.read_text(encoding="utf-8")
    assert 'if [[ "$mf_name" == *.service ]]; then' in text
    assert 'hardening_units+=("$mf_name")' in text
    assert '[[ "$mf_name" == *.service ]] &&' not in text
    assert '"$hardening_guard" "${hardening_units[@]}"' in text


def test_first_install_reloads_before_scoring_and_passes_rc():
    temporary, result, systemd_dir, events, _ = _run_sync_box_config()
    try:
        assert result.returncode == 0, result.stderr
        lines = events.read_text().splitlines()
        guard_index = next(i for i, line in enumerate(lines) if line.startswith("guard:"))
        assert any(line == "systemctl:daemon-reload" for line in lines[:guard_index])
        assert (systemd_dir / "patched-dashboard.service").exists()
    finally:
        temporary.cleanup()


def test_no_service_units_fails_closed_without_running_guard():
    temporary, result, _, events, log = _run_sync_box_config(include_units=False)
    try:
        assert result.returncode != 0
        assert not events.exists() or "guard:" not in events.read_text()
        assert "no copied systemd services" in log.read_text()
    finally:
        temporary.cleanup()


def test_guard_failure_restores_actual_changed_units_and_returns_failure():
    temporary, result, systemd_dir, _, log = _run_sync_box_config(guard_rc=7, existing=True)
    try:
        assert result.returncode != 0
        for unit in ("patched-dashboard.service", "patched-maintenance-facts.service", "patched-maintenance-facts.timer"):
            assert (systemd_dir / unit).read_text() == f"old {unit}\n"
        assert "restored changed units and timer state" in log.read_text()
    finally:
        temporary.cleanup()


def test_not_loaded_state_fails_gate_and_restores_units():
    temporary, result, systemd_dir, _, log = _run_sync_box_config(
        load_state="not-found", existing=True,
    )
    try:
        assert result.returncode != 0
        assert "Systemd hardening floor failed" in log.read_text()
        assert (systemd_dir / "patched-dashboard.service").read_text() == "old patched-dashboard.service\n"
    finally:
        temporary.cleanup()


def test_noop_gate_failure_restores_snapshotted_timer_runtime_state():
    temporary, result, _, events, log = _run_sync_box_config(
        guard_rc=7, existing=True, existing_matches=True,
    )
    try:
        assert result.returncode != 0
        calls = events.read_text()
        assert "systemctl:enable patched-maintenance-facts.timer" in calls
        assert "systemctl:start patched-maintenance-facts.timer" in calls
        assert "restored changed units and timer state" in log.read_text()
    finally:
        temporary.cleanup()


def test_restore_failure_is_critical_and_backup_trap_cleans_up():
    temporary, result, _, _, log = _run_sync_box_config(
        guard_rc=7, existing=True, restore_fail=True,
    )
    try:
        assert result.returncode != 0
        assert "CRITICAL: box-config failure and changed-unit rollback was incomplete" in log.read_text()
        assert not list(Path(temporary.name).glob("tmp.*"))
    finally:
        temporary.cleanup()


def test_fresh_timer_disable_stop_failures_are_non_spurious_when_already_inactive():
    temporary, result, systemd_dir, _, log = _run_sync_box_config(
        inactive_commands_fail=True,
    )
    try:
        assert result.returncode != 0
        assert "CRITICAL" not in log.read_text()
        assert not (systemd_dir / "patched-maintenance-facts.timer").exists()
    finally:
        temporary.cleanup()


def test_symlink_source_is_rejected_without_destroying_existing_unit():
    temporary, result, systemd_dir, _, log = _run_sync_box_config(
        existing=True, symlink_source=True,
    )
    try:
        assert result.returncode != 0
        assert (systemd_dir / "patched-dashboard.service").read_text() == "old patched-dashboard.service\n"
        assert "refusing non-regular systemd source" in log.read_text()
    finally:
        temporary.cleanup()


def test_systemd_failure_still_reconciles_later_polkit_rules():
    temporary, result, _, _, _ = _run_sync_box_config(guard_rc=7, include_polkit=True)
    try:
        assert result.returncode != 0
        assert (Path(temporary.name) / "polkit" / "49-patched-test.rules").read_text() == "new rule\n"
    finally:
        temporary.cleanup()


def test_legacy_rollback_without_guard_restores_without_exit_127():
    temporary, result, _, _, log = _run_sync_box_config(
        existing=True, existing_matches=True, guard_present=False, rollback_sync=True,
    )
    try:
        assert result.returncode == 0, result.stderr
        assert "Legacy rollback target has no executable hardening guard" in log.read_text()
    finally:
        temporary.cleanup()
