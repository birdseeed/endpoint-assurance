"""PAT-1237: normal portal-01 deploys reject unhardened installed units."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "verify-systemd-hardening-floor.sh"
INSTALL = REPO / "deploy" / "install.sh"
INSTALL_SCAN = REPO / "deploy" / "install-scan.sh"
INSTALL_HELPER = REPO / "deploy" / "install-verified-systemd-service.sh"


def _run_guard(
    analysis: str,
    load_state: str = "loaded",
    units: tuple[str, ...] = ("patched-scan.service",),
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        fakebin = Path(temporary) / "bin"
        fakebin.mkdir()
        (fakebin / "systemctl").write_text(
            '#!/usr/bin/env bash\n[[ $1 == show ]] && echo "$HARDENING_LOAD_STATE"\n'
        )
        (fakebin / "systemd-analyze").write_text(
            "#!/usr/bin/env bash\n"
            "[[ $LC_ALL == C && $SYSTEMD_COLORS == 0 && $SYSTEMD_EMOJI == 0 ]] || exit 4\n"
            "[[ $* == *security* ]] && printf '%s\\n' \"$HARDENING_ANALYSIS\"\n"
        )
        for command in fakebin.iterdir():
            command.chmod(command.stat().st_mode | stat.S_IXUSR)
        env = dict(
            os.environ,
            PATH=f"{fakebin}:/usr/bin:/bin",
            HARDENING_ANALYSIS=analysis,
            HARDENING_LOAD_STATE=load_state,
        )
        return subprocess.run(
            ["bash", str(SCRIPT), *units],
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )


def test_deliberately_unhardened_unit_fails_the_deploy_guard():
    result = _run_guard("-> Overall exposure level for patched-scan.service: 9.6 UNSAFE :-|")
    assert result.returncode != 0
    assert "above application ceiling 6.0" in result.stderr


def test_unparseable_score_fails_closed():
    result = _run_guard("systemd-analyze output changed")
    assert result.returncode != 0
    assert "no parseable exposure score" in result.stderr


def test_within_exact_unclassified_and_not_loaded_cases():
    for score in ("5.9", "6.0"):
        assert (
            _run_guard(
                f"-> Overall exposure level for patched-scan.service: {score} MEDIUM :-|"
            ).returncode
            == 0
        )
    assert (
        _run_guard(
            "-> Overall exposure level for patched-unknown.service: 1.0 OK :-|",
            units=("patched-unknown.service",),
        ).returncode
        != 0
    )
    assert (
        _run_guard(
            "-> Overall exposure level for patched-scan.service: 1.0 OK :-|", load_state="not-found"
        ).returncode
        != 0
    )


def test_parser_accepts_real_systemd_presentation_variants_and_multiple_units():
    result = _run_guard(
        "\n".join(
            (
                "→ Overall exposure level for patched-scan.service: 5.9 MEDIUM 🙂",
                "Overall exposure level for patched-scan-nvd-refresh.service: 6.0 MEDIUM",
            )
        ),
        units=("patched-scan.service", "patched-scan-nvd-refresh.service"),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("within") == 2


def _run_installer_helper(
    systemd_dir: Path,
    score: str,
    unit: str,
    *,
    fragment: Path | None = None,
    reload_fail: bool = False,
    assert_trap_preserved: bool = False,
) -> subprocess.CompletedProcess[str]:
    fakebin = systemd_dir.parent / "bin"
    fakebin.mkdir(exist_ok=True)
    (fakebin / "systemctl").write_text(
        "#!/usr/bin/env bash\n"
        'if [[ $1 == show && $* == *FragmentPath* ]]; then echo "$HARDENING_FRAGMENT"; exit 0; fi\n'
        "if [[ $1 == show ]]; then echo loaded; exit 0; fi\n"
        "if [[ $1 == daemon-reload && $FAIL_RELOAD == 1 ]]; then\n"
        '  count=$(cat "$RELOAD_COUNT"); echo $((count + 1)) > "$RELOAD_COUNT"\n'
        "  [[ $count == 0 ]] && exit 9\n"
        "fi\n"
        "exit 0\n"
    )
    (fakebin / "systemd-analyze").write_text(
        "#!/usr/bin/env bash\n"
        "unit=${@: -1}\n"
        'printf \'→ Overall exposure level for %s: %s MEDIUM 🙂\\n\' "$unit" "$HARDENING_SCORE"\n'
    )
    for command in fakebin.iterdir():
        command.chmod(command.stat().st_mode | stat.S_IXUSR)
    env = dict(
        os.environ,
        PATH=f"{fakebin}:/usr/bin:/bin",
        REPO_DIR=str(REPO),
        PATCHED_SYSTEMD_DIR=str(systemd_dir),
        PATCHED_SYSTEMD_TEST_MODE="1",
        HARDENING_SCORE=score,
        UNIT=unit,
        HARDENING_FRAGMENT=str(fragment or (systemd_dir / unit)),
        FAIL_RELOAD="1" if reload_fail else "0",
        RELOAD_COUNT=str(systemd_dir.parent / "reload-count"),
    )
    Path(env["RELOAD_COUNT"]).write_text("0\n")
    command = (
        'source "$REPO_DIR/deploy/install-verified-systemd-service.sh"; '
        'install_and_verify_service "$UNIT"'
    )
    if assert_trap_preserved:
        command = (
            "trap 'echo caller-hup >/dev/null' HUP; before=$(trap -p HUP); "
            + command
            + '; rc=$?; after=$(trap -p HUP); [[ "$before" == "$after" ]] || exit 42; exit "$rc"'
        )
    return subprocess.run(
        ["bash", "-c", command],
        text=True,
        capture_output=True,
        env=env,
        timeout=10,
    )


def test_installer_helper_restores_prior_unit_and_cleans_temporary_files():
    with tempfile.TemporaryDirectory() as temporary:
        systemd_dir = Path(temporary) / "systemd"
        systemd_dir.mkdir()
        target = systemd_dir / "patched-scan.service"
        target.write_text("previous unit\n")
        target.chmod(0o600)
        result = _run_installer_helper(systemd_dir, "9.6", target.name)
        assert result.returncode != 0
        assert target.read_text() == "previous unit\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert not list(systemd_dir.glob("*.pat1237-*"))
        assert "restored previous unit" in result.stderr


def test_installer_helper_removes_rejected_fresh_install():
    with tempfile.TemporaryDirectory() as temporary:
        systemd_dir = Path(temporary) / "systemd"
        systemd_dir.mkdir()
        target = systemd_dir / "patched-scan.service"
        result = _run_installer_helper(systemd_dir, "9.6", target.name)
        assert result.returncode != 0
        assert not target.exists()
        assert not list(systemd_dir.glob("*.pat1237-*"))
        assert "removed rejected fresh install" in result.stderr


def test_installer_helper_positive_install_path_promotes_and_cleans_stage():
    with tempfile.TemporaryDirectory() as temporary:
        systemd_dir = Path(temporary) / "systemd"
        systemd_dir.mkdir()
        target = systemd_dir / "patched-scan.service"
        result = _run_installer_helper(systemd_dir, "5.9", target.name)
        assert result.returncode == 0, result.stderr
        assert target.read_text() == (REPO / "deploy" / target.name).read_text()
        assert not list(systemd_dir.glob("*.pat1237-*"))
        assert "installed and verified" in result.stdout


def test_installer_rejects_stale_fragment_path_and_restores_previous_unit():
    with tempfile.TemporaryDirectory() as temporary:
        systemd_dir = Path(temporary) / "systemd"
        systemd_dir.mkdir()
        target = systemd_dir / "patched-scan.service"
        target.write_text("previous unit\n")
        stale = Path(temporary) / "stale.service"
        stale.write_text((REPO / "deploy" / target.name).read_text())
        result = _run_installer_helper(systemd_dir, "5.9", target.name, fragment=stale)
        assert result.returncode != 0
        assert "installed fragment mismatch" in result.stderr
        assert target.read_text() == "previous unit\n"


def test_installer_refuses_symlinked_service_target():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        systemd_dir = root / "systemd"
        systemd_dir.mkdir()
        elsewhere = root / "elsewhere.service"
        elsewhere.write_text("untouched\n")
        (systemd_dir / "patched-scan.service").symlink_to(elsewhere)
        result = _run_installer_helper(systemd_dir, "5.9", "patched-scan.service")
        assert result.returncode != 0
        assert "refusing non-regular installed systemd unit" in result.stderr
        assert elsewhere.read_text() == "untouched\n"


def test_installer_distinguishes_reload_failure_and_preserves_caller_trap():
    with tempfile.TemporaryDirectory() as temporary:
        systemd_dir = Path(temporary) / "systemd"
        systemd_dir.mkdir()
        target = systemd_dir / "patched-scan.service"
        target.write_text("previous unit\n")
        failed = _run_installer_helper(systemd_dir, "5.9", target.name, reload_fail=True)
        assert failed.returncode != 0
        assert "daemon-reload failed after installing" in failed.stderr
        preserved = _run_installer_helper(
            systemd_dir,
            "5.9",
            target.name,
            assert_trap_preserved=True,
        )
        assert preserved.returncode == 0, preserved.stderr


def test_current_portal01_scores_clear_the_deploy_policy():
    result = _run_guard(
        "\n".join(
            (
                "-> Overall exposure level for patched-portal.service: 4.3 OK :-|",
                "-> Overall exposure level for patched-scan.service: 4.3 OK :-|",
                "-> Overall exposure level for patched-scan-nvd-refresh.service: 5.9 MEDIUM :-|",
                "-> Overall exposure level for patched-maintenance-facts.service: 1.8 OK :-|",
            )
        ),
        units=(
            "patched-portal.service",
            "patched-scan.service",
            "patched-scan-nvd-refresh.service",
            "patched-maintenance-facts.service",
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("within") == 4


def test_timer_installer_is_atomic_and_refuses_symlink_target():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        systemd_dir = root / "systemd"
        fakebin = root / "bin"
        systemd_dir.mkdir()
        fakebin.mkdir()
        (fakebin / "systemctl").write_text(
            "#!/usr/bin/env bash\n"
            'if [[ $1 == show && $* == *FragmentPath* ]]; then echo "$HARDENING_FRAGMENT"; fi\n'
            "if [[ $1 == show && $* == *LoadState* ]]; then echo loaded; fi\n"
            "exit 0\n"
        )
        (fakebin / "systemctl").chmod(0o755)
        env = dict(
            os.environ,
            PATH=f"{fakebin}:/usr/bin:/bin",
            REPO_DIR=str(REPO),
            PATCHED_SYSTEMD_DIR=str(systemd_dir),
            UNIT="patched-scan-nvd-refresh.timer",
            PATCHED_SYSTEMD_TEST_MODE="1",
            HARDENING_FRAGMENT=str(systemd_dir / "patched-scan-nvd-refresh.timer"),
        )
        command = (
            'source "$REPO_DIR/deploy/install-verified-systemd-service.sh"; '
            'install_systemd_timer_atomically "$UNIT"'
        )
        installed = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True)
        target = systemd_dir / env["UNIT"]
        assert installed.returncode == 0, installed.stderr
        assert target.read_text() == (REPO / "deploy" / env["UNIT"]).read_text()
        assert not list(systemd_dir.glob("*.pat1237-new.*"))

        target.unlink()
        target.symlink_to(root / "elsewhere")
        refused = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True)
        assert refused.returncode != 0
        assert "refusing non-regular installed systemd timer" in refused.stderr


def test_timer_installer_rejects_stale_fragment_and_restores_previous_bytes():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        systemd_dir = root / "systemd"
        fakebin = root / "bin"
        systemd_dir.mkdir()
        fakebin.mkdir()
        target = systemd_dir / "patched-scan-nvd-refresh.timer"
        target.write_text("previous timer\n")
        stale = root / "stale.timer"
        stale.write_text((REPO / "deploy" / target.name).read_text())
        (fakebin / "systemctl").write_text(
            "#!/usr/bin/env bash\n"
            'if [[ $1 == show && $* == *FragmentPath* ]]; then echo "$HARDENING_FRAGMENT"; fi\n'
            "if [[ $1 == show && $* == *LoadState* ]]; then echo loaded; fi\n"
            "exit 0\n"
        )
        (fakebin / "systemctl").chmod(0o755)
        env = dict(
            os.environ,
            PATH=f"{fakebin}:/usr/bin:/bin",
            REPO_DIR=str(REPO),
            PATCHED_SYSTEMD_DIR=str(systemd_dir),
            PATCHED_SYSTEMD_TEST_MODE="1",
            HARDENING_FRAGMENT=str(stale),
            UNIT=target.name,
        )
        command = (
            'source "$REPO_DIR/deploy/install-verified-systemd-service.sh"; '
            'install_systemd_timer_atomically "$UNIT"'
        )
        result = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True)
        assert result.returncode != 0
        assert "installed timer fragment mismatch" in result.stderr
        assert target.read_text() == "previous timer\n"


def test_production_systemd_override_is_explicitly_root_refused():
    helper = INSTALL_HELPER.read_text()
    assert (
        '[[ "$EUID" -ne 0 ]] || { echo "systemd test override is refused for root installs"'
        in helper
    )


def test_both_installers_validate_helpers_before_source_and_fail_explicitly():
    for installer in (INSTALL, INSTALL_SCAN):
        text = installer.read_text()
        source_marker = 'source "/dev/fd/$helper_fd"'
        assert source_marker in text
        assert text.index("bash -n") < text.index(source_marker)
        assert text.index('exec {helper_fd}<"$helper"') < text.index(source_marker)
        for unit_call in (
            line for line in text.splitlines() if line.startswith("install_and_verify_service ")
        ):
            assert unit_call.endswith(" || exit 1")
    assert INSTALL_HELPER.is_file()
    assert os.access(INSTALL_HELPER, os.X_OK)
    assert os.access(SCRIPT, os.X_OK)
