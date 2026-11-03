"""PAT-2305: the deploy installs the nginx site config only if nginx accepts it.

The deploy workflow used to run, under ``set -euo pipefail``::

    cp /opt/patched-dashboard/deploy/nginx-dashboard.conf /etc/nginx/sites-available/dashboard.patched.im
    nginx -t && systemctl reload nginx

The live file was overwritten before it was tested, and a failure on the left
of ``&&`` does not trip ``set -e``, so a config nginx rejected stayed live
while the step exited 0. ``deploy/install-nginx-config.sh`` replaces that.
These tests run it against a scratch directory with fake ``nginx`` and
``systemctl`` executables on ``PATH`` that record their calls and exit with a
code each test chooses.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml


REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "install-nginx-config.sh"
WORKFLOW = REPO / "ci-archive" / "workflows" / "deploy.yml"
LIVE_SCRIPT_PATH = "/opt/patched-dashboard/deploy/install-nginx-config.sh"

NEW_CONFIG = b"server {\n    listen 443 ssl http2;\n    # new config from the repo\n}\n"
BROKEN_CONFIG = b"server {\n    this is not valid nginx\n"
# Deliberately awkward bytes (CRLF, non-ASCII, no trailing newline) so that a
# restore which normalises anything at all fails the byte-for-byte check.
PREVIOUS_CONFIG = b"server {\r\n    # caf\xc3\xa9: previous live config\r\n    listen 443 ssl http2;\r\n}"

FAKE_NGINX = """#!/usr/bin/env bash
echo "nginx $*" >> "$FAKE_CALLS"
cat "$NGINX_SITE_TARGET" > "$FAKE_SEEN_AT_TEST"
ls -A "$NGINX_SITE_BACKUP_DIR" > "$FAKE_BACKUPS_AT_TEST"
for f in "$NGINX_SITE_BACKUP_DIR"/*; do
    if [ -f "$f" ]; then cat "$f" > "$FAKE_BACKUP_CONTENT_AT_TEST"; fi
done
if [ -n "${FAKE_NGINX_SIGNAL:-}" ]; then kill "-$FAKE_NGINX_SIGNAL" "$PPID"; fi
exit "$FAKE_NGINX_RC"
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_CALLS"
exit "$FAKE_SYSTEMCTL_RC"
"""


@dataclass
class Run:
    returncode: int
    stdout: str
    stderr: str
    target: Path
    backup_dir: Path
    calls: list[str]
    seen_at_test: bytes | None
    backups_at_test: list[str]
    backup_content_at_test: bytes | None

    def backups_left(self) -> list[Path]:
        return sorted(self.backup_dir.iterdir())


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _read_optional(path: Path) -> bytes | None:
    return path.read_bytes() if path.exists() else None


def _run(
    root: Path,
    *,
    source: bytes | None,
    previous: bytes | None,
    previous_mode: int = 0o644,
    target_is_symlink: bool = False,
    nginx_rc: int = 0,
    systemctl_rc: int = 0,
    nginx_signal: str | None = None,
) -> Run:
    repo_deploy = root / "opt" / "patched-dashboard" / "deploy"
    sites_available = root / "etc" / "nginx" / "sites-available"
    backup_dir = root / "var" / "tmp"
    fakebin = root / "bin"
    record = root / "record"
    for directory in (repo_deploy, sites_available, backup_dir, fakebin, record):
        directory.mkdir(parents=True, exist_ok=True)

    source_path = repo_deploy / "nginx-dashboard.conf"
    if source is not None:
        source_path.write_bytes(source)
    target = sites_available / "dashboard.patched.im"
    if target_is_symlink:
        elsewhere = root / "elsewhere.conf"
        elsewhere.write_bytes(PREVIOUS_CONFIG)
        target.symlink_to(elsewhere)
    elif previous is not None:
        target.write_bytes(previous)
        target.chmod(previous_mode)

    _write_executable(fakebin / "nginx", FAKE_NGINX)
    _write_executable(fakebin / "systemctl", FAKE_SYSTEMCTL)

    calls = record / "calls"
    seen = record / "seen_at_test"
    backups_seen = record / "backups_at_test"
    backup_content = record / "backup_content_at_test"

    env = {
        "PATH": f"{fakebin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(root),
        "LC_ALL": "C",
        # Production command names are left at their defaults on purpose: the
        # fakes are found through PATH, as the real binaries are on the box.
        "NGINX_SITE_SOURCE": str(source_path),
        "NGINX_SITE_TARGET": str(target),
        "NGINX_SITE_BACKUP_DIR": str(backup_dir),
        "FAKE_CALLS": str(calls),
        "FAKE_SEEN_AT_TEST": str(seen),
        "FAKE_BACKUPS_AT_TEST": str(backups_seen),
        "FAKE_BACKUP_CONTENT_AT_TEST": str(backup_content),
        "FAKE_NGINX_RC": str(nginx_rc),
        "FAKE_SYSTEMCTL_RC": str(systemctl_rc),
    }
    if nginx_signal:
        env["FAKE_NGINX_SIGNAL"] = nginx_signal

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return Run(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        target=target,
        backup_dir=backup_dir,
        calls=calls.read_text().splitlines() if calls.exists() else [],
        seen_at_test=_read_optional(seen),
        backups_at_test=backups_seen.read_text().split() if backups_seen.exists() else [],
        backup_content_at_test=_read_optional(backup_content),
    )


def _describe(run: Run) -> str:
    return f"exit={run.returncode}\nstdout:\n{run.stdout}\nstderr:\n{run.stderr}\ncalls={run.calls}"


# --- Behaviour --------------------------------------------------------------


def test_good_config_is_installed_tested_in_place_reloaded_and_leaves_no_backup(tmp_path):
    run = _run(tmp_path, source=NEW_CONFIG, previous=PREVIOUS_CONFIG)

    assert run.returncode == 0, _describe(run)
    assert run.target.read_bytes() == NEW_CONFIG
    assert run.calls == ["nginx -t", "systemctl reload nginx"], _describe(run)
    # nginx -t ran against the new file in the live path, with the previous
    # file already saved outside /etc/nginx.
    assert run.seen_at_test == NEW_CONFIG
    assert len(run.backups_at_test) == 1, _describe(run)
    assert run.backup_content_at_test == PREVIOUS_CONFIG
    assert run.backups_left() == [], "the backup must be removed after a successful reload"
    assert "::error::" not in run.stderr


def test_bad_config_fails_and_leaves_live_file_byte_identical_without_reload(tmp_path):
    run = _run(
        tmp_path, source=BROKEN_CONFIG, previous=PREVIOUS_CONFIG,
        previous_mode=0o640, nginx_rc=1,
    )

    assert run.returncode == 1, _describe(run)
    assert run.target.read_bytes() == PREVIOUS_CONFIG, "the live file must be restored byte for byte"
    assert stat.S_IMODE(run.target.stat().st_mode) == 0o640, "the live file's mode must survive the restore"
    assert run.calls == ["nginx -t"], "nginx must not be reloaded after a failed test"
    assert run.seen_at_test == BROKEN_CONFIG
    assert "::error::" in run.stderr
    assert "nginx -t rejected" in run.stderr
    assert "restored" in run.stderr
    assert run.backups_left() == [], "a proven restore needs no leftover backup"


def test_first_install_with_good_config(tmp_path):
    run = _run(tmp_path, source=NEW_CONFIG, previous=None)

    assert run.returncode == 0, _describe(run)
    assert run.target.read_bytes() == NEW_CONFIG
    assert run.calls == ["nginx -t", "systemctl reload nginx"], _describe(run)
    assert run.seen_at_test == NEW_CONFIG
    assert run.backups_at_test == []
    assert run.backups_left() == []


def test_first_install_with_bad_config_removes_the_new_file(tmp_path):
    run = _run(tmp_path, source=BROKEN_CONFIG, previous=None, nginx_rc=1)

    assert run.returncode == 1, _describe(run)
    assert not run.target.exists(), "a rejected first install must leave no live file behind"
    assert not run.target.is_symlink()
    assert run.calls == ["nginx -t"]
    assert "::error::" in run.stderr
    assert run.backups_left() == []


def test_reload_failure_fails_the_step_and_keeps_the_tested_config(tmp_path):
    run = _run(tmp_path, source=NEW_CONFIG, previous=PREVIOUS_CONFIG, systemctl_rc=1)

    assert run.returncode == 2, _describe(run)
    # nginx -t accepted it, so it is safe for the next restart; the previous
    # file is kept for a human rather than silently deleted.
    assert run.target.read_bytes() == NEW_CONFIG
    assert run.calls == ["nginx -t", "systemctl reload nginx"]
    assert "::error::" in run.stderr
    assert "reload nginx' failed" in run.stderr
    kept = run.backups_left()
    assert len(kept) == 1 and kept[0].read_bytes() == PREVIOUS_CONFIG
    assert str(kept[0]) in run.stderr


def test_termination_before_the_test_finishes_restores_the_previous_file(tmp_path):
    # The SSH session dropping mid-deploy delivers a signal to the script
    # while nginx -t is running. The trap must put the previous file back.
    run = _run(tmp_path, source=BROKEN_CONFIG, previous=PREVIOUS_CONFIG, nginx_signal="TERM")

    assert run.returncode != 0, _describe(run)
    assert run.target.read_bytes() == PREVIOUS_CONFIG
    assert "systemctl reload nginx" not in run.calls
    assert "::error::" in run.stderr
    assert run.backups_left() == []


def test_missing_source_changes_nothing(tmp_path):
    run = _run(tmp_path, source=None, previous=PREVIOUS_CONFIG)

    assert run.returncode == 1, _describe(run)
    assert run.target.read_bytes() == PREVIOUS_CONFIG
    assert run.calls == []
    assert "::error::" in run.stderr
    assert run.backups_left() == []


def test_symlinked_live_path_is_refused_without_writing_through_it(tmp_path):
    run = _run(tmp_path, source=NEW_CONFIG, previous=None, target_is_symlink=True)

    assert run.returncode == 1, _describe(run)
    assert run.target.is_symlink()
    assert (tmp_path / "elsewhere.conf").read_bytes() == PREVIOUS_CONFIG
    assert run.calls == []
    assert "::error::" in run.stderr


# --- Script shape ------------------------------------------------------------


def _code_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_script_is_executable_and_parses():
    # The workflow runs it by absolute path, like scripts/deploy.sh.
    assert os.access(SCRIPT, os.X_OK), f"{SCRIPT} must be executable"
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_script_never_chains_a_failure_path_with_and():
    offenders = [line for line in _code_lines(SCRIPT.read_text(encoding="utf-8")) if "&&" in line]
    assert offenders == [], "use `if ! cmd; then ...; fi`, never `a && b`: " + repr(offenders)


def test_script_defaults_are_production_and_backup_is_outside_nginx_and_patched_config():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'NGINX_SITE_SOURCE:-/opt/patched-dashboard/deploy/nginx-dashboard.conf}' in text
    assert 'NGINX_SITE_TARGET:-/etc/nginx/sites-available/dashboard.patched.im}' in text
    assert 'NGINX_CMD:-nginx}' in text
    assert 'SYSTEMCTL_CMD:-systemctl}' in text
    # PAT-1408's stray-config-backup check scans /etc/patched-*, and nginx
    # includes globs under /etc/nginx, so the backup lives in neither.
    assert 'NGINX_SITE_BACKUP_DIR:-/var/tmp}' in text


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_script_passes_shellcheck():
    result = subprocess.run(["shellcheck", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


# --- Workflow ----------------------------------------------------------------


def _verify_step_script() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for step in workflow["jobs"]["deploy"]["steps"]:
        if "verify deployed revision" in step.get("name", "").lower():
            return step["with"]["script"]
    raise AssertionError("no deploy workflow step verifies the deployed revision")


def test_workflow_step_calls_the_script_after_the_revision_check():
    script = _verify_step_script()

    assert LIVE_SCRIPT_PATH in script
    call_at = script.index(LIVE_SCRIPT_PATH)
    assert script.index('"$deployed_sha" != "$expected_sha"') < call_at
    assert script.index("systemctl is-active --quiet patched-dashboard") < call_at
    assert call_at < script.index("Verified deployment")
    # The failure is checked explicitly, not left to set -e.
    call_line = next(line for line in script.splitlines() if LIVE_SCRIPT_PATH in line)
    assert call_line.strip() == f"if ! {LIVE_SCRIPT_PATH}; then"


def test_workflow_step_no_longer_installs_or_tests_nginx_inline():
    script = _verify_step_script()
    code = "\n".join(_code_lines(script))

    assert "nginx -t && systemctl reload nginx" not in script
    assert "&&" not in code
    assert "nginx -t" not in code
    assert "reload nginx" not in code
    assert "/etc/nginx" not in code
