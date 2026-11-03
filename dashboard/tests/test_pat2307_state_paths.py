"""PAT-2307: the app writes only to its state directory, and the deploy keeps
the code tree root's.

Runtime-written paths found in the code tree on patched-prod-01 (2026-09-30):
reports/ (shared.REPORTS_DIR, the upload scan's .docx output) and nvd.db
(scanner.py's lazily-built NVD cache). dashboard.db already moved to
/var/lib/patched-dashboard under PAT-994 and is not touched here;
DEPLOYED_SHA is written by root's deploy.sh and only read by the app.

These tests pin: the app honours DASHBOARD_STATE_DIR for both runtime paths;
the systemd unit sets it and no longer grants write access to the code tree;
the prune job follows the reports; deploy.sh never hands the tree back to
www-data and locks it after every reset; and the workflow runs the guard from
its own copy before the push and before the nginx install.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

from tests.retired_account_box import absent_account_assignments

REPO = Path(__file__).resolve().parent.parent
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
UNIT =REPO / "deploy" / "patched-dashboard.service"
PRUNE_UNIT = REPO / "deploy" / "patched-dashboard-prune-reports.service"
PRUNE_SCRIPT = REPO / "deploy" / "prune-reports.sh"
WORKFLOW = REPO / "ci-archive" / "workflows" / "deploy.yml"
STATE_DIR = "/var/lib/patched-dashboard"


def _service_directives(path: Path) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    in_service = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_service = line == "[Service]"
            continue
        if not in_service or not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        directives.setdefault(key.strip(), []).append(value.strip())
    return directives


def _environment(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for value in _service_directives(path).get("Environment", []):
        for assignment in shlex.split(value):
            key, _, val = assignment.partition("=")
            env[key] = val
    return env


def _import_shared(env_overrides: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("DASHBOARD_STATE_DIR", "DASHBOARD_DB_PATH")}
    env.update(env_overrides)
    code = (
        "import shared, json; print(json.dumps({"
        "'BASE': str(shared.BASE), 'STATE_DIR': str(shared.STATE_DIR), "
        "'REPORTS_DIR': str(shared.REPORTS_DIR), 'DB_PATH': str(shared.DB_PATH)}))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO, env=env,
        text=True, capture_output=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    import json
    return json.loads(result.stdout.strip().splitlines()[-1])


# ── the app ────────────────────────────────────────────────────────────────


def test_reports_are_written_to_the_state_dir_when_it_is_set(tmp_path):
    paths = _import_shared({"DASHBOARD_STATE_DIR": str(tmp_path)})
    assert paths["REPORTS_DIR"] == str(tmp_path / "reports")
    assert (tmp_path / "reports").is_dir(), "shared creates the reports dir at import"
    assert not paths["REPORTS_DIR"].startswith(paths["BASE"])


def test_the_database_path_is_unchanged_by_this_ticket(tmp_path):
    """dashboard.db moved under PAT-994 via DASHBOARD_DB_PATH; PAT-2307 must
    not change how that path resolves."""
    paths = _import_shared({"DASHBOARD_STATE_DIR": str(tmp_path)})
    assert paths["DB_PATH"] == str(Path(paths["BASE"]) / "dashboard.db")
    explicit = _import_shared({"DASHBOARD_STATE_DIR": str(tmp_path), "DASHBOARD_DB_PATH": str(tmp_path / "x.db")})
    assert explicit["DB_PATH"] == str(tmp_path / "x.db")


def test_without_a_state_dir_the_checkout_is_used_as_before():
    paths = _import_shared({})
    assert paths["STATE_DIR"] == paths["BASE"]
    assert paths["REPORTS_DIR"] == str(Path(paths["BASE"]) / "reports")


def test_the_nvd_cache_follows_the_state_dir(monkeypatch, tmp_path):
    import scanner

    monkeypatch.setenv("DASHBOARD_STATE_DIR", str(tmp_path))
    assert scanner.nvd_db_path() == str(tmp_path / "nvd.db")
    monkeypatch.delenv("DASHBOARD_STATE_DIR")
    assert scanner.nvd_db_path() == os.path.join(os.path.dirname(scanner.__file__), "nvd.db")


def test_the_scan_reads_the_cache_through_nvd_db_path():
    source = (REPO / "scanner.py").read_text(encoding="utf-8")
    scan_body = source.split("def _scan(", 1)[1].split("\ndef ", 1)[0]
    assert "db_path = nvd_db_path()" in scan_body
    assert 'os.path.dirname(__file__), "nvd.db"' not in scan_body


def test_no_runtime_write_path_is_anchored_in_the_code_tree():
    shared = (REPO / "shared.py").read_text(encoding="utf-8")
    assert 'REPORTS_DIR = STATE_DIR / "reports"' in shared
    assert 'BASE / "reports"' not in shared


# ── the systemd units ──────────────────────────────────────────────────────


def test_the_service_gets_a_state_directory_and_no_write_access_to_the_code_tree():
    directives = _service_directives(UNIT)
    assert directives.get("StateDirectory") == ["patched-dashboard"]
    assert directives.get("StateDirectoryMode") == ["0750"]
    assert directives.get("ProtectSystem") == ["strict"], (
        "strict is what makes the code tree read-only in the service's namespace"
    )
    assert directives.get("WorkingDirectory") == ["/opt/patched-dashboard"]
    for value in directives.get("ReadWritePaths", []):
        for path in value.split():
            assert not path.lstrip("-").startswith("/opt/patched-dashboard"), (
                f"the service must not be able to write the code tree root runs from: {value}"
            )
    assert _environment(UNIT).get("DASHBOARD_STATE_DIR") == STATE_DIR


def test_the_service_trusts_its_root_owned_checkout_for_read_only_git():
    env = _environment(UNIT)
    assert env.get("GIT_CONFIG_COUNT") == "1"
    assert env.get("GIT_CONFIG_KEY_0") == "safe.directory"
    assert env.get("GIT_CONFIG_VALUE_0") == "/opt/patched-dashboard"


def test_the_prune_job_follows_the_reports_into_the_state_dir():
    directives = _service_directives(PRUNE_UNIT)
    assert directives.get("ReadWritePaths") == [f"-{STATE_DIR}/reports"]
    assert _environment(PRUNE_UNIT).get("REPORTS_DIR") == f"{STATE_DIR}/reports"
    assert f'REPORTS_DIR="${{REPORTS_DIR:-{STATE_DIR}/reports}}"' in PRUNE_SCRIPT.read_text(encoding="utf-8")
    assert directives.get("User") == ["www-data"]


# ── scripts/deploy.sh ──────────────────────────────────────────────────────


def _code_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_deploy_never_hands_the_tree_back_to_the_service_user():
    text = DEPLOY_SH.read_text(encoding="utf-8")
    for line in _code_lines(text):
        assert not re.search(r"\bchown\s+-R\b", line), f"recursive chown in deploy.sh: {line.strip()}"
        assert "www-data" not in line, f"deploy.sh code names the service user: {line.strip()}"
    assert "SERVICE_OWNER" not in text


def test_deploy_checks_the_tree_before_it_runs_anything_from_it():
    text = DEPLOY_SH.read_text(encoding="utf-8")
    check = text.index("if ! code_tree_guard check; then")
    assert check < text.index('git fetch origin >> "$LOG"')
    assert check < text.index('git pull --ff-only origin main')
    assert check < text.index('\nif ! sync_box_config; then')
    assert text.index('cp "$CODE_TREE_GUARD_SRC" "$CODE_TREE_GUARD"') < check


def test_deploy_locks_the_tree_after_every_reset_before_pip_sync_or_restart():
    text = DEPLOY_SH.read_text(encoding="utf-8")
    forward_reset = text.index('git reset --hard "$FROM_HOOK"')
    forward_lock = text.index("if ! lock_code_tree; then\n    log \"ERROR: could not lock the code tree\"")
    assert forward_reset < forward_lock < text.index('\nif ! sync_box_config; then')
    assert forward_lock < text.index("\nif ! install_requirements; then")

    rollback = text.split("\nrollback() {", 1)[1].split("\n}\n", 1)[0]
    reset = rollback.index('git reset --hard "$PREVIOUS_COMMIT"')
    lock = rollback.index("if ! lock_code_tree; then")
    assert reset < lock < rollback.index("install_requirements") < rollback.index("sync_box_config")
    assert "return 3" in rollback[lock:rollback.index("install_requirements")]


def test_deploy_writes_the_provenance_record_root_owned_and_readable():
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = text.split("write_deployed_sha() {", 1)[1].split("\n}\n", 1)[0]
    assert 'chown "$CODE_OWNER:$CODE_GROUP" "$tmp"' in body
    assert 'chmod 0644 "$tmp"' in body
    assert body.index('chmod 0644 "$tmp"') < body.index('mv -f "$tmp" "$DEPLOYED_SHA_FILE"')
    assert 'CODE_OWNER="${DEPLOY_CODE_OWNER:-root}"' in text
    assert "\numask 022\n" in text


def _run_sync_with_prune_unit(tmp_path: Path) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Drive the real sync_box_config with every unit it manages present."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("\nsync_box_config() (\n") + 1
    function = text[start:text.index("\n# rollback REASON", start)]
    repo = tmp_path / "repo"
    deploy_dir = repo / "deploy"
    systemd_dir = tmp_path / "systemd"
    fakebin = tmp_path / "bin"
    for directory in (deploy_dir, systemd_dir, tmp_path / "polkit", fakebin):
        directory.mkdir(parents=True)
    for unit in (
        "patched-dashboard.service", "patched-dashboard-prune-reports.service",
        "patched-maintenance-facts.service", "patched-maintenance-facts.timer",
    ):
        (deploy_dir / unit).write_text(f"new {unit}\n")
    (systemd_dir / "patched-dashboard-prune-reports.service").write_text("hand-installed old unit\n")
    events = tmp_path / "events"
    (fakebin / "systemctl").write_text(
        "#!/usr/bin/env bash\necho systemctl:$* >> \"$EVENTS\"\n"
        "[[ $1 == show ]] && echo loaded\nexit 0\n"
    )
    guard = deploy_dir / "verify-systemd-hardening-floor.sh"
    guard.write_text("#!/usr/bin/env bash\necho guard:$* >> \"$EVENTS\"\n")
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
        + "log() { echo \"$*\" >> \"$LOG\"; }\n" + function + "\nsync_box_config\n"
    )
    env = dict(os.environ, PATH=f"{fakebin}:/usr/bin:/bin", EVENTS=str(events), TMPDIR=str(tmp_path))
    result = subprocess.run(["bash", str(harness)], text=True, capture_output=True, env=env, timeout=30)
    return result, systemd_dir, events


def test_the_deploy_installs_the_prune_unit_and_scores_it(tmp_path):
    """The prune unit was hand-installed, so its move to the state dir would
    never have reached the box. The deploy now installs, drift-checks and
    hardening-scores it like the dashboard unit."""
    result, systemd_dir, events = _run_sync_with_prune_unit(tmp_path)
    assert result.returncode == 0, result.stderr
    installed = systemd_dir / "patched-dashboard-prune-reports.service"
    assert installed.read_text() == "new patched-dashboard-prune-reports.service\n"
    guard_calls = [line for line in events.read_text().splitlines() if line.startswith("guard:")]
    assert guard_calls and "patched-dashboard-prune-reports.service" in guard_calls[-1]


# ── .github/workflows/deploy.yml ───────────────────────────────────────────


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps() -> list[dict]:
    return _workflow()["jobs"]["deploy"]["steps"]


def _index(fragment: str) -> int:
    for index, step in enumerate(_steps()):
        if fragment.lower() in (step.get("name") or "").lower():
            return index
    raise AssertionError(f"no deploy step named like {fragment!r}")


def test_adopting_is_an_explicit_dispatch_input_that_defaults_off():
    workflow = _workflow()
    # PyYAML reads the bare key `on` as True.
    trigger = workflow.get("on", workflow.get(True))
    adopt = trigger["workflow_dispatch"]["inputs"]["adopt_code_tree"]
    assert adopt["type"] == "boolean"
    assert adopt["default"] is False


def test_the_guard_runs_from_the_runner_before_the_push_fires_the_hook():
    pre = _index("check the code tree before the box runs")
    assert _index("configure ssh key") < pre < _index("bare mirror")
    step = _steps()[pre]
    run = step["run"]
    assert "< deploy/code-tree-guard.sh" in run, "the runner's (GitHub's) copy, piped in"
    assert "/opt/patched-dashboard/deploy/code-tree-guard.sh" not in run, (
        "running the box's own copy would let a box-side edit switch the guard off"
    )
    assert 'bash -s -- ${mode}' in run
    assert "mode=adopt" in run and "mode=check" in run
    assert "ADOPT_CODE_TREE" in step["env"]


def test_the_guard_runs_again_before_root_installs_the_nginx_config():
    post = _index("check the code tree before root installs its nginx config")
    assert _index("reconcile box-side config") < post < _index("refresh nginx config")
    step = _steps()[post]
    run = step["run"]
    assert "< deploy/code-tree-guard.sh" in run
    assert 'args="adopt-finish ${EXPECTED_SHA}"' in run
    assert step["env"]["EXPECTED_SHA"] == "${{ github.sha }}"


def test_workflow_guard_steps_fail_the_job_on_a_guard_failure():
    for fragment in ("check the code tree before the box runs", "check the code tree before root installs"):
        run = _steps()[_index(fragment)]["run"]
        assert run.lstrip().startswith("set -euo pipefail"), fragment
        assert "|| true" not in run, fragment
