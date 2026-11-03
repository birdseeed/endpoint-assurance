"""Regression coverage for the PAT-1507 relocated dashboard database smoke path."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO = Path(__file__).resolve().parent.parent
SMOKE_RUNNER = REPO / "scripts" / "smoke" / "run_all.py"
SCHEDULER_SMOKE = REPO / "scripts" / "smoke" / "scheduler.py"
DEPLOY_SCRIPT = REPO / "scripts" / "deploy.sh"
CANONICAL_DB = "/var/lib/patched-dashboard/dashboard.db"


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _smoke_db_passed_to_every_module(monkeypatch, argv: list[str]) -> set[str]:
    runner = _load_module(SMOKE_RUNNER)
    seen: set[str] = set()

    def fake_run(_command, *, env):
        seen.add(env["SMOKE_DB"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as result:
        runner.main()
    assert result.value.code == 0
    return seen


def test_smoke_runner_uses_configured_dashboard_db_path(monkeypatch):
    configured = "/srv/patched-state/dashboard.db"
    monkeypatch.setenv("DASHBOARD_DB_PATH", configured)

    assert _smoke_db_passed_to_every_module(monkeypatch, ["run_all.py"]) == {configured}


def test_smoke_runner_cli_db_overrides_environment(monkeypatch):
    monkeypatch.setenv("DASHBOARD_DB_PATH", "/srv/patched-state/dashboard.db")
    explicit = "/tmp/deploy-smoke.db"

    assert _smoke_db_passed_to_every_module(
        monkeypatch, ["run_all.py", "--db", explicit]
    ) == {explicit}


def test_scheduler_smoke_prefers_runner_db_then_configured_db(monkeypatch):
    monkeypatch.setenv("DASHBOARD_DB_PATH", "/srv/patched-state/dashboard.db")
    monkeypatch.setenv("SMOKE_DB", "/tmp/runner-selected.db")
    assert _load_module(SCHEDULER_SMOKE).DB_PATH == "/tmp/runner-selected.db"

    monkeypatch.delenv("SMOKE_DB")
    assert _load_module(SCHEDULER_SMOKE).DB_PATH == "/srv/patched-state/dashboard.db"


def test_scheduler_smoke_has_the_relocated_production_fallback(monkeypatch):
    monkeypatch.delenv("SMOKE_DB", raising=False)
    monkeypatch.delenv("DASHBOARD_DB_PATH", raising=False)

    assert _load_module(SCHEDULER_SMOKE).DB_PATH == CANONICAL_DB


def test_deploy_passes_env_file_db_path_explicitly_without_sourcing_it():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert "read_environment_file_value DASHBOARD_DB_PATH" in text
    assert '"$SMOKE_RUNNER" --db "$DASHBOARD_DB_PATH"' in text
    assert 'source "$ENV_FILE"' not in text
    assert '. "$ENV_FILE"' not in text
