"""PAT-1796: preserve unknown Pro attachment status end to end.

The maintenance emitter runs in a hardened systemd sandbox.  Its old full
``pro status`` query could time out and was then indistinguishable from an
explicitly detached machine.  These tests drive the real shell collector with
shims, then exercise the dashboard's tri-state consumer separately.
"""

import json
import os
import stat
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


def _api_response(attached=True, contract_valid=True, *, errors=None, result="success"):
    return json.dumps({
        "result": result,
        "errors": [] if errors is None else errors,
        "data": {"attributes": {
            "is_attached": attached,
            "is_attached_and_contract_valid": contract_valid,
        }},
    })


def _fake_bin(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    scripts = {
        "id": "#!/bin/bash\nif [ \"$1\" = \"-u\" ]; then echo 0; exit 0; fi\nexit 1\n",
        "apt-cache": "#!/bin/bash\nexit 0\n",
        "systemctl": "#!/bin/bash\nexit 1\n",
        "timeout": (
            "#!/bin/bash\n"
            'if [ "${PRO_TIMEOUT_EXIT:-0}" != "0" ]; then exit "$PRO_TIMEOUT_EXIT"; fi\n'
            "shift\nexec \"$@\"\n"
        ),
        "pro": "#!/bin/bash\nprintf '%s\\n' \"${PRO_API_PAYLOAD:-}\"\n",
    }
    for name, body in scripts.items():
        path = bindir / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bindir


def _collect(tmp_path: Path, *, payload=None, timeout_exit=0):
    bindir = _fake_bin(tmp_path)
    out_file = tmp_path / "maintenance.json"
    env = dict(os.environ)
    # Keep command lookup deterministic: only the shims plus core system
    # utilities are available.
    env["PATH"] = f"{bindir}:/usr/bin:/bin"
    env["OUT_FILE"] = str(out_file)
    config_root = tmp_path / "etc"
    (config_root / "patched-dashboard").mkdir(parents=True)
    env["CONFIG_BACKUP_ROOT"] = str(config_root)
    env["PRO_TIMEOUT_EXIT"] = str(timeout_exit)
    if payload is not None:
        env["PRO_API_PAYLOAD"] = payload
    result = subprocess.run(
        ["bash", str(SCRIPT)], cwd=REPO, env=env, capture_output=True, text=True, timeout=15
    )
    assert result.returncode == 0, result.stderr
    return json.loads(out_file.read_text())


@pytest.mark.parametrize(
    "payload,timeout_exit,expected",
    [
        pytest.param(_api_response(), 0, True, id="attached_valid_contract"),
        pytest.param(_api_response(False, False), 0, False, id="genuinely_detached"),
        pytest.param(_api_response(), 124, None, id="timeout"),
        pytest.param(_api_response(), 1, None, id="nonzero"),
        pytest.param("not-json", 0, None, id="malformed_output"),
        pytest.param(_api_response(errors=[{"code": "failed"}]), 0, None, id="api_errors"),
        pytest.param(_api_response(True, False), 0, None, id="invalid_contract"),
    ],
)
def test_collector_preserves_pro_attachment_tristate(tmp_path, payload, timeout_exit, expected):
    facts = _collect(tmp_path, payload=payload, timeout_exit=timeout_exit)
    assert facts["pro_attached"] is expected
    assert facts["esm_updates"] == (0 if expected is True else None)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _facts(now: datetime, pro_attached_marker=...):
    facts = {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reboot_required": False,
        "security_updates": 0,
        "esm_updates": None,
        "timers": [],
        "third_party_pending": [],
    }
    if pro_attached_marker is not ...:
        facts["pro_attached"] = pro_attached_marker
    return facts


@pytest.mark.parametrize(
    "marker,expected_state,expected_reason",
    [
        pytest.param(True, "ok", "confirmed healthy", id="true"),
        pytest.param(False, "degraded", "Pro not attached", id="false"),
        pytest.param(None, "unconfigured", "Pro attachment status unavailable", id="null"),
        pytest.param(..., "unconfigured", "Pro attachment status unavailable", id="missing"),
        pytest.param("false", "unconfigured", "Pro attachment status unavailable", id="unreadable"),
    ],
)
def test_evaluator_preserves_pro_attachment_tristate(
    db, tmp_path, marker, expected_state, expected_reason
):
    now = datetime.now(timezone.utc)
    path = tmp_path / "maintenance.json"
    path.write_text(json.dumps(_facts(now, marker)))

    returned_reason = dashboard._check_one_maintenance_source(
        "maintenance_test", "local", str(path), now
    )
    if marker is False:
        assert returned_reason is not None
        assert returned_reason.startswith("Pro not attached")
    else:
        assert returned_reason is None
    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT state, reason FROM check_statuses WHERE name='maintenance_test'"
        ).fetchone()
    assert row["state"] == expected_state
    assert expected_reason in row["reason"]
    if marker is not False:
        assert "Pro not attached" not in row["reason"]
