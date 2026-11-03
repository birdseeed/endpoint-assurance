"""
Test for PAT-931: /api/ops/firewall-apply must invoke `systemctl start
<unit>` directly, never `sudo systemctl start <unit>`.

The sudoers-based trigger (deploy/sudoers-patched-ops-fw, deleted) required a
setuid transition that forced patched-dashboard.service to run with
NoNewPrivileges=false. It's replaced by a polkit rule
(deploy/49-patched-ops-fw.rules) authorizing www-data to start exactly the
two firewall-apply units over D-Bus with no privilege transition at all —
this test locks in that plain `systemctl start` is what actually gets shelled
out, so `sudo` can't quietly creep back in.
"""
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


@pytest.mark.parametrize("edge,unit", [
    ("prod-01-edge", "hetzner-firewall-apply.service"),
    ("api-01-edge", "hetzner-firewall-apply-api.service"),
])
def test_firewall_apply_shells_plain_systemctl_no_sudo(client, monkeypatch, edge, unit):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    fake_result = MagicMock(returncode=0, stdout="", stderr="")
    fake_journal = MagicMock(returncode=0, stdout="ok")
    with patch("subprocess.run", side_effect=[fake_result, fake_journal]) as mock_run:
        r = client.post(
            "/api/ops/firewall-apply",
            json={"edge": edge},
            headers=_cookie("owner@patched.im"),
        )
    assert r.status_code == 200

    start_call_args = mock_run.call_args_list[0].args[0]
    assert start_call_args == ["systemctl", "start", unit]
    assert "sudo" not in start_call_args
