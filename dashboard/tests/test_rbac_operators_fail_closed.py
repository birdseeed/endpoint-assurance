"""An absent operator allow-list must never grant session owner privileges."""
import ast
import os
from pathlib import Path
import sys
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")
import main as dashboard
import shared


def _load_operators(monkeypatch, raw):
    # Evaluate the actual import-time declaration without reloading main (which
    # would recreate routes and other unrelated module state).
    if raw is None:
        monkeypatch.delenv("DASHBOARD_OPERATORS", raising=False)
    else:
        monkeypatch.setenv("DASHBOARD_OPERATORS", raw)
    tree = ast.parse(Path(dashboard.__file__).read_text())
    declaration = next(node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "DASHBOARD_OPERATORS"
                               for t in node.targets))
    namespace = {"os": os}
    exec(compile(ast.Module(body=[declaration], type_ignores=[]), dashboard.__file__, "exec"), namespace)
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", namespace["DASHBOARD_OPERATORS"])


def _cookie(email):
    token = dashboard._session_encode(email, int(time.time()) + 3600)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    with TestClient(dashboard.app) as client:
        yield client


@pytest.mark.parametrize("raw", [None, "", " \t ", ",,,", " , , \t,"])
def test_missing_operator_list_denies_owner_routes_without_upstream(client, monkeypatch, raw):
    _load_operators(monkeypatch, raw)
    upstream = MagicMock(side_effect=AssertionError("denied caller reached upstream"))
    monkeypatch.setattr(dashboard.http, "request", upstream)
    before = dashboard._billing_rates()
    headers = _cookie("anyone@example.com")
    assert client.patch("/admin/billing/rates", json={"annual_discount": 0.90}, headers=headers).status_code == 403
    purge = "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge"
    assert client.delete(purge, headers={**headers, "X-Confirm-Resource": "acme"}).status_code == 403
    assert client.get("/admin/logs", headers=headers).status_code == 403
    assert dashboard._role_for_email("anyone@example.com") == "consultant"
    assert dashboard._role_for_email(None) == "consultant"
    assert dashboard._billing_rates() == before
    upstream.assert_not_called()
    with dashboard.get_db() as db:
        rows = db.execute("SELECT role, path, outcome FROM admin_audit_log").fetchall()
    assert {(row["role"], row["path"], row["outcome"]) for row in rows} == {
        ("consultant", "/admin/billing/rates", "denied_rbac"),
        ("consultant", "/admin/logs", "denied_rbac"),
        ("consultant", purge, "denied_rbac"),
    }


def test_explicit_owner_is_case_insensitive_and_nonmatching_session_is_consultant(client, monkeypatch):
    _load_operators(monkeypatch, " , Owner@Example.COM, ")
    assert dashboard._role_for_email(" OWNER@example.com ") == "owner"
    assert dashboard._role_for_email("other@example.com") == "consultant"
    response = client.patch("/admin/billing/rates", json={"annual_discount": 0.90}, headers=_cookie("OWNER@example.com"))
    assert response.status_code == 200


def test_bearer_owner_survives_empty_operator_list(client, monkeypatch):
    _load_operators(monkeypatch, None)
    response = client.patch("/admin/billing/rates", json={"annual_discount": 0.90},
                            headers={"Authorization": "Bearer test-key"})
    assert response.status_code == 200
    upstream = MagicMock(status_code=200)
    upstream.json.return_value = {"jobs": []}
    monkeypatch.setattr(dashboard.http, "get", lambda *a, **kw: upstream)
    assert client.get("/admin/logs", headers={"Authorization": "Bearer test-key"}).status_code == 200


def test_empty_operator_list_keeps_ordinary_consultant_permissions(client, monkeypatch):
    _load_operators(monkeypatch, "")
    upstream = MagicMock(status_code=200, content=b"{}")
    upstream.json.return_value = {"tenants": []}
    monkeypatch.setattr(dashboard.http, "get", lambda *a, **kw: upstream)
    monkeypatch.setattr(dashboard.http, "post", lambda *a, **kw: upstream)
    headers = _cookie("consultant@example.com")
    assert client.get("/admin/tenants", headers=headers).status_code == 200
    assert client.post(
        "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/delivery-contacts",
        json={"email": "person@example.com"}, headers=headers,
    ).status_code == 200
