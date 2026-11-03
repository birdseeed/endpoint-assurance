"""Central audit coverage for tenant app-policy mutations."""

import os
import sys
import time
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
import shared


BEARER = {"Authorization": "Bearer test-key"}
PUT_PATH = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/app-policies"
DELETE_PATH = PUT_PATH + "/policy-1"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    token = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


def _rows(path):
    with dashboard.get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT actor_email, role, method, path, outcome "
            "FROM admin_audit_log WHERE path=?", (path,)
        ).fetchall()]


def _audit_detail(path):
    with dashboard.get_db() as db:
        row = db.execute(
            "SELECT outcome, before_value, after_value FROM admin_audit_log WHERE path=?", (path,)
        ).fetchone()
    return dict(row)


def _response(status_code, body=b"{}"):
    response = MagicMock(status_code=status_code, content=body)
    response.json.return_value = {} if body else None
    return response


@pytest.mark.parametrize(("method", "path"), [("PUT", PUT_PATH), ("DELETE", DELETE_PATH)])
def test_app_policy_mutations_require_authentication_without_creating_an_audit_row(client, method, path):
    response = client.request(method, path, json={})

    assert response.status_code == 401
    assert _rows(path) == []


@pytest.mark.parametrize(("method", "path"), [("PUT", PUT_PATH), ("DELETE", DELETE_PATH)])
def test_consultant_app_policy_mutation_is_denied_once_by_central_rbac(client, monkeypatch, method, path):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))

    response = client.request(method, path, json={}, headers=_cookie("consultant@patched.im"))

    assert response.status_code == 403
    assert _rows(path) == [{
        "actor_email": "consultant@patched.im", "role": "consultant",
        "method": method, "path": path, "outcome": "denied_rbac",
    }]


def test_app_policy_put_success_has_one_terminal_audit_row(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "get", lambda *_args, **_kwargs: _response(200, b'{"policies":[]}'))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: _response(200))

    response = client.put(PUT_PATH, json={"name": "Example", "platform": "macos", "policy": "approved"}, headers=BEARER)

    assert response.status_code == 200
    assert _rows(PUT_PATH) == [{
        "actor_email": "bearer-token", "role": "owner", "method": "PUT",
        "path": PUT_PATH, "outcome": "allowed",
    }]
    before = json.loads(_audit_detail(PUT_PATH)["before_value"])
    after = json.loads(_audit_detail(PUT_PATH)["after_value"])
    assert before == {
        "prior_state": None, "requested_policy": "approved",
        "software": {"name": "Example", "platform": "macos"}, "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
    }
    assert after == {
        "requested_policy": "approved", "software": {"name": "Example", "platform": "macos"},
        "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "upstream_status": 200, "write_state": "applied",
    }


def test_app_policy_put_preserves_canonical_body_and_prior_record_in_audit(client, monkeypatch):
    captured = {}

    def get(_url, **_kwargs):
        response = _response(200)
        response.json.return_value = {"policies": [{
            "name": "Example", "platform": "macos", "policy": "approved", "notes": "accepted",
        }]}
        return response

    def put(_url, **kwargs):
        captured["body"] = kwargs["data"]
        return _response(201)

    monkeypatch.setattr(dashboard.http, "get", get)
    monkeypatch.setattr(dashboard.http, "put", put)
    response = client.put(PUT_PATH, content=b'{ "name" : "Example", "platform":"macos", "policy":"unapproved", "notes":"accepted" }', headers={**BEARER, "Content-Type": "application/json"})

    assert response.status_code == 201
    assert json.loads(captured["body"]) == {
        "name": "Example", "notes": "accepted", "platform": "macos", "policy": "unapproved",
    }
    assert json.loads(_audit_detail(PUT_PATH)["before_value"])["prior_state"]["notes"] == "accepted"


def test_app_policy_audit_does_not_match_a_stronger_identity_to_name_only_upsert(client, monkeypatch):
    def get(_url, **_kwargs):
        response = _response(200)
        response.json.return_value = {"policies": [{
            "team_id": "TEAM-A", "bundle_id": "com.example.app", "name": "Example",
            "platform": "macos", "policy": "unapproved",
        }]}
        return response

    monkeypatch.setattr(dashboard.http, "get", get)
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: _response(200))
    response = client.put(PUT_PATH, json={"name": "example", "platform": "macos", "policy": "approved"}, headers=BEARER)
    assert response.status_code == 200
    assert json.loads(_audit_detail(PUT_PATH)["before_value"])["prior_state"] is None


def test_app_policy_audit_matches_platform_canonical_winget_identity(client, monkeypatch):
    def get(_url, **_kwargs):
        response = _response(200)
        response.json.return_value = {"policies": [{
            "winget_id": "microsoft.visualstudiocode", "platform": "windows", "policy": "unapproved",
        }]}
        return response

    monkeypatch.setattr(dashboard.http, "get", get)
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: _response(200))
    response = client.put(PUT_PATH, json={
        "winget_id": " Microsoft.VisualStudioCode ", "platform": "windows", "policy": "approved",
    }, headers=BEARER)
    assert response.status_code == 200
    assert json.loads(_audit_detail(PUT_PATH)["before_value"])["prior_state"]["policy"] == "unapproved"


def test_app_policy_audit_name_matching_does_not_use_unicode_casefold(client, monkeypatch):
    def get(_url, **_kwargs):
        response = _response(200)
        response.json.return_value = {"policies": [{
            "name": "Straße", "platform": "macos", "policy": "unapproved",
        }]}
        return response

    monkeypatch.setattr(dashboard.http, "get", get)
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: _response(200))
    response = client.put(PUT_PATH, json={"name": "STRASSE", "platform": "macos", "policy": "approved"}, headers=BEARER)
    assert response.status_code == 200
    assert json.loads(_audit_detail(PUT_PATH)["before_value"])["prior_state"] is None


@pytest.mark.parametrize("body", [
    b'{"name":"Example","Name":"Other","platform":"macos","policy":"approved"}',
    b'{"name":"Example","name":"Other","platform":"macos","policy":"approved"}',
    b'{"name":"Example","platform":"macos","policy":"approved","unexpected":"x"}',
    b'{"name":"Example","platform":"linux","policy":"approved"}',
    b'{"name":"Example","platform":"macos","policy":"install"}',
    b'{"name":"Example","platform":"macos","policy":"approved"}' + b" " * 8200,
])
def test_app_policy_put_rejects_ambiguous_or_invalid_body_before_upstream(client, monkeypatch, body):
    monkeypatch.setattr(dashboard.http, "get", lambda *_args, **_kwargs: pytest.fail("prior GET called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    response = client.put(PUT_PATH, content=body, headers={**BEARER, "Content-Type": "application/json"})
    assert response.status_code in {400, 413}
    assert _audit_detail(PUT_PATH)["outcome"] == f"rejected_{response.status_code}"


def test_app_policy_put_accepts_platform_contract_nullable_fields_and_unmanaged(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(dashboard.http, "get", lambda *_args, **_kwargs: _response(200, b'{"policies":[]}'))

    def put(_url, **kwargs):
        captured["body"] = json.loads(kwargs["data"])
        return _response(200)

    monkeypatch.setattr(dashboard.http, "put", put)
    response = client.put(PUT_PATH, json={
        "team_id": None, "bundle_id": "com.example.app", "winget_id": None,
        "name": None, "platform": "macos", "policy": "unmanaged",
        "enforcement_tier": "report_deploy", "notes": "", "min_version": None,
    }, headers=BEARER)
    assert response.status_code == 200
    assert captured["body"]["policy"] == "unmanaged"
    assert captured["body"]["min_version"] is None


def test_app_policy_put_continues_when_prior_lookup_is_unavailable(client, monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise dashboard.requests.RequestException("lookup unavailable")

    monkeypatch.setattr(dashboard.http, "get", unavailable)
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: _response(200))
    response = client.put(PUT_PATH, json={"name": "Example", "platform": "macos", "policy": "approved"}, headers=BEARER)
    assert response.status_code == 200
    assert json.loads(_audit_detail(PUT_PATH)["before_value"])["prior_state"] == "unavailable"


def test_app_policy_upstream_rejection_keeps_requested_policy_in_audit(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "get", lambda *_args, **_kwargs: _response(503))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: _response(409))
    response = client.put(PUT_PATH, json={"name": "Example", "platform": "macos", "policy": "approved"}, headers=BEARER)
    assert response.status_code == 409
    detail = _audit_detail(PUT_PATH)
    assert detail["outcome"] == "rejected_409"
    assert json.loads(detail["before_value"])["prior_state"] == "unavailable"
    assert json.loads(detail["after_value"]) == {
        "requested_policy": "approved", "software": {"name": "Example", "platform": "macos"},
        "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "upstream_status": 409, "write_state": "rejected",
    }


def test_app_policy_delete_failure_has_one_terminal_audit_row(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "delete", lambda *_args, **_kwargs: _response(502))

    response = client.delete(DELETE_PATH, headers=BEARER)

    assert response.status_code == 502
    assert _rows(DELETE_PATH) == [{
        "actor_email": "bearer-token", "role": "owner", "method": "DELETE",
        "path": DELETE_PATH, "outcome": "rejected_502",
    }]
