"""PAT-1861 -- dashboard finding-disposition proxy and Findings UI wiring.

The browser's identity joins/payload shaping are exercised by
tests/js/console-findings.test.js. These tests exercise the FastAPI proxy with
its actual RBAC middleware and guard the screen-load/UI wiring.
"""

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
BEARER = {"Authorization": "Bearer test-key"}
TENANT = "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"
PATH = f"/admin/tenants/{TENANT}/finding-dispositions"
DEVICE = "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    token = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


def _response(status_code, body):
    payload = json.dumps(body).encode()
    response = MagicMock(status_code=status_code, content=payload)
    response.json.return_value = body
    response.headers = {"content-type": "application/json"}
    return response


@pytest.mark.parametrize(
    ("query", "expected_params"),
    [
        ("?finding_kind=cis", {"finding_kind": "cis"}),
        ("?finding_kind=cve", {"finding_kind": "cve"}),
        ("", {}),
    ],
)
def test_finding_disposition_list_forwards_tenant_and_optional_kind(
    client, monkeypatch, query, expected_params
):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        return _response(200, {"dispositions": [], "total": 0})

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    response = client.get(PATH + query, headers=BEARER)

    assert response.status_code == 200
    assert captured["url"].endswith(f"/admin/tenants/{TENANT}/finding-dispositions")
    assert captured["params"] == expected_params


def test_finding_disposition_create_preserves_each_upstream_identity_shape(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs["json"]
        return _response(201, {"disposition": kwargs["json"]})

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    body = {
        "finding_kind": "cis", "device_id": DEVICE, "rule_key": "cis.filevault",
        "status": "acknowledged", "recorded_by": "Jane Customer", "reason": "Ticket confirmed",
    }
    response = client.post(PATH, json=body, headers=BEARER)

    assert response.status_code == 201
    assert captured["url"].endswith(f"/admin/tenants/{TENANT}/finding-dispositions")
    assert captured["json"] == body

    cve_body = {
        "finding_kind": "cve", "cve_id": "CVE-2026-0001",
        "status": "risk_accepted", "recorded_by": "Jane Customer",
    }
    response = client.post(PATH, json=cve_body, headers=BEARER)

    assert response.status_code == 201
    assert captured["url"].endswith(f"/admin/tenants/{TENANT}/finding-dispositions")
    assert captured["json"] == cve_body


def test_finding_disposition_create_passes_upstream_validation_status_through(client, monkeypatch):
    upstream = MagicMock(status_code=400, content=b"status must be one of acknowledged, risk_accepted, closed")
    upstream.json.side_effect = ValueError("not JSON")
    upstream.text = "status must be one of acknowledged, risk_accepted, closed"
    upstream.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: upstream)

    response = client.post(PATH, json={"finding_kind": "cve", "cve_id": "CVE-2026-0001", "status": "bad"}, headers=BEARER)

    assert response.status_code == 400


def test_finding_disposition_proxy_rejects_invalid_local_json_object(client):
    response = client.post(PATH, content=b"[]", headers={**BEARER, "Content-Type": "application/json"})
    assert response.status_code == 400


def test_finding_disposition_writes_are_owner_only_but_reads_are_not(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard.http, "get", lambda *_args, **_kwargs: _response(200, {"dispositions": [], "total": 0}))

    assert client.get(PATH, headers=_cookie("consultant@patched.im")).status_code == 200
    assert client.post(PATH, json={}, headers=_cookie("consultant@patched.im")).status_code == 403


def test_findings_workspace_has_disposition_filters_badges_and_accessible_record_form():
    load_findings = HTML.split("function _loadFindingsView()", 1)[1].split(
        "function _fFetchDispositions", 1
    )[0]

    assert 'data-fcve-disposition="none"' in HTML
    assert 'data-fcis-disposition="none"' in HTML
    assert 'id="modal-finding-disposition"' in HTML
    assert 'aria-modal="true"' in HTML
    assert 'id="finding-disposition-recorded-by"' in HTML
    assert 'id="finding-disposition-reason"' in HTML
    assert load_findings.count("_fFetchDispositions(tenantId)") == 1
    assert "PF.dispositionForFinding(_fDispositionIndex, 'cve', f)" in HTML
    assert "PF.dispositionForFinding(_fDispositionIndex, 'cis', f)" in HTML
    assert "action.className = 'finding-expand-btn owner-only'" in HTML
    assert "requestId !== _fDispositionRequestId" in HTML
    assert "if (section !== 'findings' && _fDispositionTarget) _fDispositionClose()" in HTML
