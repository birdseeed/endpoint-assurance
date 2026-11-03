"""
PAT-1820 -- Protected software console surface: proxy routes for PAT-1823's
platform endpoints (GET the effective set + changelog, POST add / override-
remove) plus the new tab's markup/wiring. Follows PAT-1606/PAT-1607's split:
pure derivations are covered in tests/js/console-protected-software.test.js
(npm run test:console); this file covers the FastAPI proxy layer for real
(same convention as test_pat1606_tenant_overview.py's device-lifecycle
coverage) and asserts the new markup/script wiring structurally.

Run with: pytest tests/test_pat1820_protected_software.py -v
"""

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
PS_JS = (ROOT / "static" / "js" / "console-protected-software.js").read_text(encoding="utf-8")

BEARER = {"Authorization": "Bearer test-key"}
LIST_PATH = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/protected-software"
CHANGES_PATH = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/protected-software/changes"
OVERRIDE_PATH = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/protected-software/42/override-remove"


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
    r = MagicMock(status_code=status_code, content=payload)
    r.json.return_value = body
    r.headers = {"content-type": "application/json"}
    return r


# ── 1. GET routes -- exercised for real ──────────────────────────────────────

def _sample_effective_set():
    return {
        "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
        "entries": [
            {"id": 1, "source": "baseline", "category": "edr", "vendor": "CrowdStrike",
             "product_name": "Falcon Sensor", "bundle_id": "com.crowdstrike.falcon",
             "team_id": None, "signer": None, "win_publisher": None, "win_product_code": None,
             "process_name": None, "reason": "Required by CE+", "added_by": "platform"},
            {"id": 2, "source": "tenant", "category": "customer_defined", "vendor": "Acme",
             "product_name": "Internal Agent", "bundle_id": None, "team_id": None, "signer": None,
             "win_publisher": None, "win_product_code": None, "process_name": "acme-agent.exe",
             "reason": "Custom EDR", "added_by": "andy@patched.im"},
        ],
    }


def test_proxy_protected_software_list_happy_path(client, monkeypatch):
    fake = _sample_effective_set()
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, fake))

    r = client.get(LIST_PATH, headers=BEARER)

    assert r.status_code == 200
    body = r.json()
    assert len(body["entries"]) == 2
    assert body["entries"][0]["source"] == "baseline"


def test_proxy_protected_software_changes_happy_path(client, monkeypatch):
    fake = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "changes": [
        {"id": 9, "entry_id": 1, "action": "added", "actor": "andy@patched.im",
         "detail": {"vendor": "Acme", "product_name": "Internal Agent"}, "changed_at": "2026-09-17T00:00:00Z"},
    ]}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, fake))

    r = client.get(CHANGES_PATH, headers=BEARER)

    assert r.status_code == 200
    assert r.json()["changes"][0]["action"] == "added"


def test_proxy_protected_software_list_upstream_error_passes_through_status(client, monkeypatch):
    resp = MagicMock(status_code=404, content=b"tenant not found")
    resp.json.side_effect = ValueError("not json")
    resp.text = "tenant not found"
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: resp)

    r = client.get(LIST_PATH, headers=BEARER)

    assert r.status_code == 404


# ── 2. POST routes -- actor is always server-resolved, never client-supplied ─

def test_proxy_protected_software_add_injects_server_resolved_actor(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(201, {"id": 3, "category": "edr", "vendor": "Acme", "product_name": "Agent"})

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(LIST_PATH, json={
        "category": "edr", "vendor": "Acme", "product_name": "Agent",
        "process_name": "agent.exe", "reason": "test", "added_by": "someone-else@evil.example",
    }, headers=BEARER)

    assert r.status_code == 201
    assert captured["url"].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/protected-software")
    # Bearer auth resolves to "bearer-token" -- the client-supplied added_by
    # must be overwritten, not merely defaulted.
    assert captured["json"]["added_by"] == "bearer-token"
    assert captured["json"]["category"] == "edr"


def test_proxy_protected_software_override_remove_injects_server_resolved_actor(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(201, {})

    fake_set = _sample_effective_set()
    fake_set["entries"].append({
        "id": 42, "source": "baseline", "category": "edr", "vendor": "Acme",
        "product_name": "Widget Guard", "bundle_id": None, "team_id": None, "signer": None,
        "win_publisher": None, "win_product_code": None, "process_name": None,
        "reason": "Required", "added_by": "platform",
    })
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, fake_set))
    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(OVERRIDE_PATH, json={"reason": "no longer required", "removed_by": "someone-else@evil.example"},
                     headers={**BEARER, "X-Confirm-Resource": "Acme Widget Guard"})

    assert r.status_code == 201
    assert captured["url"].endswith("/protected-software/42/override-remove")
    assert captured["json"]["removed_by"] == "bearer-token"
    assert captured["json"]["reason"] == "no longer required"


def test_proxy_protected_software_override_remove_requires_confirm_header(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: _response(201, {}))

    r = client.post(OVERRIDE_PATH, json={"reason": "no longer required"}, headers=BEARER)

    assert r.status_code == 428


def test_proxy_protected_software_override_remove_rejects_wrong_confirm_value(client, monkeypatch):
    fake_set = _sample_effective_set()
    fake_set["entries"].append({
        "id": 42, "source": "baseline", "category": "edr", "vendor": "Acme",
        "product_name": "Widget Guard", "bundle_id": None, "team_id": None, "signer": None,
        "win_publisher": None, "win_product_code": None, "process_name": None,
        "reason": "Required", "added_by": "platform",
    })
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, fake_set))
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: _response(201, {}))

    r = client.post(OVERRIDE_PATH, json={"reason": "no longer required"},
                     headers={**BEARER, "X-Confirm-Resource": "wrong name"})

    assert r.status_code == 409


# ── 3. RBAC -- writes are owner-only by default, reads are not ──────────────

def test_unauthenticated_requests_are_rejected(client):
    assert client.get(LIST_PATH).status_code == 401
    assert client.post(LIST_PATH, json={}).status_code == 401
    assert client.post(OVERRIDE_PATH, json={}).status_code == 401


@pytest.mark.parametrize(("method", "path"), [
    ("POST", LIST_PATH),
    ("POST", OVERRIDE_PATH),
])
def test_consultant_cannot_write_protected_software(client, monkeypatch, method, path):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))

    r = client.request(method, path, json={}, headers=_cookie("consultant@patched.im"))

    assert r.status_code == 403


def test_consultant_can_read_protected_software(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, _sample_effective_set()))

    r = client.get(LIST_PATH, headers=_cookie("consultant@patched.im"))

    assert r.status_code == 200


# ── 4. Markup -- the tab, nav entry and script tag exist ────────────────────

def test_protected_software_tab_panel_exists():
    assert 'id="tab-protected-software"' in HTML


def test_protected_software_subnav_link_exists():
    assert 'data-tab="protected-software"' in HTML
    assert "tenantTab('protected-software')" in HTML


def test_protected_software_script_included():
    assert '/static/js/console-protected-software.js?v={{ console_build_id }}"' in HTML


def test_protected_software_tab_registered_in_tenant_tabs_and_workload():
    assert "'software-catalogue', 'browser-extensions', 'protected-software'" in HTML


def test_protected_software_activation_wired():
    assert "if (tab === 'protected-software')  _psActivate();" in HTML


def _extract_fn(text, name):
    start = text.index("function " + name + "(")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError("unbalanced braces for " + name)


def test_protected_software_tab_labels_baseline_and_tenant_sections():
    start = HTML.index('id="tab-protected-software"')
    end = HTML.index('id="tab-cve-findings"') if 'id="tab-cve-findings"' in HTML else len(HTML)
    markup = HTML[start:end]
    assert "Baseline protections" in markup
    assert "Tenant additions" in markup


def test_only_baseline_rows_render_an_override_remove_action():
    render_fn = _extract_fn(HTML, "_psRender")
    baseline_block = render_fn[:render_fn.index("ps-tenant-tbody")]
    tenant_block = render_fn[render_fn.index("ps-tenant-tbody"):]
    assert "_psOverrideRemove" in baseline_block
    assert "_psOverrideRemove" not in tenant_block


def test_override_remove_requires_a_reason_via_danger_confirm():
    fn = _extract_fn(HTML, "_psOverrideRemove")
    assert "reason:" in fn
    assert "required: true" in fn


# ── 5. Pure module wiring ────────────────────────────────────────────────────

def test_protected_software_js_exports_match_what_console_html_calls():
    for fn_name in ("categoryLabel", "identityParts", "groupBySource", "addPayload",
                     "addPayloadError", "changeDetail", "changeActionLabel", "overrideRemovePayload"):
        assert "function " + fn_name + "(" in PS_JS
        assert fn_name + ": " + fn_name in PS_JS


# ── 6. CONSOLE_BUILD_ID bump ─────────────────────────────────────────────────

def test_console_build_id_bumped_for_pat1820():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
