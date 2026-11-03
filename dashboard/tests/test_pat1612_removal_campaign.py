"""
PAT-1612 -- Removal campaign console surface: proxy routes for PAT-1598's
platform endpoints (create / list / get / dry-run / authorize / cancel) plus
the new tab's markup/wiring. Follows PAT-1607/PAT-1820's split: pure
derivations are covered in tests/js/console-removal-campaign.test.js (npm run
test:console); this file covers the FastAPI proxy layer for real (same
convention as test_pat1820_protected_software.py) and asserts the new
markup/script wiring structurally.

Run with: pytest tests/test_pat1612_removal_campaign.py -v
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
RC_JS = (ROOT / "static" / "js" / "console-removal-campaign.js").read_text(encoding="utf-8")

BEARER = {"Authorization": "Bearer test-key"}
TENANT = "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"
CAMPAIGN_ID = "22222222-2222-2222-2222-222222222222"
LIST_PATH = f"/admin/tenants/{TENANT}/removal-campaigns"
GET_PATH = f"/admin/tenants/{TENANT}/removal-campaigns/{CAMPAIGN_ID}"
DRY_RUN_PATH = f"{GET_PATH}/dry-run"
AUTHORIZE_PATH = f"{GET_PATH}/authorize"
CANCEL_PATH = f"{GET_PATH}/cancel"


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


def _sample_campaign(status="dry_run"):
    return {
        "id": CAMPAIGN_ID, "tenant_id": TENANT, "team_id": None,
        "bundle_id": "io.tailscale.ipn.macos", "name": "Tailscale", "platform": "macos",
        "policy_id": None, "status": status, "reason": "pilot removal",
        "created_by": "andy@patched.im", "created_at": "2026-09-10T09:14:00Z",
        "status_changed_at": "2026-09-10T09:14:00Z", "cancelled_by": None,
        "cancelled_reason": None, "cancelled_at": None,
    }


def _sample_detail(status="dry_run"):
    return {
        "campaign": _sample_campaign(status),
        "latest_dry_run": {
            "id": "dry-run-1", "campaign_id": CAMPAIGN_ID, "computed_at": "2026-09-12T09:14:00Z",
            "computed_by": "andy@patched.im", "device_count": 132, "version_spread": [],
            "devices": [], "evidence_basis": "identifier_match", "devices_without_app_inventory": 0,
            "artefacts": [], "artefact_basis": "none", "artefact_enumeration_complete": False,
            "residue": [], "protected_match": None, "excluded_device_count": 0,
            "inventory_watermark": "2026-09-12T09:00:00Z", "stale": False, "staleness_reasons": [],
        },
        "authorization": None,
        "delivered": False,
    }


# ── 1. GET routes -- exercised for real ──────────────────────────────────────

def test_proxy_removal_campaigns_list_happy_path(client, monkeypatch):
    fake = {"tenant_id": TENANT, "campaigns": [_sample_campaign()]}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, fake))

    r = client.get(LIST_PATH, headers=BEARER)

    assert r.status_code == 200
    assert r.json()["campaigns"][0]["name"] == "Tailscale"


def test_proxy_removal_campaign_get_happy_path(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, _sample_detail()))

    r = client.get(GET_PATH, headers=BEARER)

    assert r.status_code == 200
    body = r.json()
    assert body["campaign"]["id"] == CAMPAIGN_ID
    assert body["latest_dry_run"]["device_count"] == 132


def test_proxy_removal_campaign_list_upstream_error_passes_through_status(client, monkeypatch):
    resp = MagicMock(status_code=404, content=b"tenant not found")
    resp.json.side_effect = ValueError("not json")
    resp.text = "tenant not found"
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: resp)

    r = client.get(LIST_PATH, headers=BEARER)

    assert r.status_code == 404


# ── 2. POST create -- server-resolved created_by, protected-target refusal ──

def test_proxy_removal_campaign_create_injects_server_resolved_actor(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(201, _sample_campaign("draft"))

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(LIST_PATH, json={
        "name": "Tailscale", "platform": "macos", "reason": "pilot removal",
        "created_by": "someone-else@evil.example",
    }, headers=BEARER)

    assert r.status_code == 201
    assert captured["url"].endswith(f"/admin/tenants/{TENANT}/removal-campaigns")
    # Bearer auth resolves to "bearer-token" -- the client-supplied
    # created_by must be overwritten, not merely defaulted.
    assert captured["json"]["created_by"] == "bearer-token"
    assert captured["json"]["name"] == "Tailscale"


def test_proxy_removal_campaign_create_protected_target_refusal_passes_through(client, monkeypatch):
    # PAT-1598's create handler refuses a protected target with 409 and a
    # message naming the product and protection scope -- the proxy must not
    # swallow or rewrite that.
    body = "CrowdStrike Falcon Sensor (category: edr) is protected software per the shared baseline and can never be targeted for removal"
    resp = MagicMock(status_code=409, content=body.encode())
    resp.json.side_effect = ValueError("not json")
    resp.text = body
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: resp)

    r = client.post(LIST_PATH, json={"name": "Falcon Sensor", "platform": "any", "reason": "x"}, headers=BEARER)

    assert r.status_code == 409
    assert "protected software" in r.json()["body"]


# ── 3. POST dry-run -- server-resolved computed_by ───────────────────────────

def test_proxy_removal_campaign_dry_run_injects_server_resolved_actor(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(201, _sample_detail()["latest_dry_run"])

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(DRY_RUN_PATH, json={"computed_by": "someone-else@evil.example"}, headers=BEARER)

    assert r.status_code == 201
    assert captured["url"].endswith("/dry-run")
    assert captured["json"]["computed_by"] == "bearer-token"


def test_proxy_removal_campaign_dry_run_tolerates_empty_json_object(client, monkeypatch):
    # The console always sends body: '{}' for a re-run with no other fields
    # (see _rcRunDryRun in console.html) -- confirm that round-trips cleanly
    # and still gets computed_by stamped.
    captured = {}

    def fake_post(url, **kwargs):
        captured["json"] = kwargs.get("json")
        return _response(201, _sample_detail()["latest_dry_run"])

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(DRY_RUN_PATH, json={}, headers=BEARER)

    assert r.status_code == 201
    assert captured["json"]["computed_by"] == "bearer-token"


# ── 4. POST authorize -- the destructive-write confirmation gate ────────────

def test_proxy_removal_campaign_authorize_requires_confirm_header(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: _response(201, {}))

    r = client.post(AUTHORIZE_PATH, json={
        "authorized_by": "Sarah Voss", "authorization_clause": "MSA 7.3", "dry_run_id": "dry-run-1",
    }, headers=BEARER)

    assert r.status_code == 428


def test_proxy_removal_campaign_authorize_rejects_wrong_confirm_value(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, _sample_detail()))
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: _response(201, {}))

    r = client.post(AUTHORIZE_PATH, json={
        "authorized_by": "Sarah Voss", "authorization_clause": "MSA 7.3", "dry_run_id": "dry-run-1",
    }, headers={**BEARER, "X-Confirm-Resource": "wrong product"})

    assert r.status_code == 409


def test_proxy_removal_campaign_authorize_accepts_target_name_and_forwards_authorized_by_unchanged(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, _sample_detail()))

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(201, {
            "id": "auth-1", "campaign_id": CAMPAIGN_ID, "dry_run_id": "dry-run-1",
            "authorized_by": "Sarah Voss, IT Manager", "authorization_clause": "MSA clause 7.3",
            "policy_id": None, "policy_snapshot": {}, "authorized_at": "2026-09-17T00:00:00Z",
        })

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(AUTHORIZE_PATH, json={
        "authorized_by": "Sarah Voss, IT Manager", "authorization_clause": "MSA clause 7.3",
        "dry_run_id": "dry-run-1",
    }, headers={**BEARER, "X-Confirm-Resource": "Tailscale"})

    assert r.status_code == 201
    assert captured["url"].endswith("/authorize")
    # authorized_by is free text naming the CUSTOMER's authorising contact --
    # unlike created_by/computed_by/cancelled_by, the proxy must forward it
    # unchanged, never overwrite it with the logged-in operator's identity.
    assert captured["json"]["authorized_by"] == "Sarah Voss, IT Manager"


def test_proxy_removal_campaign_authorize_accepts_campaign_id_as_confirm_value(client, monkeypatch):
    # _resolve_confirm_resource always accepts the resource's own id, same as
    # every other _CONFIRM_RULES kind.
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, _sample_detail()))
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: _response(201, {}))

    r = client.post(AUTHORIZE_PATH, json={
        "authorized_by": "Sarah Voss", "authorization_clause": "MSA 7.3", "dry_run_id": "dry-run-1",
    }, headers={**BEARER, "X-Confirm-Resource": CAMPAIGN_ID})

    assert r.status_code == 201


def test_proxy_removal_campaign_authorize_upstream_stale_refusal_passes_through(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, _sample_detail()))
    body = "dry run is stale, re-run it before authorising: inventory has been uploaded since the dry run was computed"
    resp = MagicMock(status_code=409, content=body.encode())
    resp.json.side_effect = ValueError("not json")
    resp.text = body
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: resp)

    r = client.post(AUTHORIZE_PATH, json={
        "authorized_by": "Sarah Voss", "authorization_clause": "MSA 7.3", "dry_run_id": "dry-run-1",
    }, headers={**BEARER, "X-Confirm-Resource": "Tailscale"})

    assert r.status_code == 409
    assert "stale" in r.json()["body"]


# ── 5. POST cancel -- destructive-logged, server-resolved cancelled_by, no
#      typed-confirmation bar (per the brief's split from authorize) ────────

def test_proxy_removal_campaign_cancel_injects_server_resolved_actor_no_confirm_header_needed(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(200, _sample_campaign("cancelled"))

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    r = client.post(CANCEL_PATH, json={"reason": "no longer needed", "cancelled_by": "someone-else@evil.example"},
                     headers=BEARER)

    assert r.status_code == 200
    assert captured["url"].endswith("/cancel")
    assert captured["json"]["cancelled_by"] == "bearer-token"
    assert captured["json"]["reason"] == "no longer needed"


# ── 6. RBAC -- writes are owner-only by default, reads are not ──────────────

def test_unauthenticated_requests_are_rejected(client):
    assert client.get(LIST_PATH).status_code == 401
    assert client.get(GET_PATH).status_code == 401
    assert client.post(LIST_PATH, json={}).status_code == 401
    assert client.post(DRY_RUN_PATH, json={}).status_code == 401
    assert client.post(AUTHORIZE_PATH, json={}).status_code == 401
    assert client.post(CANCEL_PATH, json={}).status_code == 401


@pytest.mark.parametrize(("method", "path"), [
    ("POST", LIST_PATH),
    ("POST", DRY_RUN_PATH),
    ("POST", AUTHORIZE_PATH),
    ("POST", CANCEL_PATH),
])
def test_consultant_cannot_write_removal_campaigns(client, monkeypatch, method, path):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))

    r = client.request(method, path, json={}, headers=_cookie("consultant@patched.im"))

    assert r.status_code == 403


def test_consultant_can_read_removal_campaigns(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k:
        _response(200, {"tenant_id": TENANT, "campaigns": [_sample_campaign()]}))

    r = client.get(LIST_PATH, headers=_cookie("consultant@patched.im"))

    assert r.status_code == 200


# ── 7. Markup -- the tab, nav entry and script tag exist ────────────────────

def test_removal_campaigns_tab_panel_exists():
    assert 'id="tab-removal-campaigns"' in HTML


def test_removal_campaigns_subnav_link_exists():
    assert 'data-tab="removal-campaigns"' in HTML
    assert "tenantTab('removal-campaigns')" in HTML


def test_removal_campaigns_script_included():
    assert '/static/js/console-removal-campaign.js?v={{ console_build_id }}"' in HTML


def test_removal_campaigns_tab_registered_in_tenant_tabs_and_workload():
    assert "'protected-software', 'removal-campaigns']" in HTML


def test_removal_campaigns_activation_wired():
    assert "if (tab === 'removal-campaigns')   _rcActivate();" in HTML


def test_removal_campaigns_states_dry_run_banner_present():
    assert "Nothing has been removed, and nothing will be until someone authorises it below." in HTML


def test_removal_campaigns_never_claims_removal_of_user_data():
    # Hard constraint: absence requires authority / evidence before actuation.
    # The residue concept (things left behind) must never be rendered as
    # something the platform removed.
    start = HTML.index('id="tab-removal-campaigns"')
    end = HTML.index('id="tab-cve-findings"') if 'id="tab-cve-findings"' in HTML else len(HTML)
    markup = HTML[start:end]
    assert "What will be left alone" in markup
    assert "What will be deleted" in markup


# ── 8. Structural gates -- authorize cannot be submitted without both fields,
#      even before the server is asked ───────────────────────────────────────

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


def test_authorize_button_starts_disabled_and_is_synced_from_both_fields():
    assert 'id="rc-btn-authorize" class="lc-btn-danger" disabled' in HTML
    assert 'id="rc-auth-by"' in HTML and "_rcSyncAuthorizeButton()" in HTML
    assert 'id="rc-auth-clause"' in HTML

    fn = _extract_fn(HTML, "_rcSyncAuthorizeButton")
    assert "authorizeReady" in fn
    assert "_rcAuthorizeBlockReason" in fn


def test_authorize_uses_danger_confirm_with_typed_product_name():
    fn = _extract_fn(HTML, "_rcAuthorize")
    assert "dangerConfirm" in fn
    assert "confirmWord: label" in fn
    assert "X-Confirm-Resource" in fn


def test_cancel_requires_a_reason_via_danger_confirm():
    fn = _extract_fn(HTML, "_rcCancelCampaign")
    assert "reason:" in fn
    assert "required: true" in fn


def test_create_campaign_surfaces_protected_refusal_message_not_a_bare_error():
    fn = _extract_fn(HTML, "_rcCreateCampaign")
    assert "adminErrorText(err)" in fn


# ── 9. Pure module wiring ────────────────────────────────────────────────────

def test_removal_campaign_js_exports_match_what_console_html_calls():
    for fn_name in ("platformLabel", "statusLabel", "evidenceLabel", "artefactBasisLabel",
                     "targetLabel", "createPayload", "createPayloadError", "cancelPayload",
                     "authorizePayload", "authorizeReady", "dryRunBlockReason", "staleReasons",
                     "artefactRows", "residueRows", "exclusion", "devicesWithoutInventoryNote",
                     "policyLabel", "deviceCounts", "sortCampaigns", "cancellable",
                     "dryRunnable", "authorizable"):
        assert "function " + fn_name + "(" in RC_JS
        assert fn_name + ": " + fn_name in RC_JS


def test_removal_campaign_js_has_no_deferred_vs_failed_device_state():
    # The platform's dry-run devices[] carries no per-device execution
    # outcome (no agent-facing delivery path exists yet -- see the module's
    # own header comment on why). This asserts no code actually reads or
    # renders a fabricated per-device deferred/failed field; it does not
    # forbid the word appearing in an explanatory comment.
    assert "d.deferred" not in RC_JS
    assert "d.failed" not in RC_JS
    assert ".execution_status" not in RC_JS
    assert "'deferred'" not in RC_JS
    assert "'failed'" not in RC_JS


# ── 10. CONSOLE_BUILD_ID bump ─────────────────────────────────────────────────

def test_console_build_id_bumped_for_pat1612():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
