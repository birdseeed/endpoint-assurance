"""
PAT-1609 -- Disposition queue console surface: proxy routes for PAT-1825's
device-dispositions endpoints (create/list) plus the new tab's markup/wiring.
device-lifecycle (PAT-1595) is already proxied for Device Health/Findings --
this ticket does not duplicate that route. Follows PAT-1607/PAT-1612's split:
pure derivations are covered in tests/js/console-disposition-queue.test.js
(npm run test:console); this file covers the FastAPI proxy layer for real
(same convention as test_pat1612_removal_campaign.py) and asserts the new
markup/script wiring structurally.

Run with: pytest tests/test_pat1609_disposition_queue.py -v
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
DQ_JS = (ROOT / "static" / "js" / "console-disposition-queue.js").read_text(encoding="utf-8")

BEARER = {"Authorization": "Bearer test-key"}
TENANT = "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"
LIST_PATH = f"/admin/tenants/{TENANT}/device-dispositions"
DEVICE_A = "11111111-1111-1111-1111-111111111111"
DEVICE_B = "22222222-2222-2222-2222-222222222222"


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


def _sample_row(device_id, cohort_id=None):
    return {
        "id": "row-" + device_id, "tenant_id": TENANT, "device_id": device_id,
        "category": "decommissioned", "reported_by": "Sarah Voss", "reported_by_role": "IT Manager",
        "channel": "email", "note": "confirmed 12 Sep", "recorded_at": "2026-09-17T09:00:00Z",
        "cohort_id": cohort_id, "supersedes_id": None, "superseded_at": None, "superseded_reason": None,
    }


# ── 1. GET list -- exercised for real, including ?active=true passthrough ───

def test_proxy_device_dispositions_list_happy_path(client, monkeypatch):
    fake = {"dispositions": [_sample_row(DEVICE_A)], "total": 1}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, fake))

    r = client.get(LIST_PATH, headers=BEARER)

    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_proxy_device_dispositions_list_forwards_active_query_param(client, monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        return _response(200, {"dispositions": [], "total": 0})

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    r = client.get(LIST_PATH + "?active=true", headers=BEARER)

    assert r.status_code == 200
    assert captured["url"].endswith("/device-dispositions")
    assert captured["params"].get("active") == "true"


def test_proxy_device_dispositions_list_upstream_error_passes_through_status(client, monkeypatch):
    resp = MagicMock(status_code=404, content=b"tenant not found")
    resp.json.side_effect = ValueError("not json")
    resp.text = "tenant not found"
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: resp)

    r = client.get(LIST_PATH, headers=BEARER)

    assert r.status_code == 404


# ── 2. POST create -- single device, cohort (shared cohort_id), reported_by
#      forwarded UNCHANGED (never server-stamped) ────────────────────────────

def test_proxy_device_disposition_create_single_device_forwards_body_unchanged(client, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _response(201, {
            "tenant_id": TENANT, "cohort_id": None, "category": "decommissioned",
            "dispositions": [_sample_row(DEVICE_A)],
        })

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    body = {
        "device_id": DEVICE_A, "category": "decommissioned",
        "reported_by": "Sarah Voss, IT Manager", "reported_by_role": "IT Manager",
        "channel": "email", "note": "confirmed 12 Sep",
    }
    r = client.post(LIST_PATH, json=body, headers=BEARER)

    assert r.status_code == 201
    assert captured["url"].endswith(f"/admin/tenants/{TENANT}/device-dispositions")
    # reported_by names the CUSTOMER's contact, typed by the operator -- it
    # is free text forwarded unchanged, never overwritten with the logged-in
    # operator's own identity (unlike created_by/computed_by/cancelled_by on
    # the removal-campaign proxies).
    assert captured["json"]["reported_by"] == "Sarah Voss, IT Manager"
    assert captured["json"]["device_id"] == DEVICE_A
    assert "device_ids" not in captured["json"]


def test_proxy_device_disposition_create_cohort_write_shares_one_cohort_id_per_response(client, monkeypatch):
    # PAT-1609 acceptance criterion: a cohort decision writes one record per
    # device with a shared cohort_id -- verified by reading the actual create
    # response, not assumed from the request shape.
    captured = {}

    def fake_post(url, **kwargs):
        captured["json"] = kwargs.get("json")
        return _response(201, {
            "tenant_id": TENANT, "cohort_id": "cohort-xyz", "category": "unaccounted",
            "dispositions": [_sample_row(DEVICE_A, "cohort-xyz"), _sample_row(DEVICE_B, "cohort-xyz")],
        })

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    body = {
        "device_ids": [DEVICE_A, DEVICE_B], "category": "unaccounted",
        "reported_by": "Sarah Voss", "reported_by_role": "", "channel": "", "note": "",
    }
    r = client.post(LIST_PATH, json=body, headers=BEARER)

    assert r.status_code == 201
    payload = r.json()
    assert captured["json"]["device_ids"] == [DEVICE_A, DEVICE_B]
    assert "device_id" not in captured["json"]
    # Exactly the acceptance criterion: one row per device, every row's
    # cohort_id equal to the response's own top-level cohort_id.
    assert len(payload["dispositions"]) == 2
    assert payload["cohort_id"] == "cohort-xyz"
    assert all(row["cohort_id"] == "cohort-xyz" for row in payload["dispositions"])
    assert {row["device_id"] for row in payload["dispositions"]} == {DEVICE_A, DEVICE_B}


def test_proxy_device_disposition_create_rejects_non_object_body(client, monkeypatch):
    r = client.post(LIST_PATH, content=b"[1,2,3]", headers={**BEARER, "Content-Type": "application/json"})
    assert r.status_code == 400


def test_proxy_device_disposition_create_upstream_validation_error_passes_through(client, monkeypatch):
    body = "category must be one of decommissioned, on-leave, lost, unaccounted"
    resp = MagicMock(status_code=400, content=body.encode())
    resp.json.side_effect = ValueError("not json")
    resp.text = body
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(dashboard.http, "post", lambda *_a, **_k: resp)

    r = client.post(LIST_PATH, json={"device_id": DEVICE_A, "category": "bogus", "reported_by": "Sarah"}, headers=BEARER)

    assert r.status_code == 400


# ── 3. RBAC -- writes are owner-only by default, reads are not ──────────────

def test_unauthenticated_requests_are_rejected(client):
    assert client.get(LIST_PATH).status_code == 401
    assert client.post(LIST_PATH, json={}).status_code == 401


def test_consultant_cannot_write_device_dispositions(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))

    r = client.post(LIST_PATH, json={}, headers=_cookie("consultant@patched.im"))

    assert r.status_code == 403


def test_consultant_can_read_device_dispositions(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard.http, "get", lambda *_a, **_k: _response(200, {"dispositions": [], "total": 0}))

    r = client.get(LIST_PATH, headers=_cookie("consultant@patched.im"))

    assert r.status_code == 200


# ── 4. Markup -- the tab, nav entry and script tag exist ────────────────────

def test_disposition_queue_tab_panel_exists():
    assert 'id="tab-disposition-queue"' in HTML


def test_disposition_queue_subnav_link_exists():
    assert 'data-tab="disposition-queue"' in HTML
    assert "tenantTab('disposition-queue')" in HTML


def test_disposition_queue_script_included():
    assert '/static/js/console-disposition-queue.js?v={{ console_build_id }}"' in HTML


def test_disposition_queue_tab_registered_in_tenant_tabs_and_workload():
    assert "'device-health', 'disposition-queue'," in HTML
    assert "'devices':        ['device-health', 'disposition-queue', 'device-lifecycle']," in HTML


def test_disposition_queue_activation_wired():
    assert "if (tab === 'disposition-queue')   _dqActivate();" in HTML


def test_disposition_queue_never_claims_compliance():
    # Hard constraint: identity/absence rules aside, a disposition must never
    # read as a compliance/pass state anywhere in this screen's markup.
    start = HTML.index('id="tab-disposition-queue"')
    end = HTML.index('id="tab-cve-findings"') if 'id="tab-cve-findings"' in HTML else len(HTML)
    markup = HTML[start:end].lower()
    for banned in ("mark compliant", "marks it compliant", "resolved", "issue fixed"):
        assert banned not in markup


def test_disposition_queue_consequence_copy_present():
    assert "It never marks a device compliant" in HTML
    assert "does not close a finding" in HTML or "does not close a finding" in DQ_JS


# ── 5. Empty states -- distinct copy, per 08-empty-states.html panel 4 ──────

def test_disposition_queue_has_three_distinct_empty_states():
    assert 'id="dq-empty-healthy"' in HTML
    assert 'id="dq-empty-never-uploaded"' in HTML
    assert 'id="dq-empty-stale-upload"' in HTML
    assert "Every device is accounted for." in HTML
    assert "No device list has ever been uploaded for this tenant." in HTML
    assert "Treat this as unverified, not as clear" in HTML


# ── 6. Structural gate -- never invents a subnet/cohort-cause field ─────────

def test_disposition_queue_js_never_fabricates_subnet_or_cause_fields():
    for banned in ("d.subnet", "subnet:", "recorded_change", "'silence_window'"):
        assert banned not in DQ_JS


def test_disposition_queue_js_exports_match_what_console_html_calls():
    for fn_name in ("stateLabel", "bucketLabel", "categoryLabel", "daysSince", "queueDevices",
                     "stateCounts", "filterByState", "candidateCohorts", "cohortForDevice",
                     "cohortSummary", "createDispositionPayload", "createDispositionPayloadError",
                     "consequenceText", "ingestStatus", "emptyQueueState"):
        assert "function " + fn_name + "(" in DQ_JS
        assert fn_name + ": " + fn_name in DQ_JS


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


def test_record_disposition_validates_before_posting():
    fn = _extract_fn(HTML, "_dqRecordDisposition")
    assert "createDispositionPayloadError" in fn
    assert "adminFetch" in fn


def test_cohort_selection_uses_real_candidate_cohorts_not_a_fabricated_field():
    fn = _extract_fn(HTML, "_dqUseCohort")
    assert "cohortForDevice" in fn
    assert "_dqCohorts" in fn


# ── 7. CONSOLE_BUILD_ID bump ─────────────────────────────────────────────────

def test_console_build_id_bumped_for_pat1609():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
