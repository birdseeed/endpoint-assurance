"""
PAT-1830 -- Coverage console screen: the first dashboard surface to render
the FULL device-lifecycle response (PAT-1595's six-state classification and
three-bucket reconciliation), not just one derived slice of it like the
Disposition Queue (PAT-1609) or the tenant-overview coverage card (PAT-1606).
No new proxy route ships with this ticket -- GET
/admin/tenants/{id}/device-lifecycle already exists (PAT-1595/PAT-1607) and
is already exercised for real by test_pat1606_tenant_overview.py and
test_pat1609_disposition_queue.py; this file adds one more real exercise
covering the null-upload / empty-devices path those two don't, then follows
the same convention as those two: pure derivations are covered in
tests/js/console-device-lifecycle.test.js (npm run test:console); this file
asserts the new tab's markup/wiring structurally, plus the PAT-1607 footer
link this ticket completes.

Run with: pytest tests/test_pat1830_device_lifecycle.py -v
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")
DL_JS = (ROOT / "static" / "js" / "console-device-lifecycle.js").read_text(encoding="utf-8")

BEARER = {"Authorization": "Bearer test-key"}
TENANT = "024c7257-bd3b-550a-81da-3212c6ff3a42"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _mock_response(status_code, body):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = json.dumps(body).encode()
    resp.json.return_value = body
    resp.headers = {"content-type": "application/json"}
    return resp


def _full_lifecycle():
    return {
        "tenant_id": TENANT,
        "computed_at": "2026-09-17T12:00:00Z",
        "thresholds": {"quiet_days": 3, "stale_days": 14, "dormant_days": 45},
        "reconciliation": {
            "normal_count": 2, "coverage_gap_count": 1, "untracked_count": 1, "unmatchable_count": 0,
        },
        "devices": [
            {"bucket": "normal", "state": "reporting", "device_id": "d1", "hostname": "alpha", "last_seen": "2026-09-17T00:00:00Z"},
            {"bucket": "normal", "state": "stale", "device_id": "d2", "hostname": "beta", "last_seen": "2026-09-01T00:00:00Z"},
            {"bucket": "coverage_gap", "state": "never_seen", "external_id": "ext-1", "hostname": "gamma"},
            {"bucket": "untracked", "state": "reporting", "device_id": "d3", "hostname": "delta", "last_seen": "2026-09-16T00:00:00Z"},
        ],
        "upload": {"id": 1, "uploaded_at": "2026-09-01T00:00:00Z", "uploaded_by": "andy", "device_count": 3},
    }


# ── 1. Proxy route -- the null-upload / empty-devices path (the "never
#      uploaded" empty state this screen must show honestly) ────────────────

def test_proxy_device_lifecycle_no_upload_no_devices(client):
    fake = {
        "tenant_id": TENANT, "computed_at": "2026-09-17T12:00:00Z",
        "thresholds": {"quiet_days": 3, "stale_days": 14, "dormant_days": 45},
        "reconciliation": {"normal_count": 0, "coverage_gap_count": 0, "untracked_count": 0, "unmatchable_count": 0},
        "devices": [], "upload": None,
    }
    with patch.object(dashboard.http, "get", return_value=_mock_response(200, fake)):
        r = client.get(f"/admin/tenants/{TENANT}/device-lifecycle", headers=BEARER)
    assert r.status_code == 200
    body = r.json()
    assert body["upload"] is None
    assert body["devices"] == []


def test_proxy_device_lifecycle_full_shape_passes_through(client):
    fake = _full_lifecycle()
    with patch.object(dashboard.http, "get", return_value=_mock_response(200, fake)):
        r = client.get(f"/admin/tenants/{TENANT}/device-lifecycle", headers=BEARER)
    assert r.status_code == 200
    body = r.json()
    assert body["reconciliation"]["coverage_gap_count"] == 1
    assert len(body["devices"]) == 4
    assert body["upload"]["device_count"] == 3


# ── 2. Markup -- the tab, nav entry and script tag exist ────────────────────

def test_device_lifecycle_tab_panel_exists():
    assert 'id="tab-device-lifecycle"' in HTML


def test_device_lifecycle_subnav_link_exists():
    assert 'data-tab="device-lifecycle"' in HTML
    assert "tenantTab('device-lifecycle')" in HTML


def test_device_lifecycle_script_included():
    assert '/static/js/console-device-lifecycle.js?v={{ console_build_id }}"' in HTML


def test_device_lifecycle_tab_registered_in_tenant_tabs_and_workload():
    assert "'device-health', 'disposition-queue', 'device-lifecycle'," in HTML
    assert "'devices':        ['device-health', 'disposition-queue', 'device-lifecycle']," in HTML


def test_device_lifecycle_activation_wired():
    assert "if (tab === 'device-lifecycle')    _dlActivate();" in HTML


# ── 3. Screen renders every field the ticket names ───────────────────────────

def test_device_lifecycle_renders_bucket_cards_and_thresholds():
    start = HTML.index('id="tab-device-lifecycle"')
    end = HTML.index('id="tab-browser-extensions"')
    panel = HTML[start:end]
    assert 'id="dl-kpi-strip"' in panel
    assert 'id="dl-thresholds-text"' in panel
    assert 'id="dl-upload-text"' in panel
    assert 'id="dl-computed-at"' in panel
    assert 'id="dl-tbody"' in panel


def test_device_lifecycle_has_distinct_no_upload_empty_state():
    assert 'id="dl-empty-never-uploaded"' in HTML
    assert 'id="dl-empty-no-devices"' in HTML
    assert "No device list has ever been uploaded for this tenant." in HTML


def test_device_lifecycle_render_covers_computed_at_and_bucket_cards():
    fn = _extract_fn(HTML, "_dlRender")
    assert "lc.computed_at" in fn
    assert "DL.bucketCards" in fn
    assert "DL.thresholdSummary" in fn
    assert "DL.emptyState" in fn


# ── 4. PAT-1607 footer link wired to the new tab, known-gap note removed ────

def test_findings_footer_links_to_device_lifecycle_tab():
    fn = _extract_fn(HTML, "_fRenderFooter")
    # Built inside a single-quoted JS string, so the literal source escapes
    # the HTML attribute's own single-quoted JS-call argument.
    assert r"tenantTab(\'device-lifecycle\')" in fn


def test_findings_footer_known_gap_comment_removed():
    assert "deferred until that screen exists" not in HTML
    assert "there is no dedicated coverage" not in HTML
    assert 'No "See coverage" link yet' not in CSS


# ── 5. JS module exports match what console.html calls ──────────────────────

def test_device_lifecycle_js_exports_match_what_console_html_calls():
    for fn_name in ("stateLabel", "bucketLabel", "bucketCards", "thresholdSummary",
                     "stateOptionsForBucket", "filterDevices", "sortDevicesByLastSeen", "emptyState"):
        assert "function " + fn_name + "(" in DL_JS
        assert fn_name + ": " + fn_name in DL_JS


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


# ── 6. CONSOLE_BUILD_ID bump ─────────────────────────────────────────────────

def test_console_build_id_bumped_for_pat1830():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
