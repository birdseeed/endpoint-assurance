"""
PAT-1554 — Agent health and coverage assurance telemetry (the "N devices never
reported inventory" gap).

Confirmed backend state (no Go/backend change needed):
  GET /admin/tenants/{tenantID}/enrolled-devices already returns, per device:
  device_id, hostname, serial, os, enrolled_at, last_seen (nullable), status
  ("active"|"revoked"), revoked_at. "Enrolled" means a tenant_credentials row
  exists for that device, including one that has never submitted inventory
  (last_seen is then null). The dashboard already proxies it at
  proxy_tenant_enrolled_devices (main.py).

The gap: GET /admin/tenants/{id}/devices only ever returns devices that have
submitted inventory at least once, so an enrolled-but-never-reported device
was invisible everywhere in the console — the Tenant Overview health score,
its issue list, and the Device Health tab all only ever saw /devices.

This ticket:
  1. _ov2Load also fetches enrolled-devices and cross-references it against
     /devices (by device_id vs id) to derive `neverReported`.
  2. `totalDevices`, the health score, and the ranked issue list all account
     for neverReported, without touching the existing active/stale/silent
     bucketing for devices that DO report.
  3. _dhActivate (Device Health tab) also fetches enrolled-devices and appends
     a synthetic row (hostname, serial, enrolled_at, state 'missing') for each
     enrolled-but-never-reported device, so it's visible in the table, not
     just counted.

Console.html ships one hash-routed SPA with no JS test runner (see AGENTS.md),
so — same convention as test_pat1067_agent_health_console.py — the
client-side pieces are asserted structurally (function source extraction),
not executed; the proxy route is exercised for real via TestClient.

Run with: pytest tests/test_pat1554_coverage_gap.py -v
"""

import json
import os
import re
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


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


# ── 1. Proxy route — unchanged, but exercised for real (no prior coverage) ──

def _sample_enrolled_devices():
    return {
        "tenant_id": "024c7257-bd3b-550a-81da-3212c6ff3a42",
        "total": 3,
        "devices": [
            {
                "device_id": "dev-reported",
                "hostname": "alpha-mac",
                "serial": "SN-A",
                "os": "macOS",
                "enrolled_at": "2026-08-01T00:00:00Z",
                "last_seen": "2026-09-10T00:00:00Z",
                "status": "active",
                "revoked_at": None,
            },
            {
                "device_id": "dev-never-reported",
                "hostname": "beta-win",
                "serial": "SN-B",
                "os": "Windows",
                "enrolled_at": "2026-08-15T00:00:00Z",
                "last_seen": None,
                "status": "active",
                "revoked_at": None,
            },
            {
                "device_id": "dev-revoked",
                "hostname": "gamma-mac",
                "serial": "SN-C",
                "os": "macOS",
                "enrolled_at": "2026-07-01T00:00:00Z",
                "last_seen": None,
                "status": "revoked",
                "revoked_at": "2026-08-20T00:00:00Z",
            },
        ],
    }


def test_proxy_enrolled_devices_happy_path(client):
    fake_response = _sample_enrolled_devices()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_response
    mock_resp.content = json.dumps(fake_response).encode()
    mock_resp.headers = {"content-type": "application/json"}

    with patch.object(dashboard.http, "get", return_value=mock_resp) as mock_get:
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/enrolled-devices",
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert body["devices"][1]["status"] == "active"
    assert body["devices"][1]["last_seen"] is None
    called_urls = [c.args[0] for c in mock_get.call_args_list if c.args]
    assert any("024c7257-bd3b-550a-81da-3212c6ff3a42" in u and "enrolled-devices" in u for u in called_urls), called_urls


def test_proxy_enrolled_devices_upstream_error(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.content = b"bad gateway"
    mock_resp.text = "bad gateway"
    mock_resp.json.side_effect = ValueError("not json")
    mock_resp.headers = {"content-type": "text/plain"}

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/enrolled-devices",
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code >= 400


# ── 2. _ov2Load: fetches enrolled-devices alongside the existing promises ──

def test_ov2_load_fetches_enrolled_devices():
    fn = _extract_fn(HTML, "_ov2Load")
    assert "/enrolled-devices" in fn
    assert re.search(r"Promise\.all\(\[pAtt,\s*pDev,\s*pApps,\s*pCert,\s*pEnr\]\)", fn)
    # Same failure-tracking pattern as the other four promises (PAT-1809):
    # a failed fetch records itself in _ov2Failed rather than degrading
    # silently to the same null a genuinely-empty success would produce.
    assert re.search(r"pEnr\s*=\s*adminFetch\([^)]*enrolled-devices[^)]*\)\.catch\(_ov2Catch\('enrolled-devices'\)\)", fn)


def test_ov2_load_cross_references_by_id_vs_device_id():
    """/devices entries key off `id`; enrolled-devices entries key off
    `device_id` — same UUID, different field name. Devices already reported
    (matched by that key, with a real last_seen) must not be double-counted;
    revoked devices must never count as missing."""
    fn = _extract_fn(HTML, "_ov2Load")
    assert "e.device_id" in fn
    assert "_seenDeviceIds" in fn
    assert "e.status === 'revoked'" in fn or "e.status !== 'active'" in fn


def test_ov2_load_never_reported_definition():
    """status active + not matched in /devices -> counts as neverReported.

    Deliberately NOT `!reported || !e.last_seen`: enrolled-devices and
    /devices are two separate queries that could disagree on a null
    last_seen for a device that genuinely is in /devices (code review
    finding, 2026-09-11) -- testing e.last_seen once reported is already
    true would double-count that device into both the devs-loop
    contribution to totalDevices and neverReported.
    """
    fn = _extract_fn(HTML, "_ov2Load")
    m = re.search(r"if \(!reported\) neverReported\+\+;", fn)
    assert m, fn
    assert "!reported || !e.last_seen" not in fn


def test_ov2_load_reported_device_never_double_counted_regardless_of_its_own_last_seen():
    """A device present in /devices (reported=true) must never increment
    neverReported, even if enrolled-devices independently reports a null
    last_seen for that same device_id -- it is already counted via the
    devs loop (mac/win) and already has its own active/stale/silent bucket."""
    fn = _extract_fn(HTML, "_ov2Load")
    # The predicate must short-circuit on `reported` alone with no OR clause
    # that could re-add a device that already matched.
    idx = fn.index("var reported = e.device_id")
    predicate_region = fn[idx: idx + 200]
    assert "if (!reported) neverReported++;" in predicate_region


def test_ov2_load_total_devices_includes_never_reported():
    fn = _extract_fn(HTML, "_ov2Load")
    assert re.search(r"totalDevices\s*=\s*\(\(mac \+ win\)\s*\|\|\s*t\.device_count\s*\|\|\s*0\)\s*\+\s*neverReported;", fn)


def test_ov2_load_issue_list_includes_never_reported_at_least_as_severe_as_silent():
    fn = _extract_fn(HTML, "_ov2Load")
    assert "devices enrolled but have never reported inventory" in fn
    never_idx = fn.index("neverReported > 0")
    silent_idx = fn.index("if (silent > 0)")
    # Ranked at or ahead of silent within the same severity tier.
    assert never_idx < silent_idx
    never_line = fn[never_idx:fn.index("\n", never_idx)]
    assert "sev:'crit'" in never_line


def test_ov2_load_score_deduction_comparable_to_silent_and_not_a_noop():
    fn = _extract_fn(HTML, "_ov2Load")
    silent_weight = re.search(r"\(silent / totalDevices\) \* (\d+)\)", fn)
    never_weight = re.search(r"\(neverReported / totalDevices\) \* (\d+)\)", fn)
    assert silent_weight and never_weight
    sw, nw = int(silent_weight.group(1)), int(never_weight.group(1))
    assert nw > 0
    # Comparable weight to silent (both represent "no evidence of assurance") —
    # not wildly larger or smaller.
    assert sw / 2 <= nw <= sw * 2


def test_ov2_load_atrisk_includes_never_reported():
    fn = _extract_fn(HTML, "_ov2Load")
    assert re.search(r"var atRisk = silent \+ neverReported \+ crits \+ expired \+ vulnerable;", fn)


# ── 3. _dhActivate: Device Health tab renders synthetic missing rows ────────

def test_dh_activate_fetches_enrolled_devices():
    fn = _extract_fn(HTML, "_dhActivate")
    assert "/enrolled-devices" in fn
    assert "Promise.all([pDevices, pEnrolled])" in fn


def test_dh_activate_builds_synthetic_row_for_active_unreported_device():
    fn = _extract_fn(HTML, "_dhActivate")
    assert "e.status !== 'active'" in fn
    assert "_neverReported: true" in fn
    assert "last_seen: null" in fn
    assert "enrolled_at: e.enrolled_at" in fn


def test_dh_activate_skips_already_reported_device_no_double_count():
    fn = _extract_fn(HTML, "_dhActivate")
    assert "if (e.device_id && seenIds[e.device_id]) return;" in fn


def test_dh_health_state_classifies_null_last_seen_as_missing():
    """_dhHealthState already returns 'missing' for a falsy last_seen before
    ever falling back to the freshness bucket — this is what makes a
    synthetic row (last_seen: null) classify correctly with no further
    change needed to the shared state-classification helper."""
    fn = _extract_fn(HTML, "_dhHealthState")
    assert "if (!d.last_seen) return 'missing';" in fn


def test_dh_render_shows_enrolled_at_for_never_reported_row_not_last_seen():
    fn = _extract_fn(HTML, "_dhRender")
    assert "d._neverReported && d.enrolled_at" in fn
    assert "'Enrolled ' + _fmtTs(d.enrolled_at)" in fn


# ── 4. CONSOLE_BUILD_ID bump (mandatory for any console.html change) ───────

def test_console_build_id_bumped_for_pat1554():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
