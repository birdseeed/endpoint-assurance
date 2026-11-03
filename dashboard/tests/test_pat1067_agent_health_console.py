"""
PAT-1067 — surface agent_health.degraded in the console (4/4 of PAT-1029).

The agents now emit agent_health.degraded (PAT-1065 macOS, PAT-1066 Windows)
and the server ingests + exposes it (PAT-1064) at
GET /admin/tenants/{tenant_id}/agent-health, grouped per device:

  { "tenant_id": "...", "total": 3,
    "devices": [ { "device_id": "...", "hostname": "...",
                   "degraded": [ { "kind": "...", "subject": "...",
                                   "reason": "...", "first_seen": "...",
                                   "last_seen": "...", "count": 1119,
                                   "ever_succeeded": false } ] } ] }

This ticket:
  1. adds the dashboard proxy route for that endpoint (mirrors
     proxy_browser_extensions);
  2. adds a fourth immediate-issue class to the device-detail issues banner
     (_ddRenderIssues), rendered in its own visual state (dd-issues-degraded)
     distinct from the existing alert/clear treatment, with ever_succeeded
     rendering as a different phrase ("Never worked" vs "Stopped working");
  3. rolls the signal up per-tenant (build_tenant_agent_health_stats, fed
     into /api/home/triage) and into _homeTenantScore, so a tenant whose
     agents are quietly broken isn't filtered out of "Tenants needing
     attention" (the exact PAT-1019 regression shape).

Console.html ships one hash-routed SPA with no JS test runner (see AGENTS.md),
so — same convention as test_pat1006/test_pat956 — the client-side pieces are
asserted structurally (function source extraction, rendered-HTML presence),
not executed; the pure Python helpers and the proxy route are exercised for
real via TestClient.

Run with: pytest tests/test_pat1067_agent_health_console.py -v
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
CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")


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


@pytest.fixture
def console_html(client):
    r = client.get("/console")
    assert r.status_code == 200
    return r.text


# ── 1. Proxy route ───────────────────────────────────────────────────────────

def _sample_agent_health():
    return {
        "tenant_id": "024c7257-bd3b-550a-81da-3212c6ff3a42",
        "total": 1,
        "devices": [
            {
                "device_id": "dev-1",
                "hostname": "alpha-mac",
                "degraded": [
                    {
                        "kind": "capability_missing",
                        "subject": "extension_blocklist",
                        "reason": "lib_not_installed",
                        "first_seen": "2026-07-01T00:00:00Z",
                        "last_seen": "2026-07-29T00:00:00Z",
                        "count": 1119,
                        "ever_succeeded": False,
                    },
                    {
                        "kind": "sync_never_succeeded",
                        "subject": "catalogue",
                        "reason": "fetch_failed",
                        "first_seen": "2026-07-20T00:00:00Z",
                        "last_seen": "2026-07-29T00:00:00Z",
                        "count": 4,
                        "ever_succeeded": True,
                    },
                ],
            }
        ],
    }


def test_proxy_agent_health_happy_path(client):
    fake_response = _sample_agent_health()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_response
    mock_resp.content = json.dumps(fake_response).encode()
    mock_resp.headers = {"content-type": "application/json"}

    with patch.object(dashboard.http, "get", return_value=mock_resp) as mock_get:
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/agent-health",
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["devices"][0]["degraded"][0]["kind"] == "capability_missing"
    # Same call-args-list discipline as test_enforcement_audit_tab.py: a
    # background scheduler thread shares this globally-patched http.get, so
    # don't trust call_args[-1] alone.
    called_urls = [c.args[0] for c in mock_get.call_args_list if c.args]
    assert any("024c7257-bd3b-550a-81da-3212c6ff3a42" in u and "agent-health" in u for u in called_urls), called_urls


def test_proxy_agent_health_upstream_error(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.content = b"bad gateway"
    mock_resp.text = "bad gateway"
    mock_resp.json.side_effect = ValueError("not json")
    mock_resp.headers = {"content-type": "text/plain"}

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/agent-health",
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code >= 400


def test_agent_health_proxy_route_referenced_in_console(console_html):
    assert "/admin/tenants/' + encodeURIComponent(tenantId) + '/agent-health" in console_html


# ── 2. build_tenant_agent_health_stats — pure server-side rollup ───────────

def _sample_ah_by_tenant():
    return {
        "t1": {
            "devices": [
                {"device_id": "d1", "hostname": "alpha-mac", "degraded": [
                    {"kind": "capability_missing", "subject": "extension_blocklist",
                     "reason": "lib_not_installed", "ever_succeeded": False, "count": 3},
                ]},
                {"device_id": "d2", "hostname": "beta-win", "degraded": []},
                {"device_id": "d3", "hostname": "gamma-mac", "degraded": [
                    {"kind": "sync_never_succeeded", "subject": "catalogue",
                     "reason": "fetch_failed", "ever_succeeded": True, "count": 1},
                ]},
            ],
        },
        "t2": {
            "devices": [
                {"device_id": "d4", "hostname": "delta-win", "degraded": []},
            ],
        },
    }


def test_tenant_agent_health_stats_counts_devices_not_entries():
    stats = dashboard.build_tenant_agent_health_stats(_sample_ah_by_tenant())
    # t1: d1 and d3 each have >=1 degraded entry -> 2 devices (not 2 entries
    # summed differently, and d2's empty list must not count).
    assert stats["t1"] == {"devices_degraded": 2}
    assert stats["t2"] == {"devices_degraded": 0}


def test_tenant_agent_health_stats_omits_tenants_without_device_data():
    ah = {"t1": {"devices": []}, "t2": {"total": 3}}  # t2 has no devices list
    stats = dashboard.build_tenant_agent_health_stats(ah)
    assert "t1" in stats
    assert "t2" not in stats


def test_tenant_agent_health_stats_empty_inputs():
    assert dashboard.build_tenant_agent_health_stats({}) == {}
    assert dashboard.build_tenant_agent_health_stats(None) == {}


def test_tenant_agent_health_stats_malformed_input_never_raises():
    for bad in ({"devices": 1}, {"devices": "oops"},
                {"devices": [1, "x", None]},
                {"devices": [{"device_id": "d1", "degraded": "not-a-list"}]},
                {"devices": [{"device_id": "d1", "degraded": None}]},
                {}, {"devices": None}):
        dashboard.build_tenant_agent_health_stats({"t1": bad})  # must not raise


def test_tenant_agent_health_stats_resolved_device_drops_to_zero():
    """The server's explicit all-clear (degraded: []) for a previously-bad
    device must not linger — a fresh payload with an empty list contributes
    nothing, mirroring the "resolved" acceptance criterion at the device
    level."""
    still_bad = {"t1": {"devices": [
        {"device_id": "d1", "degraded": [{"kind": "x", "subject": "y", "reason": "z",
                                            "ever_succeeded": False, "count": 1}]},
    ]}}
    resolved = {"t1": {"devices": [
        {"device_id": "d1", "degraded": []},
    ]}}
    assert dashboard.build_tenant_agent_health_stats(still_bad)["t1"]["devices_degraded"] == 1
    assert dashboard.build_tenant_agent_health_stats(resolved)["t1"]["devices_degraded"] == 0


# ── 3. /api/home/triage carries the new field, degraded-mode contract intact ─

@pytest.mark.usefixtures("network_down")
def test_home_triage_carries_tenant_agent_health_stats_degraded_mode(client):
    r = client.get("/api/home/triage", headers={"Authorization": "Bearer test-key"})
    assert r.status_code == 200
    data = r.json()
    assert data["sources"] == {
        "tenants": False, "health": False,
        "needs_attention": False, "agent_health": False,
    }
    assert data["tenant_agent_health_stats"] == {}


# ── 4. CONSOLE_BUILD_ID bump (mandatory for any console.html/CSS change) ────

def test_console_build_id_bumped_for_pat1067():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"


# ── 5. Device-detail: the fourth issue class ────────────────────────────────

def test_dd_render_issues_takes_compliance_and_degraded_arguments():
    fn = _extract_fn(HTML, "_ddRenderIssues")
    assert re.search(r"function _ddRenderIssues\(dev, pending, failedPatches, failEvals, degraded, agentHealthState\)", fn)


def test_dd_render_issues_answers_the_four_questions():
    """PAT-1029: what was asked, why it failed, since when, how many times."""
    detail_fn = _extract_fn(HTML, "_ddDegradedDetail")
    what_fn = _extract_fn(HTML, "_ddDegradedWhat")
    assert "d.kind" in what_fn and "d.subject" in what_fn      # what was asked
    assert "d.reason" in detail_fn                             # why it failed
    assert "d.first_seen" in detail_fn and "_relativeTime" in detail_fn  # since when
    assert "d.count" in detail_fn                               # how many times


def test_dd_render_issues_ever_succeeded_renders_distinctly():
    fn = _extract_fn(HTML, "_ddDegradedDetail")
    assert "ever_succeeded === false" in fn or "ever_succeeded===false" in fn
    assert "Never worked" in fn
    assert "Stopped working" in fn
    # Not the same sentence with a spliced-in variable — genuinely different
    # phrases, so collapsing the two states back into one is a visible diff,
    # not a silent one.
    assert fn.index("Never worked") != fn.index("Stopped working")


def test_dd_render_issues_never_hard_fails_on_unknown_vocabulary():
    what_fn = _extract_fn(HTML, "_ddDegradedWhat")
    # No allowlist/switch over specific kind/subject strings — anything
    # unrecognised must still render (verbatim), never be dropped.
    assert "switch" not in what_fn
    for known in ("directive_skipped", "capability_missing", "sync_never_succeeded"):
        assert known not in what_fn


def test_dd_render_issues_degraded_gets_its_own_visual_state():
    fn = _extract_fn(HTML, "_ddRenderIssues")
    assert "dd-issues-degraded" in fn
    assert "dd-issue-row-degraded" in fn
    # The degraded-only branch must not reuse the alert class.
    degraded_only_branch = fn[fn.index("Agent-health attention only"):]
    assert "dd-issues-alert" not in degraded_only_branch.split("dd-issues-degraded")[0][-200:]


def test_dd_issues_degraded_css_is_a_third_distinct_colour():
    assert ".dd-issues-banner.dd-issues-degraded" in CSS
    assert ".dd-issues-degraded .dd-issue-icon" in CSS
    # Distinct from the existing alert (orange) / clear (green) tokens.
    degraded_rule = re.search(r"\.dd-issues-banner\.dd-issues-degraded\s*\{([^}]*)\}", CSS)
    assert degraded_rule
    assert "var(--orange)" not in degraded_rule.group(1)
    assert "var(--green)" not in degraded_rule.group(1)


def test_dd_render_issues_resolved_case_no_lingering_entry():
    """An empty degraded array (the server's explicit all-clear) must fall
    through to the ordinary "no immediate issues" / hard-issues-only paths —
    there is no code path that renders a degraded row for an empty list."""
    fn = _extract_fn(HTML, "_ddRenderIssues")
    assert "(degraded || []).forEach" in fn


def test_loader_wired_into_device_detail_and_reuses_last_data():
    assert "_loadDeviceAgentHealth(deviceId)" in HTML
    load_fn = _extract_fn(HTML, "_loadDeviceAgentHealth")
    assert "/agent-health" in load_fn
    assert "device_id" in load_fn
    apply_fn = _extract_fn(HTML, "_ddApplyDegraded")
    assert "_ddLastData" in apply_fn
    assert "_ddRenderIssues(dev, pending, failedPatches, failEvals, degraded, agentHealthState)" in apply_fn


# ── 6. Tenant + Home rollup — the PAT-1019 regression shape ─────────────────

def test_home_tenant_score_reads_agent_health_cache():
    fn = _extract_fn(HTML, "_homeTenantScore")
    assert "_homeTenantAgentHealth" in fn
    assert "devices_degraded" in fn
    # Defensive null check, same idiom as _homeTenantPatchStats — a tenant_id
    # absent from the cache (not yet reviewed) must not throw.
    assert "_homeTenantAgentHealth && t && t.id" in fn


def test_home_tenant_score_weight_sits_between_pending_and_blocked():
    """Ticket: 'not as urgent as a critical failed patch, but more urgent
    than a pending update.' Assert the actual numeric ordering rather than
    just presence, so a future edit that picks an out-of-range weight fails
    this test instead of silently shipping."""
    fn = _extract_fn(HTML, "_homeTenantScore")

    def _weight(pattern):
        m = re.search(pattern, fn)
        assert m, pattern
        return int(m.group(1))

    crit    = _weight(r"crit_high_fail_count \|\| 0\) \* (\d+)")
    blocked = _weight(r"devices_blocked \|\| 0\) \* (\d+)")
    pending = _weight(r"devices_pending_update \|\| 0\) \* (\d+)")
    degraded = _weight(r"devices_degraded \|\| 0\) \* (\d+)")

    assert pending < degraded < blocked < crit, (pending, degraded, blocked, crit)


def test_home_tenant_agent_health_cache_populated_by_loader():
    load_fn = _extract_fn(HTML, "_loadHomePatchQueue")
    assert "_homeTenantAgentHealth" in load_fn
    assert "tenant_agent_health_stats" in load_fn
    assert "sources.agent_health" in load_fn or "sources && sources.agent_health" in load_fn


def test_home_tenant_agent_health_module_cache_declared_null_until_loaded():
    assert "var _homeTenantAgentHealth = null;" in HTML
