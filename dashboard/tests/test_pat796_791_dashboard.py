"""Regression tests for PAT-796 and PAT-791 dashboard bugs."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard


def _console_html():
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_admin_fetch_callers_do_not_parse_json_twice():
    html = _console_html()

    assert "adminFetch('/api/leads')\n    .then(function(r) { return r.json(); })" not in html
    assert "adminFetch('/api/ops/data')\n    .then(function(r) { return r.json(); })" not in html
    assert "adminFetch('/api/ops/firewall-apply'" in html
    assert ".then(function(r) { return r.json(); })\n    .then(function(d) {\n      var ok = d.ok;" not in html


def test_new_apps_decision_sends_required_actor_and_action():
    html = _console_html()

    assert "PatchedConsoleGovernance.newAppDecision(decision)" in html
    assert "body: JSON.stringify({ decision: upstreamDecision, decided_by: window.__ACTOR || 'dashboard' })" in html
    assert "alert('Decision failed: ' + adminErrorText(err));" in html


def test_proxy_json_preserves_non_json_upstream_body():
    class Resp:
        status_code = 400
        content = b"decided_by is required\n"
        text = "decided_by is required\n"

        def json(self):
            raise ValueError("not json")

    response = dashboard._proxy_json(Resp())

    assert response.status_code == 400
    assert b'"error":"upstream returned non-JSON"' in response.body
    assert b'"body":"decided_by is required\\n"' in response.body
