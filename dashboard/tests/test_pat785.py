"""
Tests for PAT-785 — Managed Controls view only showed macOS controls.

Background: the "Manage CIS L1 controls" screen (`_cisManageOpen()` /
`_cisManageRender()` in templates/console.html, backed by
GET /admin/tenant-rules/{tenant_id}) grouped tenant CIS rules by platform but
only ever rendered a section for platforms present in the upstream response.
When the upstream Go service (`patched.im` repo, out of reach from this
worktree) returned zero Windows rules for a tenant, the Windows section
simply didn't appear — no section, no message, indistinguishable from a
rendering bug.

Covers:
  - GET /admin/tenant-rules/{tenant_id} proxies the upstream response
    unmodified — confirms the dashboard's proxy layer is a faithful
    passthrough (main.py `_proxy_json` / `proxy_rules_get`), so if Windows
    rules are absent it's an upstream data gap, not something this proxy
    route filters out.
  - console.html's rendering JS now (a) always considers both macOS and
    Windows as known platforms rather than only rendering whatever platforms
    happen to be present in the data, (b) renders an explicit "no rules
    configured" note for a known platform with zero rules instead of
    silently omitting the section, and (c) matches per-platform count
    refreshes by a `data-platform` attribute rather than positional index
    (which would misalign once empty-platform placeholder sections exist).

Run with: pytest tests/test_pat785.py -v
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test-key"}

_RULES_BOTH_PLATFORMS = {
    "rules": [
        {
            "rule_id": "r-mac-1", "rule_key": "macos_filevault_enabled",
            "title": "FileVault enabled", "platform": "macos",
            "collection_tier": "T1", "global_severity": "critical",
            "override_severity": None, "enabled": True,
        },
        {
            "rule_id": "r-mac-2", "rule_key": "macos_gatekeeper_enabled",
            "title": "Gatekeeper enabled", "platform": "macos",
            "collection_tier": "T2", "global_severity": "high",
            "override_severity": None, "enabled": False,
        },
        {
            "rule_id": "r-win-1", "rule_key": "windows_bitlocker_enabled",
            "title": "BitLocker enabled", "platform": "windows",
            "collection_tier": "T1", "global_severity": "critical",
            "override_severity": None, "enabled": True,
        },
        {
            "rule_id": "r-win-2", "rule_key": "windows_defender_enabled",
            "title": "Windows Defender enabled", "platform": "windows",
            "collection_tier": "T2", "global_severity": "high",
            "override_severity": None, "enabled": True,
        },
    ]
}

_RULES_MACOS_ONLY = {
    "rules": [
        {
            "rule_id": "r-mac-1", "rule_key": "macos_filevault_enabled",
            "title": "FileVault enabled", "platform": "macos",
            "collection_tier": "T1", "global_severity": "critical",
            "override_severity": None, "enabled": True,
        },
    ]
}


def _mock_upstream(payload, status=200):
    m = MagicMock()
    m.status_code = status
    m.content = b"x"
    m.json.return_value = payload
    m.text = str(payload)
    return m


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


# ── Proxy layer: faithful passthrough, no platform filtering ─────────────────

def test_tenant_rules_proxy_passes_through_both_platforms(client):
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_RULES_BOTH_PLATFORMS)):
        r = client.get("/admin/tenant-rules/a5effb0c-c4c3-5d57-af50-5c7fd102599e", headers=_AUTH)
    assert r.status_code == 200
    data = r.json()
    platforms = {rule["platform"] for rule in data["rules"]}
    assert platforms == {"macos", "windows"}


def test_tenant_rules_proxy_passes_through_macos_only_unmodified(client):
    # Confirms the dashboard's own proxy route does not inject or strip
    # platforms — it forwards exactly what the upstream Go service sent. If a
    # tenant only has macOS rules in prod, that's an upstream data question,
    # not something to "fix" by mutating the response here.
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_RULES_MACOS_ONLY)):
        r = client.get("/admin/tenant-rules/a5effb0c-c4c3-5d57-af50-5c7fd102599e", headers=_AUTH)
    assert r.status_code == 200
    data = r.json()
    assert len(data["rules"]) == 1
    assert data["rules"][0]["platform"] == "macos"


def test_tenant_rules_proxy_url_contains_tenant_id(client):
    captured = []

    def _fake_get(url, **kwargs):
        captured.append(url)
        return _mock_upstream(_RULES_BOTH_PLATFORMS)

    with patch.object(dashboard.http, "get", side_effect=_fake_get):
        client.get("/admin/tenant-rules/a5effb0c-c4c3-5d57-af50-5c7fd102599e", headers=_AUTH)

    assert any("tenant-rules/a5effb0c-c4c3-5d57-af50-5c7fd102599e" in u for u in captured)


# ── Frontend rendering logic — Manage CIS L1 controls screen ─────────────────

def test_cis_manage_screen_present(console_html):
    assert 'id="cis-manage"' in console_html
    assert "Manage CIS L1 controls" in console_html
    assert 'id="cis-manage-body"' in console_html


def test_cis_manage_render_treats_macos_and_windows_as_known_platforms(console_html):
    # The fix for PAT-785: both platforms are always considered, not just
    # whatever platform keys happen to show up in the response.
    assert "_CIS_KNOWN_PLATFORMS = ['macos', 'windows']" in console_html
    assert "_CIS_PLATFORM_LABELS = { macos: 'macOS', windows: 'Windows' }" in console_html
    assert "_CIS_KNOWN_PLATFORMS.concat(extraPlatforms)" in console_html


def test_cis_manage_render_shows_explicit_empty_state_per_platform(console_html):
    # Acceptance criterion: "Empty/unavailable Windows state is explicit if
    # no Windows rules exist" — not a silently missing section.
    assert "cis-manage-platform-empty" in console_html
    assert "CIS/NIST rules are configured for this tenant" in console_html
    # Guard the branch exists ahead of the full-table render path.
    assert "if (!rulesForP.length)" in console_html


def test_cis_manage_sections_tagged_with_data_platform(console_html):
    # Sections carry a stable data-platform attribute so per-platform count
    # refreshes (_cisManageUpdateCounts) don't rely on DOM ordering, which
    # would misalign once empty-platform placeholders are in the mix.
    assert "section.setAttribute('data-platform', p)" in console_html
    assert "section.getAttribute('data-platform')" in console_html
    assert "#cis-manage-body .cis-manage-platform" in console_html


def test_cis_manage_toggle_logic_is_platform_agnostic(console_html):
    # _cisManageToggle keys off rule_id, not platform — Windows T2 toggles go
    # through the same PUT /admin/tenant-rules/{id}/{ruleId} path as macOS.
    assert "function _cisManageToggle(ruleId, newValue)" in console_html
    assert "adminFetch('/admin/tenant-rules/' + tenantId + '/' + encodeURIComponent(ruleId)" in console_html


def test_cis_manage_t1_always_on_semantics_shared_across_platforms(console_html):
    # T1/T2 semantics text lives once, above the platform sections, and the
    # per-row "Always on" lock applies identically regardless of platform.
    assert "baseline controls are always on" in console_html
    assert "Always on</span>" in console_html
    assert "r.collection_tier === 'T1'" in console_html
