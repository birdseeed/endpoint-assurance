"""
PAT-1006 — Home leads with patching posture, not CIS compliance.
PAT-1019/1020 follow-ups landed in this same file (see their sections below):
  * PAT-1019 relabelled the "Blocked / failed" headline stat to "Blocked" —
    devices_blocked is verification-blocked updates, never attempted-and-
    failed installs (no estate-wide count of the latter exists without a
    per-device patch_history fetch).
  * PAT-1020 removed the "Devices needing work" per-device card entirely —
    Home is a tenant view, not a device queue — and enriched the tenant rows
    with per-tenant pending-update / blocked-patch device counts instead.

Covers:
  * build_estate_patch_stats() — estate-wide patch counters sourced from the
    real by_device breakdown, plus the full-estate not-checked-in count.
  * build_tenant_patch_stats() — the SAME by_device breakdown grouped per
    tenant instead of summed, feeding the tenant-row chips.
  * /api/home/triage carries patch_stats + tenant_patch_stats alongside the
    existing items/sources contract (unchanged shape for degraded-mode tests).
  * The blocked_patch device field bug (it.get("device_name") -> "hostname").
  * The Home tenant-attention row no longer renders CIS posture twice, and now
    carries per-tenant pending/blocked device chips.
  * The device-queue card and its backend/frontend/CSS are fully gone.

Run with: pytest tests/test_pat1006_home_patching_first.py -v
"""

import os
import sys
from pathlib import Path

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


def _sample_na_by_tenant():
    return {
        "t1": {
            "by_device": [
                {"device_id": "d1", "hostname": "alpha-mac", "total": 3,
                 "vulnerable": 0, "out_of_date": 1, "blocked": 2},
                {"device_id": "d2", "hostname": "beta-win", "total": 1,
                 "vulnerable": 0, "out_of_date": 1, "blocked": 0},
                {"device_id": "d3", "hostname": "gamma-mac", "total": 0,
                 "vulnerable": 0, "out_of_date": 0, "blocked": 0},
            ],
        },
        "t2": {
            "by_device": [
                {"device_id": "d4", "hostname": "delta-win", "total": 2,
                 "vulnerable": 2, "out_of_date": 0, "blocked": 0},
            ],
        },
    }


def _sample_tenants():
    return [
        {"id": "t1", "name": "Alpha Co", "device_count": 10, "active_last_7d": 8},
        {"id": "t2", "name": "Beta Co", "device_count": 5, "active_last_7d": 5},
    ]


# ── build_estate_patch_stats: real counters, correct coverage scope ─────────

def test_patch_stats_counts_unique_devices_not_issue_rows():
    stats = dashboard.build_estate_patch_stats(_sample_tenants(), _sample_na_by_tenant())
    # d1 (blocked) + d4... wait d4 is vulnerable only, not blocked/out_of_date.
    # devices_pending_update: d1 (out_of_date=1), d2 (out_of_date=1) -> 2
    assert stats["devices_pending_update"] == 2
    # devices_blocked: d1 only -> 1
    assert stats["devices_blocked"] == 1


def test_patch_stats_not_checked_in_covers_full_estate_no_fanout_cap():
    tenants = _sample_tenants() + [{"id": "t3", "name": "Gamma Co",
                                     "device_count": 20, "active_last_7d": 2}]
    # t3 has no needs-attention entry at all (outside the fan-out cap) but its
    # stale-device count must still be included — this counter has no cap.
    stats = dashboard.build_estate_patch_stats(tenants, _sample_na_by_tenant())
    assert stats["devices_not_checked_in"] == (10 - 8) + (5 - 5) + (20 - 2)


def test_patch_stats_reports_tenant_coverage():
    tenants = _sample_tenants() + [{"id": "t3", "name": "Gamma Co"}]
    stats = dashboard.build_estate_patch_stats(tenants, _sample_na_by_tenant())
    assert stats["tenants_total"] == 3
    assert stats["tenants_reviewed"] == 2  # only t1/t2 have needs-attention data


def test_patch_stats_empty_inputs():
    stats = dashboard.build_estate_patch_stats([], {})
    assert stats == {
        "devices_pending_update": 0, "devices_blocked": 0,
        "devices_not_checked_in": 0, "tenants_reviewed": 0, "tenants_total": 0,
        "fanout_cap": dashboard.TRIAGE_NA_FANOUT_CAP,
    }


# ── build_tenant_patch_stats (PAT-1020): same source, grouped per tenant ────

def test_tenant_patch_stats_groups_per_tenant_not_summed():
    stats = dashboard.build_tenant_patch_stats(_sample_na_by_tenant())
    # t1: d1 out_of_date=1 & blocked=2>0, d2 out_of_date=1, d3 nothing.
    assert stats["t1"] == {"devices_pending_update": 2, "devices_blocked": 1}
    # t2: d4 vulnerable only -> neither pending nor blocked.
    assert stats["t2"] == {"devices_pending_update": 0, "devices_blocked": 0}


def test_tenant_patch_stats_omits_tenants_without_device_data():
    """A tenant with no by_device list (outside the fan-out cap, or its
    needs-attention call failed) must be ABSENT from the result, not present
    with zeros — the caller needs to tell "unreviewed" from "clean"."""
    na = {"t1": {"by_device": []}, "t2": {"items": []}}  # t2 has no by_device
    stats = dashboard.build_tenant_patch_stats(na)
    assert "t1" in stats
    assert "t2" not in stats


def test_tenant_patch_stats_empty_inputs():
    assert dashboard.build_tenant_patch_stats({}) == {}
    assert dashboard.build_tenant_patch_stats(None) == {}


def test_tenant_patch_stats_malformed_input_never_raises():
    for bad in ({"by_device": 1}, {"by_device": "oops"},
                {"by_device": [1, "x", None]},
                {"by_device": [{"total": "5"}]},
                {"by_device": [{"total": 3, "blocked": "2"}]},
                {}, {"by_device": None}):
        dashboard.build_tenant_patch_stats({"t1": bad})  # must not raise


def test_tenant_patch_stats_coerces_malicious_and_negative_counts():
    """A count reaches innerHTML on the client via the tenant row chips.
    Coerce at the boundary so a string payload can neither render as markup
    nor show as a negative, and non-numeric junk doesn't spuriously flag a
    device as blocked/pending."""
    na = {"t1": {"by_device": [{
        "device_id": "d1", "hostname": "h1",
        "blocked": "<img src=x onerror=alert(1)>",
        "out_of_date": "-7",
    }, {
        "device_id": "d2", "hostname": "h2",
        "blocked": "2", "out_of_date": 0,
    }]}}
    stats = dashboard.build_tenant_patch_stats(na)
    # d1: non-numeric "blocked" -> 0 (not counted), negative out_of_date -> 0.
    # d2: numeric string "2" -> counted as blocked.
    assert stats["t1"] == {"devices_pending_update": 0, "devices_blocked": 1}


# ── The blocked_patch device-field bug (device_name -> hostname) ────────────

def test_blocked_patch_reads_hostname_not_nonexistent_device_name():
    # Upstream's needsAttentionItem has no "device_name" field (see
    # go-service/internal/handlers/needs_attention.go) — only "hostname". A
    # payload shaped like the real API (hostname, no device_name) must still
    # surface the device in the blocked-patch detail text.
    tenants = [{"id": "t1", "name": "Alpha"}]
    na = {"t1": {"items": [
        {"category": "blocked", "app_name": "Zoom", "hostname": "real-host",
         "failure_reason": "signer_mismatch"},
    ], "summary": {"blocked": 1}}}
    q = dashboard.build_triage_queue(tenants, {}, na, None)
    blocked = [i for i in q if i["kind"] == "blocked_patch"]
    assert blocked and "real-host" in blocked[0]["detail"]


def test_blocked_patch_wording_never_says_failed():
    """PAT-1019: build_triage_queue's blocked_patch item is sourced from
    verification-blocked updates only — its wording must say "blocked", never
    "failed", so it isn't read as the (unrelated) attempted-and-failed-install
    signal that only exists per-device in device detail."""
    tenants = [{"id": "t1", "name": "Alpha"}]
    na_with_item = {"t1": {"items": [
        {"category": "blocked", "app_name": "Zoom", "hostname": "real-host",
         "failure_reason": "signer_mismatch"},
    ], "summary": {"blocked": 1}}}
    na_summary_only = {"t1": {"items": [], "summary": {"blocked": 3}}}
    for na in (na_with_item, na_summary_only):
        q = dashboard.build_triage_queue(tenants, {}, na, None)
        blocked = [i for i in q if i["kind"] == "blocked_patch"]
        assert blocked
        for item in blocked:
            assert "failed" not in item["title"].lower()
            assert "failed" not in item["detail"].lower()


# ── /api/home/triage: new fields alongside the existing degraded-mode contract ─

@pytest.mark.usefixtures("network_down")
def test_home_triage_response_carries_patch_stats_and_tenant_patch_stats(client):
    r = client.get("/api/home/triage", headers={"Authorization": "Bearer test-key"})
    assert r.status_code == 200
    data = r.json()
    # Existing PAT-698 contract is untouched.
    assert data["items"] == []
    assert data["sources"] == {"tenants": False, "health": False,
                               "needs_attention": False, "agent_health": False}
    # PAT-1006 estate-wide counters, present even in fully-degraded mode.
    assert data["patch_stats"] == {
        "devices_pending_update": 0, "devices_blocked": 0,
        "devices_not_checked_in": 0, "tenants_reviewed": 0, "tenants_total": 0,
        "fanout_cap": dashboard.TRIAGE_NA_FANOUT_CAP,
    }
    # PAT-1020: per-tenant breakdown replaces the removed device_queue key.
    assert data["tenant_patch_stats"] == {}
    assert "device_queue" not in data
    # PAT-1067: per-tenant degraded-agent counter, present even in fully-
    # degraded mode (empty, not absent — same "present but empty" contract).
    assert data["tenant_agent_health_stats"] == {}


# ── CONSOLE_BUILD_ID bump (mandatory for any console.html/CSS change) ───────

def test_console_build_id_bumped_for_this_ticket():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"


# ── Home tenant row: CIS posture renders at most once (was duplicated) ──────

def test_tenant_attention_row_does_not_duplicate_cis_posture():
    fn = _extract_fn(HTML, "_renderHomeAttention")
    # The chip-construction block used to push a second "% CIS posture" STRING
    # LITERAL onto the same row as the `posture` subtitle. Only one construction
    # site (the `posture` variable) should remain. Match the quoted literal
    # specifically so an explanatory code comment mentioning the old bug
    # ("53.4% CIS posture" twice) doesn't also count as a hit.
    assert fn.count("'% CIS posture'") == 1
    assert "posture" in fn


# ── PAT-1020: tenant rows carry per-tenant pending/blocked chips ────────────

def test_tenant_attention_row_reads_per_tenant_patch_stats():
    fn = _extract_fn(HTML, "_renderHomeAttention")
    assert "_homeTenantPatchStats" in fn
    assert "devices_blocked" in fn
    assert "devices_pending_update" in fn
    # Counts are attacker-influenced (upstream JSON) and reach innerHTML, so
    # every value must be escaped at the sink, same discipline as the rest of
    # this row builder (PAT-854/PAT-1006 review).
    assert "_escHtml(String(blockedDevices))" in fn
    assert "_escHtml(String(pendingDevices))" in fn


# ── Home layout: card removed, single balanced column, no dead space ───────

def test_home_devices_card_fully_removed():
    """PAT-1020: the "Devices needing work" card — markup, JS, CSS, backend
    builder, and payload key — must be gone with no orphaned remnant."""
    assert "Devices needing work" not in HTML
    assert 'id="home-devices"' not in HTML
    for needle in ("home-devices-loading", "home-devices-unavailable",
                   "home-devices-content", "home-devices-more", "home-devices-count"):
        assert needle not in HTML, needle
    assert "_homeDeviceDrill" not in HTML
    assert "_renderHomeDeviceQueue" not in HTML
    assert "home-devices-more" not in CSS
    assert not hasattr(dashboard, "build_device_work_queue")
    assert not hasattr(dashboard, "DEVICE_QUEUE_CAP")


def test_home_primary_flow_has_no_device_column():
    # Service exceptions are the primary surface; retired estate posture
    # must not become an active DOM target again.
    start = HTML.index('<div id="section-home"')
    end = HTML.index("<!-- ═══ SECTION: REPORTS", start)
    home = HTML[start:end]

    assert 'class="work-landing-grid" id="home-list-detail"' in home
    assert 'class="work-primary-column"' in home
    assert 'class="work-context-rail"' in home
    attention_pos = home.index('id="home-service-exceptions"')
    rail_pos = home.index('class="work-context-rail"')
    assert attention_pos < rail_pos
    assert 'id="home-estate-posture"' not in home
    assert 'data-retired-surface="estate-posture"' in home
    assert "Service exceptions" in home
    assert "Customer attention" not in home


def test_home_layout_still_collapses_responsively():
    # Work's primary/context composition collapses before its table and 340px
    # context rail become cramped.
    assert "@media (max-width: 1100px)" in CSS
    assert "#home-attention { order: 1; }" in CSS
    assert "#home-inspector { order: 2; }" in CSS


# ── Headline: patch state leads, CIS demoted to a secondary stat ────────────

def test_verdict_headline_leads_with_patch_state_cis_secondary():
    fn = _extract_fn(HTML, "_renderHomeVerdict")
    assert "_homePatchStats" in fn
    assert "_homePatchSources" in fn
    assert "Updates pending" in fn
    assert "'CIS posture', pctCol, {secondary: true}" in fn
    # The stats row must list patch/device signals ahead of CIS posture.
    pending_pos = fn.index("'Updates pending'")
    cis_pos = fn.index("'CIS posture'")
    assert pending_pos < cis_pos


def test_verdict_blocked_stat_relabelled_not_blocked_slash_failed():
    """PAT-1019: devices_blocked is verification-blocked, never an
    attempted-and-failed install — the old "Blocked / failed" label could read
    0 while a device elsewhere had real failed patch attempts (a different
    measurement, device detail's _ddUnresolvedFailedPatches). The label must
    say only what this stat actually counts."""
    fn = _extract_fn(HTML, "_renderHomeVerdict")
    assert "'Blocked'" in fn
    assert "'Blocked / failed'" not in fn


# ── PAT-1006 review fixes: malformed upstream must not crash, lie, or inject ──
# All three were reproduced against the pre-fix code before these were written.


@pytest.mark.parametrize("bad", [
    {"by_device": 1},                          # not a list at all
    {"by_device": "oops"},
    {"by_device": [1, "x", None]},             # list of non-dicts
    {"by_device": [{"total": "5"}]},           # string count -> "<=" TypeError pre-fix
    {"by_device": [{"total": 3, "blocked": "2"}]},
    {},                                        # by_device absent entirely
    {"by_device": None},
])
def test_malformed_by_device_never_raises(bad):
    """Pre-fix these raised TypeError inside /api/home/triage, which runs the
    helpers OUTSIDE the upstream try blocks — so Home returned 500."""
    tenants = [{"id": "t1", "name": "T1", "device_count": 5, "active_last_7d": 5}]
    dashboard.build_estate_patch_stats(tenants, {"t1": bad})
    dashboard.build_tenant_patch_stats({"t1": bad})


def test_missing_by_device_is_not_counted_as_reviewed():
    """"Unavailable" must not collapse into "nothing needs attention". A
    tenant that answered without a by_device list has NOT been reviewed."""
    tenants = [{"id": "t1", "name": "T1", "device_count": 1, "active_last_7d": 1},
               {"id": "t2", "name": "T2", "device_count": 1, "active_last_7d": 1}]
    na = {"t1": {"by_device": []}, "t2": {"items": []}}  # t2 has no by_device
    assert dashboard.build_estate_patch_stats(tenants, na)["tenants_reviewed"] == 1
    tps = dashboard.build_tenant_patch_stats(na)
    assert "t1" in tps and "t2" not in tps
