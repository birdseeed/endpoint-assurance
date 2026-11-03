"""Admin Tools ▸ Logs — unified, interrogable feed over every log source the
dashboard already writes (admin_audit_log, impersonation_audit_log,
report_send_audit_log, the four outbound-alert
ledgers, conversion_events, device_log_requests) plus remote automation-run
history from the platform API.

Covers: multi-source aggregation, source filter, free-text search, pagination/
limit bounds, owner-only RBAC (consultant 403 / owner 200), graceful
degradation when the automations API is unreachable, and its surviving
Admin Tools navigation placement.
"""
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    dashboard.init_db()
    with TestClient(dashboard.app) as value:
        yield value


def _cookie(email, ttl=3600):
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


def _mock_automations(jobs=None):
    mock = MagicMock(status_code=200)
    mock.json.return_value = {"jobs": jobs or []}
    mock.raise_for_status = lambda: None
    return mock


def _seed_admin_audit(db, **overrides):
    row = {
        "id": "aa-1", "ts": "2026-07-20T10:00:00+00:00",
        "actor_email": "owner@patched.im", "role": "owner",
        "method": "DELETE", "path": "/admin/tenants/acme/purge",
        "resource": "acme", "outcome": "allowed",
        "resource_name": "Acme Co", "reason": None,
        "before_value": None, "after_value": None,
    }
    row.update(overrides)
    db.execute(
        "INSERT INTO admin_audit_log "
        "(id, ts, actor_email, role, method, path, resource, outcome, "
        " resource_name, reason, before_value, after_value) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (row["id"], row["ts"], row["actor_email"], row["role"], row["method"],
         row["path"], row["resource"], row["outcome"], row["resource_name"],
         row["reason"], row["before_value"], row["after_value"]),
    )


def _seed_impersonation(db, **overrides):
    row = {
        "id": "imp-1", "session_id": "sess-1", "tenant_id": "acme",
        "actor_email": "owner@patched.im", "action": "started",
        "started_at": "2026-07-20T09:00:00+00:00", "ended_at": None,
        "duration_seconds": None, "created_at": "2026-07-20T09:00:00+00:00",
    }
    row.update(overrides)
    db.execute(
        "INSERT INTO impersonation_audit_log "
        "(id, session_id, tenant_id, actor_email, action, started_at, ended_at, duration_seconds, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (row["id"], row["session_id"], row["tenant_id"], row["actor_email"],
         row["action"], row["started_at"], row["ended_at"],
         row["duration_seconds"], row["created_at"]),
    )


# ── Multi-source aggregation ──────────────────────────────────────────────────

def test_unified_feed_returns_entries_from_multiple_sources(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db)
        _seed_impersonation(db)

    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r = client.get("/admin/logs", headers=BEARER)
    assert r.status_code == 200
    body = r.json()
    sources_seen = {e["source"] for e in body["entries"]}
    assert "admin_audit" in sources_seen
    assert "impersonation" in sources_seen
    # Every declared source has a meta entry, even ones with zero matches —
    # this is what lets the UI show an accurate chip list.
    assert set(dashboard._LOG_SOURCES) == set(body["sources"])
    assert body["sources"]["admin_audit"]["matched"] == 1
    assert body["sources"]["impersonation"]["matched"] == 1
    # Newest-first.
    timestamps = [e["ts"] for e in body["entries"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_admin_audit_row_shape_and_outcome_bucket(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db, outcome="denied_rbac")
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r = client.get("/admin/logs", headers=BEARER, params={"source": "admin_audit"})
    entry = r.json()["entries"][0]
    assert entry["source"] == "admin_audit"
    assert entry["actor"] == "owner@patched.im"
    assert entry["outcome"] == "denied"
    assert entry["outcome_raw"] == "denied_rbac"
    assert entry["detail"]["path"] == "/admin/tenants/acme/purge"
    assert "id" in entry and "ts" in entry and "summary" in entry and "action" in entry


# ── Source filter ─────────────────────────────────────────────────────────────

def test_source_filter_restricts_to_requested_sources(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db)
        _seed_impersonation(db)
    with patch.object(dashboard.http, "get", return_value=_mock_automations()) as mock_get:
        r = client.get("/admin/logs", headers=BEARER, params={"source": "admin_audit"})
    assert r.status_code == 200
    body = r.json()
    assert {e["source"] for e in body["entries"]} == {"admin_audit"}
    assert set(body["sources"]) == {"admin_audit"}
    # automation_run wasn't requested — no remote call should have happened.
    mock_get.assert_not_called()


def test_comma_separated_and_repeated_source_params_both_work(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db)
        _seed_impersonation(db)
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r1 = client.get("/admin/logs", headers=BEARER, params={"source": "admin_audit,impersonation"})
        r2 = client.get("/admin/logs?source=admin_audit&source=impersonation", headers=BEARER)
    for r in (r1, r2):
        assert {e["source"] for e in r.json()["entries"]} == {"admin_audit", "impersonation"}


def test_unknown_outcome_bucket_yields_zero_rows_for_that_source(client):
    # conversion_events models only "info" — asking for "denied" must return
    # zero rows from it, not silently ignore the filter. (This used the PAT-960
    # catalogue_hosting source until PAT-2249 retired it.)
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO conversion_events (id,tenant_id,event_name,category,severity,recorded_at) "
            "VALUES (?,?,?,?,?,?)",
            ("ce-1", "tenant-1", "cta_click", "patching", "info", "2026-07-20T11:00:00+00:00"),
        )
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        info = client.get("/admin/logs", headers=BEARER,
                          params={"source": "conversion_event", "outcome": "info"})
        r = client.get("/admin/logs", headers=BEARER,
                        params={"source": "conversion_event", "outcome": "denied"})
    # Control: the row is visible under the bucket the source does model, so
    # the empty result below is the bucket filter, not a missing row.
    assert info.json()["sources"]["conversion_event"]["matched"] == 1
    body = r.json()
    assert body["entries"] == []
    assert body["sources"]["conversion_event"]["matched"] == 0


# ── Free-text search ──────────────────────────────────────────────────────────

def test_search_filter_matches_free_text(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db, id="aa-1", resource_name="Acme Co", path="/admin/tenants/acme/purge")
        _seed_admin_audit(db, id="aa-2", resource_name="Widgets Ltd", path="/admin/tenants/widgets/purge",
                           ts="2026-07-20T10:05:00+00:00")
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r = client.get("/admin/logs", headers=BEARER, params={"q": "Widgets", "source": "admin_audit"})
    body = r.json()
    assert len(body["entries"]) == 1
    assert body["entries"][0]["detail"]["resource_name"] == "Widgets Ltd"


def test_search_filter_with_no_matches_returns_empty(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db)
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r = client.get("/admin/logs", headers=BEARER, params={"q": "nonexistent-xyz", "source": "admin_audit"})
    assert r.json()["entries"] == []


# ── Pagination / limit bounds ─────────────────────────────────────────────────

def test_limit_defaults_and_is_clamped_to_max(client):
    with dashboard.get_db() as db:
        for i in range(5):
            _seed_admin_audit(db, id=f"aa-{i}", ts=f"2026-07-20T10:0{i}:00+00:00")
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        default_resp = client.get("/admin/logs", headers=BEARER, params={"source": "admin_audit"})
        assert default_resp.json()["limit"] == dashboard._LOG_DEFAULT_LIMIT

        huge_resp = client.get("/admin/logs", headers=BEARER,
                                params={"source": "admin_audit", "limit": 999999})
        assert huge_resp.json()["limit"] == dashboard._LOG_MAX_LIMIT

        small_resp = client.get("/admin/logs", headers=BEARER,
                                 params={"source": "admin_audit", "limit": 2})
        assert small_resp.json()["limit"] == 2
        assert len(small_resp.json()["entries"]) == 2
        assert small_resp.json()["sources"]["admin_audit"]["matched"] == 5


def test_offset_pages_through_results_without_duplicates(client):
    with dashboard.get_db() as db:
        for i in range(5):
            _seed_admin_audit(db, id=f"aa-{i}", ts=f"2026-07-20T10:0{i}:00+00:00")
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        page1 = client.get("/admin/logs", headers=BEARER,
                            params={"source": "admin_audit", "limit": 2, "offset": 0}).json()
        page2 = client.get("/admin/logs", headers=BEARER,
                            params={"source": "admin_audit", "limit": 2, "offset": 2}).json()
    ids1 = [e["id"] for e in page1["entries"]]
    ids2 = [e["id"] for e in page2["entries"]]
    assert len(ids1) == 2 and len(ids2) == 2
    assert set(ids1).isdisjoint(ids2)
    # Newest-first: page1 (offset 0) must be strictly newer than page2.
    assert min(page1["entries"], key=lambda e: e["ts"])["ts"] >= max(page2["entries"], key=lambda e: e["ts"])["ts"]


# ── RBAC: owner-only ───────────────────────────────────────────────────────────

def test_consultant_is_denied(client):
    r = client.get("/admin/logs", headers=_cookie("consultant@patched.im"))
    assert r.status_code == 403


def test_owner_cookie_is_allowed(client):
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r = client.get("/admin/logs", headers=_cookie("owner@patched.im"))
    assert r.status_code == 200


def test_bearer_token_is_allowed(client):
    with patch.object(dashboard.http, "get", return_value=_mock_automations()):
        r = client.get("/admin/logs", headers=BEARER)
    assert r.status_code == 200


def test_no_auth_is_401(client):
    r = client.get("/admin/logs")
    assert r.status_code == 401


def test_is_owner_only_get_classifier():
    assert dashboard._is_owner_only_get("GET", "/admin/logs") is True
    assert dashboard._is_owner_only_get("GET", "/admin/tenants") is False


# ── Graceful degradation when the automations API is unreachable ─────────────

def test_degrades_gracefully_when_automations_api_unreachable(client):
    with dashboard.get_db() as db:
        _seed_admin_audit(db)
    with patch.object(dashboard.http, "get", side_effect=ConnectionError("no route to host")):
        r = client.get("/admin/logs", headers=BEARER)
    assert r.status_code == 200  # never 500s the whole page
    body = r.json()
    assert body["sources"]["automation_run"]["available"] is False
    assert "unavailable" in body["sources"]["automation_run"]["error"]
    # Local sources are unaffected — admin_audit still comes through.
    assert body["sources"]["admin_audit"]["available"] is True
    assert body["sources"]["admin_audit"]["matched"] == 1


def test_degrades_gracefully_on_non_200_from_automations_api(client):
    bad = MagicMock(status_code=503)
    bad.raise_for_status.side_effect = Exception("503 Service Unavailable")
    with patch.object(dashboard.http, "get", return_value=bad):
        r = client.get("/admin/logs", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["sources"]["automation_run"]["available"] is False


def test_automation_run_entries_included_when_api_is_up(client):
    jobs = [{
        "job_name": "nightly-digest",
        "schedule": "0 7 * * *",
        "recent_runs": [
            {"id": 1, "started_at": "2026-07-20T07:00:00+00:00",
             "finished_at": "2026-07-20T07:00:05+00:00", "status": "success", "duration_s": 5.0},
            {"id": 2, "started_at": "2026-07-19T07:00:00+00:00",
             "finished_at": "2026-07-19T07:00:07+00:00", "status": "failed",
             "duration_s": 7.0, "error_msg": "boom"},
        ],
    }]
    with patch.object(dashboard.http, "get", return_value=_mock_automations(jobs)):
        r = client.get("/admin/logs", headers=BEARER, params={"source": "automation_run"})
    body = r.json()
    assert body["sources"]["automation_run"]["available"] is True
    assert len(body["entries"]) == 2
    by_status = {e["outcome_raw"]: e["outcome"] for e in body["entries"]}
    assert by_status["success"] == "success"
    assert by_status["failed"] == "error"


# ── Console nav placement ─────────────────────────────────────────────────────

def test_console_nav_keeps_logs_between_software_alerts_and_reports():
    html = (REPO / "templates" / "console.html").read_text()
    admin_group_start = html.index('id="nav-section-admin"')
    admin_group_end = html.index("</nav>", admin_group_start)
    admin_group = html[admin_group_start:admin_group_end]
    for needle in ('id="nav-credentials"', 'id="nav-docs"',
                   'id="nav-homebrew-review"', 'id="nav-software-alerts"',
                   'id="nav-logs"', 'id="nav-reports"'):
        assert needle in admin_group, f"{needle} missing from the Admin Tools nav group"
    alerts_pos = admin_group.index('id="nav-software-alerts"')
    logs_pos = admin_group.index('id="nav-logs"')
    reports_pos = admin_group.index('id="nav-reports"')
    assert alerts_pos < logs_pos < reports_pos


def test_console_build_id_bumped_for_this_change():
    # Any templates/console.html change requires a CONSOLE_BUILD_ID bump —
    # see tests/test_console_build_id.py for the full regression cover; this
    # just pins the specific value this ticket introduced.
    #
    # NOTE (PAT-1004): this assertion only fires when someone DOES bump the id,
    # never when they forget to. PAT-998 shipped a console.html change without a
    # bump and this test stayed green, so browsers held the old
    # console.css?v=... for up to 7 days (nginx serves /static/ with
    # `expires 7d; Cache-Control "public, immutable"`) and rendered new markup
    # against stale CSS. Treat this as a value pin, not as cache-bust coverage.
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
