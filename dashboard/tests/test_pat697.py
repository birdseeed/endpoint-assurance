"""
Tests for PAT-697 — Dashboard Phase 2: one server-owned "stale" vocabulary,
one timestamp convention, and honest data-freshness indicators.

Coverage:
  - DEVICE_FRESHNESS is the single source of truth (active 7d / silent 30d) and
    STALE_THRESHOLD_DEFAULT_DAYS derives from it (dropped 14 → 7).
  - GET /api/config/freshness returns 7/30 (+ the derived digest default).
  - The /console template injects window.__DEVICE_FRESHNESS and _dhFreshnessBucket
    reads it — no literal 7/30 day-boundary left hard-coded in that function.
  - The stale-endpoint digest tick flags a device stale at the 7-day default when
    no per-tenant override is set; a per-tenant override still wins.
  - A device at 5 / 10 / 40 days maps to active / stale / silent under the shared
    constant.
  - The rendered template no longer emits UTC toISOString().slice(0,10) dates.
  - Infra "stale" wording is now "lagging" (automation-alert reason string).
"""

import os
import re
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


# ── The single freshness vocabulary ───────────────────────────────────────────

class TestFreshnessConstant:
    def test_device_freshness_values(self):
        assert dashboard.DEVICE_FRESHNESS["active_max_days"] == 7
        assert dashboard.DEVICE_FRESHNESS["silent_min_days"] == 30

    def test_stale_default_derives_from_active_max(self):
        # PAT-697: the digest default is no longer a magic 14; it IS active_max_days.
        assert dashboard.STALE_THRESHOLD_DEFAULT_DAYS == 7
        assert (dashboard.STALE_THRESHOLD_DEFAULT_DAYS
                == dashboard.DEVICE_FRESHNESS["active_max_days"])

    def test_freshness_endpoint_returns_7_30(self, client):
        r = client.get("/api/config/freshness", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        assert body["active_max_days"] == 7
        assert body["silent_min_days"] == 30
        assert body["stale_digest_default_days"] == 7


# ── UI reads the injected vocabulary, never a hard-coded boundary ──────────────

class TestTemplateInjection:
    def test_console_injects_device_freshness(self, client):
        r = client.get("/console")
        assert r.status_code == 200
        assert "window.__DEVICE_FRESHNESS" in r.text
        assert '"active_max_days": 7' in r.text
        assert '"silent_min_days": 30' in r.text

    def _extract_fn(self, text, name):
        # Pull a single top-level `function <name>(...) { ... }` body by brace match.
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

    def test_bucket_fn_sources_thresholds_not_hardcoded(self, client):
        r = client.get("/console")
        fn = self._extract_fn(r.text, "_dhFreshnessBucket")
        # It must read the shared config…
        assert "_freshnessCfg()" in fn or "__DEVICE_FRESHNESS" in fn
        assert "active_max_days" in fn
        assert "silent_min_days" in fn
        # …and carry no literal 7 / 30 day boundary of its own.
        assert not re.search(r"\b7\b", fn)
        assert not re.search(r"\b30\b", fn)

    def test_freshness_cfg_falls_back_to_shared_defaults(self, client):
        r = client.get("/console")
        fn = self._extract_fn(r.text, "_freshnessCfg")
        # Fallback numbers mirror the server constant (defence in depth only).
        assert "active_max_days" in fn and "silent_min_days" in fn


# ── One timestamp convention: no UTC-date slicing left in the template ─────────

class TestTimestampConvention:
    def test_no_utc_date_slice_in_template(self, client):
        r = client.get("/console")
        assert "toISOString().slice(0,10)" not in r.text
        assert "toISOString().slice(0, 10)" not in r.text

    def test_local_date_and_tooltip_helpers_present(self, client):
        r = client.get("/console")
        assert "function _fmtDate(" in r.text
        assert "function _localDateISO(" in r.text
        # Date helpers carry an ISO-UTC hover tooltip.
        assert "(UTC)" in r.text


# ── Honest freshness indicators ───────────────────────────────────────────────

class TestFreshnessStamp:
    def test_stamp_helper_and_targets_present(self, client):
        r = client.get("/console")
        assert "function _freshnessStamp(" in r.text
        for el in ("home-freshness", "cl-freshness", "dh-freshness"):
            assert 'id="' + el + '"' in r.text


# ── Infra staleness is now "lagging"/"overdue", not "stale" ────────────────────

class _FakeResp:
    def __init__(self, payload):
        self._payload = payload
        self.content = b"x"
        self.status_code = 200

    def json(self):
        return self._payload


class TestInfraWording:
    def test_automation_alert_reason_is_lagging(self, client, monkeypatch):
        # A job whose last run is >26h old is lagging (infra lag), NOT "stale".
        old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()

        def fake_get(url, *a, **k):
            if url.endswith("/admin/automations"):
                return _FakeResp({"jobs": [
                    {"job_name": "nightly-sync", "last_status": "success", "last_run": old},
                ]})
            # /admin/health and anything else: minimal healthy payload.
            return _FakeResp({"service_health": {}})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        r = client.get("/admin/health/proxy", headers=BEARER)
        assert r.status_code == 200
        alerts = r.json().get("service_health", {}).get("automation_alerts", [])
        assert alerts, "expected a lagging automation alert"
        assert alerts[0]["reason"] == "lagging"
        # "stale" must no longer be used for infra job lag.
        assert all(a["reason"] != "stale" for a in alerts)

    def test_quarantined_automation_is_not_a_live_service_health_alert(self, client, monkeypatch):
        old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()

        def fake_get(url, *a, **k):
            if url.endswith("/admin/automations"):
                return _FakeResp({"jobs": [{
                    "job_name": "installomator_sync", "last_status": "failed", "last_run": old,
                }]})
            return _FakeResp({"service_health": {}})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        r = client.get("/admin/health/proxy", headers=BEARER)
        assert r.status_code == 200
        assert r.json()["service_health"]["automation_alerts"] == []


# ── The stale-endpoint digest tick uses the shared default (7), overrides win ──

class TestDigestTick:
    def _seed_client(self, tenant_id="t-1", threshold=None, recipient="ops@acme.test"):
        with dashboard.get_db() as db:
            db.execute(
                "INSERT INTO clients (id, company, tenant_id, "
                "created_at, primary_contact_email, stale_digest_enabled, "
                "stale_digest_threshold_days) VALUES (?,?,?,?,?,?,?)",
                ("id-1", "Acme", tenant_id,
                 datetime.now(timezone.utc).isoformat(), recipient, 1, threshold),
            )

    def _run(self, monkeypatch, tenant_id="t-1", devices=None):
        now = datetime.now(timezone.utc)
        sent = []

        def fake_get(url, *a, **k):
            if url.endswith("/admin/tenants/overview"):
                return _FakeResp({"tenants": [{"id": tenant_id}]})
            if url.endswith("/devices"):
                return _FakeResp({"devices": devices or []})
            return _FakeResp({})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(
            dashboard, "_send_email",
            lambda to, subj, html, text: sent.append((to, subj, html, text)) or True)
        dashboard._run_stale_digest_tick(now)
        return sent, now

    def test_default_threshold_flags_at_7_days(self, client, monkeypatch):
        # No per-tenant override → shared default (7). A 9-day-silent device is
        # stale (would NOT have been at the old 14-day default), a 5-day one is not.
        self._seed_client(threshold=None)
        now = datetime.now(timezone.utc)
        devices = [
            {"hostname": "stale-host", "last_seen": (now - timedelta(days=9)).isoformat()},
            {"hostname": "fresh-host", "last_seen": (now - timedelta(days=5)).isoformat()},
        ]
        sent, _ = self._run(monkeypatch, devices=devices)
        # NOTE: the app's background scheduler thread may also tick through the
        # monkeypatched http/_send_email during the test, so assert on CONTENT
        # (which is identical across ticks — same seeded tenant/devices) rather
        # than an exact send count.
        assert len(sent) >= 1, "a stale device at 9d should trigger the digest at the 7d default"
        for (_to, _subj, html, text) in sent:
            body = html + text
            assert "stale-host" in body   # 9d ≥ 7d default → stale
            assert "fresh-host" not in body  # 5d < 7d default → fresh

    def test_per_tenant_override_still_wins(self, client, monkeypatch):
        # Override of 20 days → the 9-day device is fresh, no email.
        self._seed_client(threshold=20)
        now = datetime.now(timezone.utc)
        devices = [
            {"hostname": "stale-host", "last_seen": (now - timedelta(days=9)).isoformat()},
        ]
        sent, _ = self._run(monkeypatch, devices=devices)
        assert sent == [], "a 20-day override must suppress a 9-day-silent device"

    def test_send_failure_does_not_mark_delivered(self, client, monkeypatch):
        # PAT-815: the historic delivery guard used to record delivery even
        # when _send_email() returned False. A failed send must leave
        # last_stale_digest_sent_at untouched so the next tick retries. (The fix
        # no longer reads provider configuration at all — this test only needs
        # to simulate _send_email() returning False.)
        tenant_id = "t-fail"
        self._seed_client(tenant_id=tenant_id, threshold=None)
        now = datetime.now(timezone.utc)
        devices = [
            {"hostname": "stale-host", "last_seen": (now - timedelta(days=9)).isoformat()},
        ]

        def fake_get(url, *a, **k):
            if url.endswith("/admin/tenants/overview"):
                return _FakeResp({"tenants": [{"id": tenant_id}]})
            if url.endswith("/devices"):
                return _FakeResp({"devices": devices})
            return _FakeResp({})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: False)

        dashboard._run_stale_digest_tick(now)

        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT last_stale_digest_sent_at FROM clients WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        assert row["last_stale_digest_sent_at"] is None, \
            "a failed send must not be recorded as delivered"


# ── The server constant maps 5 / 10 / 40 days to active / stale / silent ───────

def _server_bucket(days_ago):
    cfg = dashboard.DEVICE_FRESHNESS
    if days_ago < cfg["active_max_days"]:
        return "active"
    if days_ago < cfg["silent_min_days"]:
        return "stale"
    return "silent"


class TestBucketMapping:
    def test_5_10_40_map_consistently(self):
        assert _server_bucket(5) == "active"
        assert _server_bucket(10) == "stale"
        assert _server_bucket(40) == "silent"
