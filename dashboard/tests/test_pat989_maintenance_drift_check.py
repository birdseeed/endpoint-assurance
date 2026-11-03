"""
PAT-989: per-box patch/reboot/timer drift visibility.

Three production boxes (patched-prod-01, patched-api-01, patched-portal-01)
each run an hourly facts emitter (deploy/patched-maintenance-facts.sh and its
api-01/portal-01 equivalents) that writes a JSON snapshot of pending updates,
ESM/security status, reboot-required, and timer health to the identical
schema described in that script's header comment.

This covers the dashboard-side checker half:
  * _run_maintenance_drift_check_tick() reads all three sources (a local
    file for prod-01, since this process runs there; HTTP for api-01 and
    portal-01) and records three independent check_statuses rows --
    maintenance_prod01 / maintenance_api01 / maintenance_portal01 -- modeled
    directly on _run_deploy_drift_check_tick's tri-state discipline: every
    branch that cannot positively confirm health records unconfigured or
    degraded with a specific, distinguishable reason, never ok on partial
    information (PAT-992's core lesson, replicated here).
  * portal-01's facts arrive in a reduced shape (public /healthz cannot
    expose full per-timer/per-package detail -- see AGENTS.md) with
    *_count integers instead of the prod-01/api-01 timers/third_party_pending
    arrays. _maintenance_counts() normalizes both shapes so
    _maintenance_facts_degraded_reasons() -- the one shared "does this look
    degraded" decision -- is written once, not three times, and this test
    file exercises both shapes against the same trigger conditions to prove
    that.
  * The PAT-1045 shape every check in this file must not reproduce: a named
    check reading degraded while its tick_<label> heartbeat reads ok. Every
    degraded branch here must make _run_maintenance_drift_check_tick return
    a non-empty reason so _run_tick's wrapper heartbeat
    (tick_maintenance_drift_check) agrees with whichever named check(s) went
    degraded.
  * unconfigured (any of: unreachable, missing, unparseable JSON, or
    generated_at older than _MAINTENANCE_STALE_AFTER) is, by the convention
    already established for health_alert_delivery/portal_auth/deploy_drift,
    NOT itself a tick failure -- the tick heartbeat stays ok while the named
    check(s) read unconfigured.

Run with: pytest tests/test_pat989_maintenance_drift_check.py -v
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


class _FakeResp:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        return self._payload


def _iso(dt: datetime) -> str:
    """Match the real emitter's `date -u +%Y-%m-%dT%H:%M:%SZ` format."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _healthy_full_facts(generated_at: datetime) -> dict:
    """prod-01/api-01 shape: full timers + third_party_pending arrays."""
    return {
        "generated_at": _iso(generated_at),
        "hostname": "patched-prod-01",
        "pending_updates": 3,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "reboot_required": False,
        "running_kernel": "6.8.0-124-generic",
        "newest_kernel": "6.8.0-124-generic",
        "automatic_reboot_configured": True,
        "third_party_pending": [],
        "timers": [
            {
                "unit": "patched-dashboard-prune-reports.timer",
                "enabled": "enabled",
                "last_trigger": _iso(generated_at),
                "last_result": "success",
            },
        ],
    }


def _healthy_portal_facts(generated_at: datetime) -> dict:
    """portal-01 /healthz reduced shape: *_count integers, no arrays."""
    return {
        "generated_at": _iso(generated_at),
        "reboot_required": False,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "automatic_reboot_configured": True,
        "third_party_pending_count": 0,
        "timers_failed_count": 0,
        "timers_disabled_count": 0,
    }


def _write_local_facts(path, facts: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(facts))


def _install_http(
    monkeypatch,
    api_facts=None, api_status=200, api_exc=None,
    portal_body=None, portal_status=200, portal_exc=None,
):
    """Route dashboard.http.get() to the api-01 admin endpoint or portal-01's
    public /healthz based on URL, exactly like the real calls the tick makes."""

    def fake_get(url, timeout=None, verify=None):
        if url == f"{dashboard.PATCHED_API_INTERNAL}/admin/ops/maintenance":
            if api_exc is not None:
                raise api_exc
            return _FakeResp(api_facts, status_code=api_status)
        if url == "https://app.patched.im/healthz":
            if portal_exc is not None:
                raise portal_exc
            return _FakeResp(portal_body, status_code=portal_status)
        raise AssertionError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _run(monkeypatch, now, prod01_path):
    """Point MAINTENANCE_FACTS_FILE at prod01_path, call the tick function
    directly to capture its own return value (the reason string, or None),
    then also route it through _run_tick exactly as scheduler_loop registers
    it so tick_maintenance_drift_check gets recorded too. Both calls are
    idempotent (check_statuses upserts by name), so running the check twice
    is safe and lets one helper cover both assertions callers want."""
    monkeypatch.setattr(dashboard, "MAINTENANCE_FACTS_FILE", str(prod01_path))
    reason = dashboard._run_maintenance_drift_check_tick(now)
    dashboard._run_tick(
        "maintenance-drift-check",
        lambda: dashboard._run_maintenance_drift_check_tick(now),
        now,
    )
    return reason


# ── ok: all three boxes healthy ─────────────────────────────────────────────


def test_all_three_boxes_ok(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    assert _status("maintenance_prod01")["state"] == "ok"
    assert _status("maintenance_api01")["state"] == "ok"
    assert _status("maintenance_portal01")["state"] == "ok"
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


# ── degraded triggers: prod-01, full-detail shape ───────────────────────────

PROD01_DEGRADED_CASES = [
    pytest.param(lambda f: f.update(reboot_required=True), "reboot required", id="reboot_required"),
    pytest.param(lambda f: f.update(pro_attached=False), "Pro not attached", id="pro_not_attached"),
    pytest.param(lambda f: f.update(esm_updates=4), "ESM update", id="esm_updates_pending"),
    pytest.param(lambda f: f.update(security_updates=2), "security update", id="security_updates_pending"),
    pytest.param(
        lambda f: f.__setitem__("timers", [
            {"unit": "patched-x.timer", "enabled": "enabled", "last_trigger": None, "last_result": "failed"}
        ]),
        "failed",
        id="timer_failed",
    ),
    pytest.param(
        lambda f: f.__setitem__("timers", [
            {"unit": "patched-x.timer", "enabled": "disabled", "last_trigger": None, "last_result": "success"}
        ]),
        "unexpectedly disabled",
        id="timer_unexpectedly_disabled",
    ),
    pytest.param(
        lambda f: f.__setitem__("third_party_pending", [
            {"package": "docker-ce", "installed": "1", "candidate": "2", "origin": "download.docker.com"}
        ]),
        "third-party",
        id="third_party_pending",
    ),
]


@pytest.mark.parametrize("mutate,expected_substring", PROD01_DEGRADED_CASES)
def test_prod01_degraded_triggers(db, tmp_path, monkeypatch, mutate, expected_substring):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now)
    mutate(facts)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, facts)
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    reason = _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert expected_substring in row["reason"]
    # PAT-1045 shape guard: the tick heartbeat must not stay ok while a named
    # check reads degraded.
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"
    assert reason is not None


# ── degraded triggers: portal-01, counts-only shape drives the same states ──

PORTAL01_DEGRADED_CASES = [
    pytest.param(lambda f: f.update(reboot_required=True), "reboot required", id="reboot_required"),
    pytest.param(lambda f: f.update(pro_attached=False), "Pro not attached", id="pro_not_attached"),
    pytest.param(lambda f: f.update(esm_updates=4), "ESM update", id="esm_updates_pending"),
    pytest.param(lambda f: f.update(security_updates=2), "security update", id="security_updates_pending"),
    pytest.param(lambda f: f.update(timers_failed_count=1), "failed", id="timer_failed"),
    pytest.param(lambda f: f.update(timers_disabled_count=1), "unexpectedly disabled", id="timer_unexpectedly_disabled"),
    pytest.param(lambda f: f.update(third_party_pending_count=2), "third-party", id="third_party_pending"),
]


@pytest.mark.parametrize("mutate,expected_substring", PORTAL01_DEGRADED_CASES)
def test_portal01_counts_only_shape_drives_same_degraded_states(
    db, tmp_path, monkeypatch, mutate, expected_substring
):
    now = datetime.now(timezone.utc)
    portal_facts = _healthy_portal_facts(now)
    mutate(portal_facts)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": portal_facts},
    )

    reason = _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_portal01")
    assert row["state"] == "degraded"
    assert expected_substring in row["reason"]
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"
    assert reason is not None


# ── disabled declared timers fail closed ────────────────────────────────────────


def test_disabled_prod01_firewall_timer_triggers_degraded(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now)
    facts["timers"] = [
        {
            "unit": "hetzner-firewall-apply.timer",
            "enabled": "disabled",
            "last_trigger": None,
            "last_result": "unknown",
        },
    ]
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, facts)
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert "1 timer(s) unexpectedly disabled/not-found" in row["reason"]
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"


# ── unconfigured: prod-01 local file ────────────────────────────────────────


def test_prod01_missing_facts_file_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "does-not-exist.json"  # deliberately never written
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_prod01")
    assert row["state"] == "unconfigured"
    assert "does not exist" in row["reason"]
    # unconfigured is a standing gap, not a tick failure.
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


def test_prod01_unparseable_facts_file_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"
    prod01_path.write_text("not valid json at all {{{")
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_prod01")
    assert row["state"] == "unconfigured"
    assert "not valid JSON" in row["reason"]


def test_prod01_stale_facts_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    stale_generated_at = now - timedelta(hours=4)  # past _MAINTENANCE_STALE_AFTER (3h)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(stale_generated_at))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_prod01")
    assert row["state"] == "unconfigured"
    assert "stale" in row["reason"]
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


# ── unconfigured: api-01 HTTP fetch ─────────────────────────────────────────


def test_api01_unreachable_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_exc=ConnectionError("connection refused"),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_api01")
    assert row["state"] == "unconfigured"
    assert "unreachable" in row["reason"]
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


def test_api01_http_error_status_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_status=503,
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_api01")
    assert row["state"] == "unconfigured"
    assert "503" in row["reason"]


def test_api01_stale_facts_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    stale_generated_at = now - timedelta(hours=5)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(stale_generated_at),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_api01")
    assert row["state"] == "unconfigured"
    assert "stale" in row["reason"]


# ── unconfigured: portal-01 HTTP fetch ──────────────────────────────────────


def test_portal01_unreachable_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_exc=ConnectionError("connection refused"),
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_portal01")
    assert row["state"] == "unconfigured"
    assert "unreachable" in row["reason"]
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


def test_portal01_missing_maintenance_key_is_unconfigured(db, tmp_path, monkeypatch):
    """The public /healthz body must nest facts under "maintenance" -- a
    healthz body without it (e.g. an older portal build, or a genuine outage
    response) is a distinguishable, unparseable-shape error, not treated as
    an empty-but-healthy result."""
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok"},  # no "maintenance" key
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_portal01")
    assert row["state"] == "unconfigured"
    assert "maintenance" in row["reason"]


def test_portal01_stale_facts_is_unconfigured(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    stale_generated_at = now - timedelta(hours=6)
    prod01_path = tmp_path / "maintenance.json"
    _write_local_facts(prod01_path, _healthy_full_facts(now))
    _install_http(
        monkeypatch,
        api_facts=_healthy_full_facts(now),
        portal_body={"status": "ok", "maintenance": _healthy_portal_facts(stale_generated_at)},
    )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_portal01")
    assert row["state"] == "unconfigured"
    assert "stale" in row["reason"]


# ── all unconfigured -> tick heartbeat stays ok (not a tick failure) ───────


def test_all_three_unconfigured_tick_heartbeat_stays_ok(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "does-not-exist.json"
    _install_http(monkeypatch, api_exc=ConnectionError("refused"), portal_exc=ConnectionError("refused"))

    _run(monkeypatch, now, prod01_path)

    assert _status("maintenance_prod01")["state"] == "unconfigured"
    assert _status("maintenance_api01")["state"] == "unconfigured"
    assert _status("maintenance_portal01")["state"] == "unconfigured"
    assert _status("tick_maintenance_drift_check")["state"] == "ok"


# ── never ok without positive confirmation ──────────────────────────────────


@pytest.mark.parametrize("setup", ["missing", "stale", "unreachable"])
def test_never_reports_ok_without_positive_confirmation(db, tmp_path, monkeypatch, setup):
    now = datetime.now(timezone.utc)
    prod01_path = tmp_path / "maintenance.json"

    if setup == "missing":
        prod01_path = tmp_path / "does-not-exist.json"
        _install_http(
            monkeypatch,
            api_facts=_healthy_full_facts(now),
            portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
        )
    elif setup == "stale":
        _write_local_facts(prod01_path, _healthy_full_facts(now - timedelta(hours=10)))
        _install_http(
            monkeypatch,
            api_facts=_healthy_full_facts(now),
            portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
        )
    else:  # unreachable-equivalent: file present but unparseable
        prod01_path.write_text("{ garbage")
        _install_http(
            monkeypatch,
            api_facts=_healthy_full_facts(now),
            portal_body={"status": "ok", "maintenance": _healthy_portal_facts(now)},
        )

    _run(monkeypatch, now, prod01_path)

    row = _status("maintenance_prod01")
    assert row["state"] in ("unconfigured", "degraded")
    assert row["state"] != "ok"
