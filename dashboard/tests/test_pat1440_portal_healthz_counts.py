"""PAT-1440: teach _stray_config_backup_findings/_systemd_hardening_findings
to accept portal-01's counts-only /healthz shape, alongside the full-array
shape prod-01/api-01 already hand over.

Context: stray_config_backups (PAT-1431/1433) and systemd_hardening
(PAT-1237) reached prod-01/api-01's maintenance_* rows the day each was
added, but never portal-01's -- portal's _maintenance_info() built an
explicit allowlist dict and silently dropped both fields (see portal's
tests/test_pat1440_healthz_projection_parity.py for the fix on that side).
This file is the dashboard-side half: portal now hands over
`stray_config_backups_count`/`_readable_count`/`_unknown_count` and
`systemd_hardening_available`/`_over_ceiling_count`/`_unclassified_count`/
`_unjudged_count` instead of the full arrays, and _stray_config_backup_
findings/_systemd_hardening_findings must normalise that shape into the
same (degraded_reasons, info_note) decision the full shape already
produces -- same discipline _maintenance_counts() already established for
timers/third_party_pending.

The property that must not be lost, across BOTH fields: three states stay
distinguishable --

  1. field genuinely absent (an emitter that predates it)      -> "not reported"
  2. systemd-analyze reported unavailable                       -> "not available"
  3. a real scan/count that is genuinely zero                   -> "none found" / clean

Collapsing (1) and (3) into a bare 0 is exactly the "unknown reads as
clean" failure PAT-912/837/960 already caught this estate doing elsewhere
-- see root AGENTS.md. This file proves it wasn't reintroduced at the
counts-shape boundary.

Run with: pytest tests/test_pat1440_portal_healthz_counts.py -v
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


# ═════════════════════════════════════════════════════════════════════════
# Part 1: _stray_config_backup_findings, counts shape
# ═════════════════════════════════════════════════════════════════════════


def test_stray_counts_absent_is_not_reported_not_clean():
    """No stray_config_backups[_count] key at all -- an emitter (of either
    shape) that predates the field. Must not be confused with a clean
    zero-count scan."""
    degraded, info = dashboard._stray_config_backup_findings({"generated_at": "x"})
    assert degraded == []
    assert "not reported" in info
    assert "none found" not in info


def test_stray_counts_zero_total_is_clean_and_distinct_from_absent():
    degraded, info = dashboard._stray_config_backup_findings(
        {
            "stray_config_backups_count": 0,
            "stray_config_backups_readable_count": 0,
            "stray_config_backups_unknown_count": 0,
        }
    )
    assert degraded == []
    assert "none found" in info
    assert "not reported" not in info


def test_stray_counts_readable_is_degraded_without_naming_a_path():
    degraded, info = dashboard._stray_config_backup_findings(
        {
            "stray_config_backups_count": 2,
            "stray_config_backups_readable_count": 1,
            "stray_config_backups_unknown_count": 0,
        }
    )
    assert len(degraded) == 1
    assert "1 stray config backup" in degraded[0]
    assert "readable beyond owner" in degraded[0]
    # No absolute path or filename leaks -- the counts shape never had one
    # to leak, but a naive implementation could still stringify the raw
    # dict and accidentally include one.
    assert "/etc" not in degraded[0]
    assert ".bak" not in degraded[0]
    assert ".pre-" not in degraded[0]


def test_stray_counts_unknown_mode_is_degraded_fail_closed():
    degraded, info = dashboard._stray_config_backup_findings(
        {
            "stray_config_backups_count": 1,
            "stray_config_backups_readable_count": 0,
            "stray_config_backups_unknown_count": 1,
        }
    )
    assert len(degraded) == 1
    assert "could not be determined" in degraded[0]
    assert "readable beyond owner" not in degraded[0]


def test_stray_counts_root_only_is_reported_but_not_degraded():
    degraded, info = dashboard._stray_config_backup_findings(
        {
            "stray_config_backups_count": 3,
            "stray_config_backups_readable_count": 0,
            "stray_config_backups_unknown_count": 0,
        }
    )
    assert degraded == []
    assert "3 root-only 0600" in info
    assert "not a permission leak" in info


def test_stray_counts_malformed_value_fails_closed_to_not_reported():
    """A present-but-unparseable count from a buggy emitter must not be
    silently treated as 0 -- same _as_count discipline every other malformed
    numeric maintenance field already gets."""
    degraded, info = dashboard._stray_config_backup_findings(
        {"stray_config_backups_count": "not-a-number"}
    )
    assert degraded == []
    assert "not reported" in info


def test_stray_counts_full_shape_still_takes_priority_over_counts_shape():
    """If a facts dict somehow carried both keys (shouldn't happen in
    practice -- each box reports one shape or the other), the full array is
    the richer source of truth and must win."""
    facts = {
        "stray_config_backups": [
            {
                "path": "/etc/patched-dashboard/x.env.bak-pat1",
                "mode": "0640",
                "owner": "root",
                "group": "www-data",
                "group_readable": True,
                "world_readable": False,
                "mode_unknown": False,
            }
        ],
        "stray_config_backups_count": 99,
        "stray_config_backups_readable_count": 99,
        "stray_config_backups_unknown_count": 99,
    }
    degraded, info = dashboard._stray_config_backup_findings(facts)
    assert len(degraded) == 1
    assert "x.env.bak-pat1" in degraded[0]  # the full-shape path, not "99"


# ═════════════════════════════════════════════════════════════════════════
# Part 2: _systemd_hardening_findings, counts shape
# ═════════════════════════════════════════════════════════════════════════


def test_hardening_counts_absent_is_not_reported_not_clean():
    degraded, info = dashboard._systemd_hardening_findings({"generated_at": "x"})
    assert degraded == []
    assert "not reported" in info
    assert "not available" not in info


def test_hardening_counts_unavailable_is_distinct_from_clean_scan():
    """systemd_hardening_available: false must read as unknown/unavailable,
    never as 'scanned, zero units over ceiling' -- the exact distinction the
    ticket brief calls out as the property most at risk of being lost."""
    degraded, info = dashboard._systemd_hardening_findings(
        {"systemd_hardening_available": False}
    )
    assert degraded == []
    assert "not available" in info
    assert "none over ceiling" not in info
    assert "0 unit" not in info


def test_hardening_counts_available_true_all_zero_is_clean():
    degraded, info = dashboard._systemd_hardening_findings(
        {
            "systemd_hardening_available": True,
            "systemd_hardening_over_ceiling_count": 0,
            "systemd_hardening_unclassified_count": 0,
            "systemd_hardening_unjudged_count": 0,
        }
    )
    assert degraded == []
    assert "0 unit(s) over ceiling" in info
    assert "not available" not in info
    assert "not reported" not in info


def test_hardening_counts_over_ceiling_is_degraded_without_naming_a_unit():
    degraded, info = dashboard._systemd_hardening_findings(
        {
            "systemd_hardening_available": True,
            "systemd_hardening_over_ceiling_count": 1,
            "systemd_hardening_unclassified_count": 0,
            "systemd_hardening_unjudged_count": 0,
        }
    )
    assert len(degraded) == 1
    assert "1 unit(s) over their hardening ceiling" in degraded[0]
    assert ".service" not in degraded[0]


def test_hardening_counts_unclassified_is_degraded_checked_independently():
    degraded, info = dashboard._systemd_hardening_findings(
        {
            "systemd_hardening_available": True,
            "systemd_hardening_over_ceiling_count": 0,
            "systemd_hardening_unclassified_count": 1,
            "systemd_hardening_unjudged_count": 0,
        }
    )
    assert len(degraded) == 1
    assert "unclassified" in degraded[0]


def test_hardening_counts_unjudged_is_degraded():
    degraded, info = dashboard._systemd_hardening_findings(
        {
            "systemd_hardening_available": True,
            "systemd_hardening_over_ceiling_count": 0,
            "systemd_hardening_unclassified_count": 0,
            "systemd_hardening_unjudged_count": 1,
        }
    )
    assert len(degraded) == 1
    assert "could not be judged" in degraded[0]


def test_hardening_counts_malformed_value_fails_closed_to_not_reported():
    degraded, info = dashboard._systemd_hardening_findings(
        {"systemd_hardening_available": True, "systemd_hardening_over_ceiling_count": "oops"}
    )
    assert degraded == []
    assert "not reported" in info


def test_hardening_counts_full_shape_still_takes_priority_over_counts_shape():
    facts = {
        "systemd_hardening": {
            "available": True,
            "units": [
                {
                    "unit": "patched-portal.service",
                    "score": 7.2,
                    "rating": "EXPOSED",
                    "class": "network-facing",
                    "ceiling": 6.0,
                    "over_ceiling": True,
                }
            ],
        },
        "systemd_hardening_available": True,
        "systemd_hardening_over_ceiling_count": 0,
        "systemd_hardening_unclassified_count": 0,
        "systemd_hardening_unjudged_count": 0,
    }
    degraded, info = dashboard._systemd_hardening_findings(facts)
    assert len(degraded) == 1
    assert "patched-portal.service" in degraded[0]


# ═════════════════════════════════════════════════════════════════════════
# Part 3: integration -- wired through maintenance_portal01, no leakage
# ═════════════════════════════════════════════════════════════════════════


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
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _healthy_full_facts(generated_at: datetime) -> dict:
    """prod-01/api-01 shape, trivially healthy and field-complete -- these
    two boxes aren't under test here, only portal-01's counts shape is."""
    return {
        "generated_at": _iso(generated_at),
        "hostname": "patched-prod-01",
        "pending_updates": 0,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "reboot_required": False,
        "running_kernel": "6.8.0-124-generic",
        "newest_kernel": "6.8.0-124-generic",
        "automatic_reboot_configured": True,
        "third_party_pending": [],
        "timers": [],
    }


def _portal_counts_maintenance(generated_at: datetime, **overrides) -> dict:
    """portal-01's real reduced /healthz "maintenance" shape (PAT-1440) --
    every field _maintenance_info() in the portal repo now produces for a
    healthy, fully-reporting box."""
    maint = {
        "generated_at": _iso(generated_at),
        "reboot_required": False,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "automatic_reboot_configured": True,
        "third_party_pending_count": 0,
        "timers_failed_count": 0,
        "timers_disabled_count": 0,
        "stray_config_backups_count": 0,
        "stray_config_backups_readable_count": 0,
        "stray_config_backups_unknown_count": 0,
        "systemd_hardening_available": True,
        "systemd_hardening_over_ceiling_count": 0,
        "systemd_hardening_unclassified_count": 0,
        "systemd_hardening_unjudged_count": 0,
    }
    maint.update(overrides)
    return maint


def _run_with_portal_maintenance(monkeypatch, tmp_path, now, portal_maint):
    prod01_path = tmp_path / "maintenance.json"
    prod01_path.write_text(json.dumps(_healthy_full_facts(now)))
    monkeypatch.setattr(dashboard, "MAINTENANCE_FACTS_FILE", str(prod01_path))

    def fake_get(url, timeout=None, verify=None):
        if url == f"{dashboard.PATCHED_API_INTERNAL}/admin/ops/maintenance":
            return _FakeResp(_healthy_full_facts(now), status_code=200)
        if url == "https://app.patched.im/healthz":
            return _FakeResp({"status": "ok", "maintenance": portal_maint}, status_code=200)
        raise AssertionError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    # Mirrors test_pat1408_stray_config_backups.py's `_run`: call the tick
    # directly to capture its return value, then also route it through
    # _run_tick exactly as scheduler_loop registers it, so
    # tick_maintenance_drift_check gets recorded too. Both are idempotent
    # (check_statuses upserts by name).
    reason = dashboard._run_maintenance_drift_check_tick(now)
    dashboard._run_tick(
        "maintenance-drift-check",
        lambda: dashboard._run_maintenance_drift_check_tick(now),
        now,
    )
    return reason


def test_portal01_reduced_counts_over_ceiling_and_readable_stray_degrades_row(
    db, tmp_path, monkeypatch
):
    now = datetime.now(timezone.utc)
    portal_maint = _portal_counts_maintenance(
        now,
        stray_config_backups_count=1,
        stray_config_backups_readable_count=1,
        systemd_hardening_over_ceiling_count=1,
    )
    _run_with_portal_maintenance(monkeypatch, tmp_path, now, portal_maint)

    row = _status("maintenance_portal01")
    assert row["state"] == "degraded"
    assert "readable beyond owner" in row["reason"]
    assert "over their hardening ceiling" in row["reason"]
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"


def test_portal01_reduced_counts_all_clean_is_ok(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    portal_maint = _portal_counts_maintenance(now)
    _run_with_portal_maintenance(monkeypatch, tmp_path, now, portal_maint)

    row = _status("maintenance_portal01")
    assert row["state"] == "ok"
    assert "none found" in row["reason"]
    assert "0 unit(s) over ceiling" in row["reason"]


def test_portal01_reduced_counts_absent_fields_read_as_not_reported(db, tmp_path, monkeypatch):
    """Simulates portal-01 running an emitter/portal build that predates
    PAT-1440 -- both fields' keys are simply missing from the maintenance
    object, exactly as they were before this ticket. Must never be
    misread as a confirmed-clean scan."""
    now = datetime.now(timezone.utc)
    portal_maint = _portal_counts_maintenance(now)
    for key in list(portal_maint):
        if key.startswith("stray_config_backups") or key.startswith("systemd_hardening"):
            del portal_maint[key]

    _run_with_portal_maintenance(monkeypatch, tmp_path, now, portal_maint)

    row = _status("maintenance_portal01")
    assert row["state"] == "ok"
    assert "stray config backups: not reported by this emitter" in row["reason"]
    assert "systemd hardening: not reported by this emitter" in row["reason"]


def test_portal01_systemd_hardening_unavailable_is_reported_not_hidden(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    portal_maint = _portal_counts_maintenance(now)
    portal_maint["systemd_hardening_available"] = False
    for key in (
        "systemd_hardening_over_ceiling_count",
        "systemd_hardening_unclassified_count",
        "systemd_hardening_unjudged_count",
    ):
        del portal_maint[key]

    _run_with_portal_maintenance(monkeypatch, tmp_path, now, portal_maint)

    row = _status("maintenance_portal01")
    assert row["state"] == "ok"
    assert "systemd hardening: not available on this box" in row["reason"]


def test_portal01_reduced_counts_never_leak_paths_filenames_or_unit_names(
    db, tmp_path, monkeypatch
):
    """The whole reason this reduction exists: /healthz is unauthenticated,
    so nothing that reaches maintenance_portal01's stored reason via that
    route may ever contain a filesystem path, a stray's filename, or a
    systemd unit name -- those are exactly what the counts-only shape is
    designed to withhold. Prove it holds for the degraded path, which is
    the one most likely to accidentally interpolate raw identifying detail."""
    now = datetime.now(timezone.utc)
    portal_maint = _portal_counts_maintenance(
        now,
        stray_config_backups_count=2,
        stray_config_backups_readable_count=1,
        stray_config_backups_unknown_count=1,
        systemd_hardening_over_ceiling_count=1,
        systemd_hardening_unclassified_count=1,
        systemd_hardening_unjudged_count=1,
    )
    _run_with_portal_maintenance(monkeypatch, tmp_path, now, portal_maint)

    row = _status("maintenance_portal01")
    reason = row["reason"]
    assert reason  # sanity: something was actually recorded
    for leaky in (
        "/etc/",
        ".bak",
        ".pre-",
        ".service",
        ".timer",
        "patched-portal",
        "patched-dashboard",
        "patched-api",
    ):
        assert leaky not in reason, f"{leaky!r} leaked into maintenance_portal01's reason"
