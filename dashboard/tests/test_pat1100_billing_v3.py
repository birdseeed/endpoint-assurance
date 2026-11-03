"""
Tests for PAT-1100 — billing v3 banded retainer model + time ledger.

Covers:
  - Band-lookup boundaries for both tiers (25/26, 60/61, 120/121, 250/251)
  - The tail-rate hand-off above 250 endpoints
  - Regression: two tenants at the same endpoint count on different tiers now
    bill DIFFERENT amounts (the actual defect this ticket fixes)
  - report-tier tenants compute to 0 without crashing
  - annual_discount applies BELOW the monthly headline, not above it
  - A v2-shaped stored `kv` row does not crash the Billing view; it falls
    back to v3 defaults
  - PATCH /admin/billing/rates persists a new band shape and validates it
  - time_ledger duration/class validation (400s)
  - service_integrity entries never move the advisory balance
  - The balance endpoint returns exactly the four documented fields
"""

import json
import os
from datetime import datetime, timedelta, timezone
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.content = b"x"

    def json(self):
        return self._payload


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(shared, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def _insert_client(tenant_id, billing_tier, company="Acme Corp"):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, tenant_id, company, billing_tier, created_at) VALUES (?,?,?,?,?)",
            (tenant_id, tenant_id, company, billing_tier, "2026-07-01T00:00:00Z"),
        )


# ── Band boundaries ──────────────────────────────────────────────────────────

class TestBandBoundaries:
    RATES = dashboard._default_billing_rates()

    @pytest.mark.parametrize("endpoints,expected_monthly,expected_hours", [
        (1,   500.0,  2),
        (25,  500.0,  2),
        (26,  750.0,  3),
        (60,  750.0,  3),
        (61,  1200.0, 4),
        (120, 1200.0, 4),
        (121, 2000.0, 6),
        (250, 2000.0, 6),
    ])
    def test_patch_band_boundaries(self, endpoints, expected_monthly, expected_hours):
        band = dashboard._billing_band_for(endpoints, self.RATES["bands"]["patch"])
        assert band["monthly"] == expected_monthly
        assert band["advisory_hours"] == expected_hours

    @pytest.mark.parametrize("endpoints,expected_monthly,expected_hours", [
        (1,   1500.0, 4),
        (60,  1500.0, 4),
        (61,  2600.0, 6),
        (120, 2600.0, 6),
        (121, 4200.0, 10),
        (250, 4200.0, 10),
    ])
    def test_full_band_boundaries(self, endpoints, expected_monthly, expected_hours):
        band = dashboard._billing_band_for(endpoints, self.RATES["bands"]["full"])
        assert band["monthly"] == expected_monthly
        assert band["advisory_hours"] == expected_hours

    def test_251_endpoints_falls_into_tail_territory_both_tiers(self):
        assert dashboard._billing_band_for(251, self.RATES["bands"]["patch"]) is None
        assert dashboard._billing_band_for(251, self.RATES["bands"]["full"]) is None

    def test_tail_rate_hand_off_patch(self):
        # >250 endpoints: monthly = endpoints * tail_rate, not the last band's monthly.
        monthly = dashboard._compute_monthly(300, "patch", "monthly", self.RATES)
        assert monthly == round(300 * 8.0, 2)
        assert monthly != 2000.0

    def test_tail_rate_hand_off_full(self):
        monthly = dashboard._compute_monthly(300, "full", "monthly", self.RATES)
        assert monthly == round(300 * 16.0, 2)
        assert monthly != 4200.0

    def test_251_boundary_is_strictly_above_top_band(self):
        # 250 is still in-band; 251 is the first tail-territory endpoint count.
        monthly_250 = dashboard._compute_monthly(250, "patch", "monthly", self.RATES)
        monthly_251 = dashboard._compute_monthly(251, "patch", "monthly", self.RATES)
        assert monthly_250 == 2000.0
        assert monthly_251 == round(251 * 8.0, 2)


# ── The actual regression this ticket fixes ─────────────────────────────────

class TestTierDifferentiationRegression:
    def test_same_endpoint_count_different_tiers_bill_differently(self):
        """The old model billed every tenant below the per-tier floor
        threshold the SAME £500, regardless of tier. This is the explicit
        regression test proving that defect is gone: two tenants with
        identical endpoint counts on different tiers must now bill
        DIFFERENT monthly amounts."""
        rates = dashboard._default_billing_rates()
        patch_monthly = dashboard._compute_monthly(20, "patch", "monthly", rates)
        full_monthly = dashboard._compute_monthly(20, "full", "monthly", rates)
        assert patch_monthly != full_monthly
        assert patch_monthly == 500.0
        assert full_monthly == 1500.0


# ── report tier ──────────────────────────────────────────────────────────────

class TestReportTier:
    def test_report_tier_computes_to_zero_without_crashing(self):
        rates = dashboard._default_billing_rates()
        assert dashboard._compute_monthly(50, "report", "monthly", rates) == 0.0
        assert dashboard._compute_monthly(50, "report", "annual", rates) == 0.0

    def test_billing_summary_does_not_crash_on_report_tier(self, client, monkeypatch):
        _insert_client("t-report", "report")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "t-report", "device_count": 50}]}),
        )
        r = client.get("/admin/billing/summary", headers=BEARER)
        assert r.status_code == 200
        row = [x for x in r.json()["rows"] if x["tenant_id"] == "t-report"][0]
        assert row["monthly"] == 0.0
        assert r.json()["total"] == 0.0


# ── annual discount direction ───────────────────────────────────────────────

class TestAnnualDiscountDirection:
    def test_annual_is_below_monthly_not_above(self):
        rates = dashboard._default_billing_rates()
        monthly = dashboard._compute_monthly(20, "patch", "monthly", rates)
        annual = dashboard._compute_monthly(20, "patch", "annual", rates)
        assert annual < monthly
        assert annual == round(monthly * 0.92, 2)

    def test_annual_discount_is_eight_percent_below(self):
        assert dashboard._BILLING_ANNUAL_DISCOUNT_DEFAULT == 0.92


# ── v2-shaped stored rates: must not crash, must fall back to v3 defaults ──

class TestV2StoredRatesFallback:
    def _store_v2_rates(self):
        v2 = {
            "report": 3.50, "patch": 7.50, "full": 15.00,
            "app_control": 3.50, "floor": 500.0, "monthly_uplift": 1.22,
        }
        with dashboard.get_db() as db:
            db.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?)",
                (dashboard._BILLING_RATES_KEY, json.dumps(v2), "2026-07-01T00:00:00Z"),
            )

    def test_billing_rates_falls_back_to_v3_defaults(self, client):
        self._store_v2_rates()
        rates = dashboard._billing_rates()
        assert rates == dashboard._default_billing_rates()

    def test_billing_view_does_not_crash_with_v2_stored_rates(self, client, monkeypatch):
        self._store_v2_rates()
        _insert_client("t-v2", "patch")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "t-v2", "device_count": 20}]}),
        )
        r = client.get("/admin/billing/summary", headers=BEARER)
        assert r.status_code == 200
        row = [x for x in r.json()["rows"] if x["tenant_id"] == "t-v2"][0]
        # v3 default patch band for 20 endpoints is £500; clients.billing_frequency
        # defaults to 'annual', so the 8%-below-monthly discount applies.
        assert row["monthly"] == round(500.0 * 0.92, 2)

        r2 = client.get("/admin/billing/rates", headers=BEARER)
        assert r2.status_code == 200
        assert r2.json() == dashboard._default_billing_rates()


# ── PATCH /admin/billing/rates: v3 band payload ─────────────────────────────

class TestBillingRatesPatchV3:
    def test_patch_updates_a_tier_band_list(self, client):
        new_patch_bands = [
            {"max_endpoints": 25, "monthly": 600.0, "advisory_hours": 2},
            {"max_endpoints": 60, "monthly": 900.0, "advisory_hours": 3},
        ]
        r = client.patch(
            "/admin/billing/rates",
            json={"bands": {"patch": new_patch_bands}},
            headers=BEARER,
        )
        assert r.status_code == 200
        rates = dashboard._billing_rates()
        assert rates["bands"]["patch"] == new_patch_bands
        # Untouched tier is unaffected.
        assert rates["bands"]["full"] == dashboard._BILLING_BAND_DEFAULTS["full"]

    def test_patch_rejects_non_increasing_band_boundaries(self, client):
        bad_bands = [
            {"max_endpoints": 60, "monthly": 900.0, "advisory_hours": 3},
            {"max_endpoints": 25, "monthly": 600.0, "advisory_hours": 2},
        ]
        r = client.patch(
            "/admin/billing/rates",
            json={"bands": {"patch": bad_bands}},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_patch_rejects_unknown_tier(self, client):
        r = client.patch(
            "/admin/billing/rates",
            json={"bands": {"report": []}},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_patch_updates_tail_rate(self, client):
        r = client.patch(
            "/admin/billing/rates",
            json={"tail_rate_per_endpoint": {"full": 20.0}},
            headers=BEARER,
        )
        assert r.status_code == 200
        rates = dashboard._billing_rates()
        assert rates["tail_rate_per_endpoint"]["full"] == 20.0
        assert rates["tail_rate_per_endpoint"]["patch"] == 8.0  # untouched

    def test_patch_rejects_annual_discount_above_one(self, client):
        # Non-author review finding (P1): an operator storing the OLD v2
        # monthly_uplift semantics (e.g. 1.22) into the new annual_discount
        # field would silently re-invert the exact defect this ticket fixes
        # — annual must be a discount BELOW monthly, never an uplift above
        # it. Only `>= 0` was previously enforced; must now reject `> 1`.
        r = client.patch(
            "/admin/billing/rates",
            json={"annual_discount": 1.22},
            headers=BEARER,
        )
        assert r.status_code == 400
        # And the stored rate card must be untouched by the rejected write.
        assert dashboard._billing_rates()["annual_discount"] == dashboard._BILLING_ANNUAL_DISCOUNT_DEFAULT

    def test_patch_rejects_annual_discount_zero(self, client):
        r = client.patch(
            "/admin/billing/rates",
            json={"annual_discount": 0},
            headers=BEARER,
        )
        assert r.status_code == 400


# ── time_ledger: duration + class validation ────────────────────────────────

class TestTimeLedgerValidation:
    def test_rejects_non_iso_entry_date(self, client):
        # Non-author review finding: the balance endpoint matches entries via
        # `entry_date LIKE '<YYYY-MM>%'` — a non-ISO date must be rejected
        # loudly rather than silently never counting toward any balance.
        for bad in ("11/08/2026", "August 11 2026", "2026-8-11", "not-a-date"):
            r = client.post(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
                json={"entry_date": bad, "duration_minutes": 30, "class": "advisory"},
                headers=BEARER,
            )
            assert r.status_code == 400, f"expected 400 for entry_date={bad!r}"

    def test_rejects_non_multiple_of_15(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-11", "duration_minutes": 20, "class": "advisory"},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_zero_and_negative_duration(self, client):
        for bad in (0, -15):
            r = client.post(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
                json={"entry_date": "2026-08-11", "duration_minutes": bad, "class": "advisory"},
                headers=BEARER,
            )
            assert r.status_code == 400

    def test_accepts_15_and_30(self, client):
        for good in (15, 30):
            r = client.post(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
                json={"entry_date": "2026-08-11", "duration_minutes": good, "class": "advisory"},
                headers=BEARER,
            )
            assert r.status_code == 200

    def test_rejects_bad_class(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-11", "duration_minutes": 30, "class": "bogus"},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_missing_class(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-11", "duration_minutes": 30},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_service_integrity_class_is_accepted(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-11", "duration_minutes": 30, "class": "service_integrity"},
            headers=BEARER,
        )
        assert r.status_code == 200

    def test_list_returns_created_entry_most_recent_first(self, client):
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-01", "duration_minutes": 15, "class": "advisory", "note": "first"},
            headers=BEARER,
        )
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-10", "duration_minutes": 30, "class": "advisory", "note": "second"},
            headers=BEARER,
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger", headers=BEARER)
        assert r.status_code == 200
        entries = r.json()["entries"]
        assert len(entries) == 2
        assert entries[0]["note"] == "second"


# ── Balance: the core safety property ───────────────────────────────────────

class TestTimeLedgerBalance:
    def test_service_integrity_never_moves_the_balance(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "device_count": 10}]}),
        )
        # patch tier, 10 endpoints -> band = {monthly:500, advisory_hours:2} -> 120 min allowance.
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": "2026-08-11", "duration_minutes": 9999 - (9999 % 15),
                  "class": "service_integrity"},
            headers=BEARER,
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger/balance", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        assert body["consumed_minutes"] == 0
        assert body["allowance_minutes"] == 120
        assert body["remaining_minutes"] == 120
        assert body["over_80_percent"] is False

    @staticmethod
    def _date_in_current_month(day: int = 11) -> str:
        """PAT-1513: the balance endpoint scopes to the current calendar month
        (`entry_date LIKE '<YYYY-MM>%'`), so a hardcoded date silently stops
        exercising this behaviour the moment the month rolls over. This test
        passed every day of August 2026 and began failing on 1 September for
        that reason, with no code change behind it."""
        return datetime.now(timezone.utc).strftime(f"%Y-%m-{day:02d}")

    @staticmethod
    def _date_in_previous_month(day: int = 11) -> str:
        now = datetime.now(timezone.utc)
        prev = now.replace(day=1) - timedelta(days=1)
        return prev.strftime(f"%Y-%m-{day:02d}")

    def test_advisory_entries_consume_the_balance(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "device_count": 10}]}),
        )
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": self._date_in_current_month(), "duration_minutes": 105,
                  "class": "advisory"},
            headers=BEARER,
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger/balance", headers=BEARER)
        body = r.json()
        assert body["consumed_minutes"] == 105
        assert body["allowance_minutes"] == 120
        assert body["remaining_minutes"] == 15
        assert body["over_80_percent"] is True  # 105/120 = 87.5%

    def test_previous_month_entries_do_not_consume_this_month_balance(self, client, monkeypatch):
        """The month boundary the endpoint implements, asserted in the other
        direction. Without this, nothing covers exclusion: the original test
        only ever passed because its hardcoded date happened to be in the
        current month, so the boundary was exercised by accident and then
        broke silently when the month changed (PAT-1513)."""
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "device_count": 10}]}),
        )
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger",
            json={"entry_date": self._date_in_previous_month(), "duration_minutes": 105,
                  "class": "advisory"},
            headers=BEARER,
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger/balance", headers=BEARER)
        body = r.json()
        assert body["consumed_minutes"] == 0
        assert body["remaining_minutes"] == 120
        assert body["over_80_percent"] is False

    def test_balance_response_shape_is_minimal(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "device_count": 10}]}),
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger/balance", headers=BEARER)
        assert set(r.json().keys()) == {
            "consumed_minutes", "allowance_minutes", "remaining_minutes", "over_80_percent",
        }

    def test_report_tier_tenant_has_zero_allowance_without_crashing(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "report")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": [{"id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "device_count": 10}]}),
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/time-ledger/balance", headers=BEARER)
        assert r.status_code == 200
        assert r.json()["allowance_minutes"] == 0

    def test_unknown_tenant_has_zero_consumed_and_zero_allowance(self, client, monkeypatch):
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **kw: _FakeResp({"tenants": []}),
        )
        r = client.get("/admin/tenants/24cc09de-1433-5b6d-b73e-e300523fea98/time-ledger/balance", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        assert body["consumed_minutes"] == 0
        assert body["allowance_minutes"] == 0
        assert body["over_80_percent"] is False
