"""
Tests for PAT-1103 — band drift watcher.

Ruling (2026-08-11, recorded on the ticket): "re-band at renewal only, both
directions" — a signed contract's price never changes mid-term regardless of
which way a tenant's live endpoint count has drifted relative to the band it
was signed at. Drift is purely advisory information fed into the renewal
conversation. This suite proves:

  - _tenant_band_drift() classifies direction (above/below/none) correctly
    at every band edge named in the ticket, for both billed tiers.
  - headroom_to_next_edge for each direction, including the tail-territory
    "no ceiling" case.
  - band_would_produce matches _compute_monthly() for the tenant's live
    endpoints (the same figure api_billing_renewals's current_band_monthly
    already computed pre-refactor).
  - The monthly scheduler tick (_run_band_drift_check_tick) is
    idempotent per tenant per calendar month.
  - _consecutive_drift_months() reflects TODAY's live direction, not a
    historical max streak.
  - GET /admin/billing/drift and the drift fields added to GET
    /admin/billing/renewals.
  - Nothing in this ticket ever writes billing_contracts — drift is
    read-only observability.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
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


def _insert_client(tenant_id, billing_tier, company="Acme Corp", billing_frequency="annual"):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, tenant_id, company, billing_tier, billing_frequency, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (tenant_id, tenant_id, company, billing_tier, billing_frequency, "2026-01-01T00:00:00Z"),
        )


def _mock_devices(monkeypatch, counts_by_tenant, names_by_tenant=None):
    names_by_tenant = names_by_tenant or {}
    tenants = [
        {"id": tid, "device_count": n, "name": names_by_tenant.get(tid)}
        for tid, n in counts_by_tenant.items()
    ]
    monkeypatch.setattr(
        dashboard.http, "get",
        lambda *a, **kw: _FakeResp({"tenants": tenants}),
    )


def _make_contract(client, monkeypatch, tenant_id, signature_endpoints, tier="patch",
                    frequency="monthly", term_start=None):
    _insert_client(tenant_id, tier)
    _mock_devices(monkeypatch, {tenant_id: signature_endpoints})
    body = {"tier_at_signature": tier, "billing_frequency": frequency}
    if term_start:
        body["term_start"] = term_start
    r = client.post(f"/admin/tenants/{tenant_id}/contracts", json=body, headers=BEARER)
    assert r.status_code == 200, r.text
    return r.json()


# ── _tenant_band_drift(): direction classification at named band edges ─────

class TestDriftDirectionAtBandEdges:
    """patch bands: [25, 60, 120, 250]; full bands: [60, 120, 250]. The
    ticket names 25/26, 60/61, 120/121, 250/251 as the edges to prove."""

    def _drift(self, tier, signature_endpoints, current_endpoints, frequency="monthly"):
        rates = dashboard._default_billing_rates()
        contract = {
            "tier_at_signature": tier,
            "billing_frequency": frequency,
            "band_endpoints_at_signature": signature_endpoints,
        }
        return dashboard._tenant_band_drift("0a4c2c91-7412-575c-b544-dea3a596dd31", current_endpoints, contract, rates)

    @pytest.mark.parametrize("edge", [25, 60, 120, 250])
    def test_patch_tier_crossing_up_at_each_edge_is_above(self, edge):
        d = self._drift("patch", edge, edge + 1)
        assert d["direction"] == "above"
        assert d["contracted_band_max"] == edge

    @pytest.mark.parametrize("edge", [25, 60, 120, 250])
    def test_patch_tier_staying_at_the_edge_is_none(self, edge):
        d = self._drift("patch", edge, edge)
        assert d["direction"] == "none"

    @pytest.mark.parametrize("edge", [60, 120, 250])
    def test_full_tier_crossing_up_at_each_edge_is_above(self, edge):
        d = self._drift("full", edge, edge + 1)
        assert d["direction"] == "above"
        assert d["contracted_band_max"] == edge

    @pytest.mark.parametrize("edge", [60, 120, 250])
    def test_full_tier_staying_at_the_edge_is_none(self, edge):
        d = self._drift("full", edge, edge)
        assert d["direction"] == "none"

    def test_dropping_below_the_signed_band_is_below(self):
        # Signed at 61 (band max 120), now at 60 (band max 60) -> below.
        d = self._drift("patch", 61, 60)
        assert d["direction"] == "below"
        assert d["contracted_band_max"] == 120

    def test_no_drift_within_the_same_band_is_none(self):
        d = self._drift("patch", 10, 20)  # both inside the 0-25 band
        assert d["direction"] == "none"

    def test_tail_territory_signature_has_no_contracted_band_max(self):
        # Signed at 300 (beyond every patch band) -> tail territory at
        # signature, so there's no "band max" to report.
        d = self._drift("patch", 300, 300)
        assert d["contracted_band_max"] is None
        assert d["direction"] == "none"

    def test_dropping_out_of_tail_territory_is_below(self):
        d = self._drift("patch", 300, 100)
        assert d["direction"] == "below"

    def test_climbing_further_into_tail_territory_is_none_not_above(self):
        # Already beyond every band at signature; drifting further up still
        # has "no higher band" to cross into, so this stays 'none' rather
        # than a meaningless 'above'.
        d = self._drift("patch", 300, 400)
        assert d["direction"] == "none"


# ── headroom_to_next_edge ────────────────────────────────────────────────

class TestHeadroomToNextEdge:
    def _drift(self, tier, signature_endpoints, current_endpoints):
        rates = dashboard._default_billing_rates()
        contract = {
            "tier_at_signature": tier,
            "billing_frequency": "monthly",
            "band_endpoints_at_signature": signature_endpoints,
        }
        return dashboard._tenant_band_drift("0a4c2c91-7412-575c-b544-dea3a596dd31", current_endpoints, contract, rates)

    def test_above_reports_room_left_to_grow_before_the_next_edge(self):
        # patch band max 60 is the current band's ceiling; at 26 endpoints
        # there's 34 endpoints of room before crossing it.
        d = self._drift("patch", 25, 26)
        assert d["direction"] == "above"
        assert d["headroom_to_next_edge"] == 60 - 26

    def test_above_in_tail_territory_has_no_ceiling(self):
        d = self._drift("patch", 250, 251)
        assert d["direction"] == "above"
        assert d["headroom_to_next_edge"] is None

    def test_below_reports_room_left_to_shrink_before_the_next_edge_down(self):
        # Signed at 61 (band max 120), now at 60 (band max 60, lower edge 25).
        d = self._drift("patch", 61, 60)
        assert d["direction"] == "below"
        assert d["headroom_to_next_edge"] == 60 - 25

    def test_none_reports_the_nearer_of_the_two_edges(self):
        # 10 endpoints, band (0, 25]: 15 room to grow, 10 room to shrink ->
        # nearer edge is 10.
        d = self._drift("patch", 10, 10)
        assert d["direction"] == "none"
        assert d["headroom_to_next_edge"] == 10


# ── band_would_produce matches _compute_monthly() exactly ──────────────────

class TestBandWouldProduceMatchesComputeMonthly:
    def test_matches_live_compute_monthly_for_the_same_inputs(self):
        rates = dashboard._default_billing_rates()
        contract = {
            "tier_at_signature": "full",
            "billing_frequency": "annual",
            "band_endpoints_at_signature": 50,
        }
        d = dashboard._tenant_band_drift("0a4c2c91-7412-575c-b544-dea3a596dd31", 90, contract, rates)
        expected = dashboard._compute_monthly(90, "full", "annual", rates)
        assert d["band_would_produce"] == expected


# ── Endpoint-counting: no second code path ──────────────────────────────────

class TestNoSecondEndpointCountingPath:
    def test_current_endpoints_is_whatever_the_caller_passed_in(self):
        # _tenant_band_drift never fetches endpoints itself -- it's purely a
        # function of the endpoints value its caller supplies, which is the
        # property that stops a second counting path existing at all.
        rates = dashboard._default_billing_rates()
        contract = {
            "tier_at_signature": "patch",
            "billing_frequency": "monthly",
            "band_endpoints_at_signature": 10,
        }
        d = dashboard._tenant_band_drift("0a4c2c91-7412-575c-b544-dea3a596dd31", 42, contract, rates)
        assert d["current_endpoints"] == 42


# ── Scheduler tick: monthly idempotency ─────────────────────────────────────

class TestBandDriftSchedulerTickIdempotent:
    def test_calling_twice_in_the_same_month_inserts_only_one_row_per_tenant(self, client, monkeypatch):
        _make_contract(client, monkeypatch, "0a4c2c91-7412-575c-b544-dea3a596dd31", 20)
        now = datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc)

        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 26})
        dashboard._run_band_drift_check_tick(now)
        dashboard._run_band_drift_check_tick(now)

        with dashboard.get_db() as db:
            rows = db.execute(
                "SELECT * FROM billing_drift_checks WHERE tenant_id=?", ("0a4c2c91-7412-575c-b544-dea3a596dd31",)
            ).fetchall()
        assert len(rows) == 1
        assert rows[0]["checked_month"] == "2026-08"
        assert rows[0]["direction"] == "above"
        assert rows[0]["endpoints"] == 26

    def test_calling_in_a_later_month_inserts_a_second_row(self, client, monkeypatch):
        _make_contract(client, monkeypatch, "0a4c2c91-7412-575c-b544-dea3a596dd31", 20)
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})
        dashboard._run_band_drift_check_tick(datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc))
        dashboard._run_band_drift_check_tick(datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc))

        with dashboard.get_db() as db:
            rows = db.execute(
                "SELECT checked_month FROM billing_drift_checks WHERE tenant_id=? ORDER BY checked_month",
                ("0a4c2c91-7412-575c-b544-dea3a596dd31",),
            ).fetchall()
        assert [r["checked_month"] for r in rows] == ["2026-08", "2026-09"]

    def test_tick_never_writes_billing_contracts(self, client, monkeypatch):
        contract = _make_contract(client, monkeypatch, "0a4c2c91-7412-575c-b544-dea3a596dd31", 20)
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 90})  # well above the signed band
        dashboard._run_band_drift_check_tick(datetime(2026, 8, 15, tzinfo=timezone.utc))

        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT monthly_at_signature FROM billing_contracts WHERE id=?", (contract["id"],)
            ).fetchone()
        # Advisory only: the frozen contracted figure must be completely
        # unaffected by the tick, no matter how far endpoints have drifted.
        assert row["monthly_at_signature"] == contract["monthly_at_signature"]

    def test_only_tenants_with_active_contracts_get_a_row(self, client, monkeypatch):
        _insert_client("t-no-contract", "patch")
        _mock_devices(monkeypatch, {"t-no-contract": 20})
        dashboard._run_band_drift_check_tick(datetime(2026, 8, 15, tzinfo=timezone.utc))
        with dashboard.get_db() as db:
            rows = db.execute("SELECT * FROM billing_drift_checks").fetchall()
        assert rows == []


# ── _consecutive_drift_months(): current streak, not historical max ────────

class TestConsecutiveDriftMonths:
    def _seed(self, tenant_id, month_direction_pairs):
        with dashboard.get_db() as db:
            for month, direction in month_direction_pairs:
                db.execute(
                    "INSERT INTO billing_drift_checks "
                    "(id, tenant_id, checked_month, direction, endpoints, band_would_produce, checked_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (f"row-{tenant_id}-{month}", tenant_id, month, direction, 30, 500.0,
                     "2026-01-01T00:00:00Z"),
                )

    def test_no_history_gives_a_zero_streak(self, client):
        assert dashboard._consecutive_drift_months("t-fresh", "above") == 0

    def test_three_consecutive_matching_months_gives_a_streak_of_three(self, client):
        self._seed("0a4c2c91-7412-575c-b544-dea3a596dd31", [("2026-06", "above"), ("2026-07", "above"), ("2026-08", "above")])
        assert dashboard._consecutive_drift_months("0a4c2c91-7412-575c-b544-dea3a596dd31", "above") == 3

    def test_streak_stops_at_the_first_mismatch_walking_backward(self, client):
        self._seed("0a4c2c91-7412-575c-b544-dea3a596dd31", [("2026-05", "none"), ("2026-06", "above"), ("2026-07", "above"), ("2026-08", "above")])
        assert dashboard._consecutive_drift_months("0a4c2c91-7412-575c-b544-dea3a596dd31", "above") == 3

    def test_drifted_above_for_three_months_then_back_to_none_today_streak_reflects_today(self, client):
        # The exact scenario named in the ticket: 'above' for 3 recorded
        # months, but the tenant's LIVE direction today is 'none' (this
        # month's row not yet recorded). The streak for 'none' must NOT be
        # the historical 3-month 'above' run -- it's 0, because the most
        # recently recorded month ('above') doesn't match 'none'.
        self._seed("0a4c2c91-7412-575c-b544-dea3a596dd31", [("2026-06", "above"), ("2026-07", "above"), ("2026-08", "above")])
        assert dashboard._consecutive_drift_months("0a4c2c91-7412-575c-b544-dea3a596dd31", "none") == 0
        # And querying the OLD direction still correctly reports the streak
        # that direction actually has (3), proving this isn't just always 0.
        assert dashboard._consecutive_drift_months("0a4c2c91-7412-575c-b544-dea3a596dd31", "above") == 3

    def test_this_months_row_already_recorded_as_none_gives_streak_of_one(self, client):
        self._seed("0a4c2c91-7412-575c-b544-dea3a596dd31", [("2026-06", "above"), ("2026-07", "above"), ("2026-08", "none")])
        assert dashboard._consecutive_drift_months("0a4c2c91-7412-575c-b544-dea3a596dd31", "none") == 1


# ── GET /admin/billing/drift ─────────────────────────────────────────────

class TestBillingDriftEndpoint:
    def test_shows_every_tenant_with_an_active_contract_not_just_renewal_window(self, client, monkeypatch):
        # Renewal far in the future -- outside api_billing_renewals' 60-day
        # window -- but still an active contract, so it belongs here.
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 26})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly", "term_length_months": 36},
            headers=BEARER,
        )
        assert r.status_code == 200

        rows = client.get("/admin/billing/drift", headers=BEARER).json()["rows"]
        assert any(row["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31" for row in rows)

        renewal_rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        assert not any(row["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31" for row in renewal_rows)

    def test_row_shape_and_direction_value(self, client, monkeypatch):
        _make_contract(client, monkeypatch, "0a4c2c91-7412-575c-b544-dea3a596dd31", 25, tier="patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 61})  # now well into the next band
        rows = client.get("/admin/billing/drift", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["direction"] == "above"
        assert row["endpoints"] == 61
        assert row["contracted_band_max"] == 25
        assert row["band_would_produce"] == dashboard._compute_monthly(
            61, "patch", "monthly", dashboard._default_billing_rates()
        )
        assert "headroom_to_next_edge" in row
        assert "consecutive_months_drifted" in row

    def test_tenants_with_no_drift_still_appear(self, client, monkeypatch):
        _make_contract(client, monkeypatch, "0a4c2c91-7412-575c-b544-dea3a596dd31", 20)
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})  # unchanged -> direction 'none'
        rows = client.get("/admin/billing/drift", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["direction"] == "none"

    def test_tenant_without_an_active_contract_is_absent(self, client, monkeypatch):
        _insert_client("t-no-contract", "patch")
        _mock_devices(monkeypatch, {"t-no-contract": 20})
        rows = client.get("/admin/billing/drift", headers=BEARER).json()["rows"]
        assert not any(r["tenant_id"] == "t-no-contract" for r in rows)


# ── GET /admin/billing/renewals: additive drift fields ──────────────────────

class TestRenewalsCarriesDriftFields:
    def test_renewals_row_includes_drift_fields_alongside_the_existing_delta(self, client, monkeypatch):
        renewal_date = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
        term_start = dashboard._add_months(renewal_date, -12)
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={
                "tier_at_signature": "patch", "billing_frequency": "monthly",
                "term_start": term_start, "term_length_months": 12,
            },
            headers=BEARER,
        )
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 61})  # drifted up a band
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        # Existing PAT-1101 fields untouched.
        assert row["contracted_monthly"] == 500.0
        assert row["current_band_monthly"] == 1200.0
        assert row["delta"] == 700.0
        # New PAT-1103 fields present and consistent with the delta above.
        assert row["drift_direction"] == "above"
        assert row["drift_contracted_band_max"] == 25
        assert row["drift_headroom_to_next_edge"] == 120 - 61  # room to the next edge (120) from 61
        assert row["drift_consecutive_months"] == 0  # no scheduler history seeded


# ── Nothing here writes billing_contracts (advisory-only) ───────────────────

class TestAdvisoryOnly:
    def test_get_drift_endpoint_never_mutates_the_contract(self, client, monkeypatch):
        contract = _make_contract(client, monkeypatch, "0a4c2c91-7412-575c-b544-dea3a596dd31", 20)
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 200})
        client.get("/admin/billing/drift", headers=BEARER)
        client.get("/admin/billing/renewals", headers=BEARER)
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT monthly_at_signature, band_endpoints_at_signature FROM billing_contracts WHERE id=?",
                (contract["id"],),
            ).fetchone()
        assert row["monthly_at_signature"] == contract["monthly_at_signature"]
        assert row["band_endpoints_at_signature"] == contract["band_endpoints_at_signature"]
