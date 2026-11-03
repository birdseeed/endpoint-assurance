"""
Tests for PAT-1101 — contract & term record + renewal prompt.

Covers:
  - Contract creation freezes the correct figures (band lookup, advisory
    hours, renewal date) from the CURRENT band table at creation time.
  - THE core regression this ticket exists to prevent: changing the stored
    band table does NOT alter an existing tenant's billed figure once they
    have an active contract — api_billing_summary must keep returning
    monthly_at_signature, not a live _compute_monthly() recalculation.
  - The one-active-contract-per-tenant constraint (reject vs. explicit
    ?supersede=true).
  - GET .../contracts and .../contracts/active.
  - GET /admin/billing/renewals: the 60-day window (just inside, just
    outside, and past/overdue), the contracted-vs-current-band delta, and
    mean/peak/over-allowance advisory-class consumption stats, with
    service_integrity entries proven excluded.
  - _add_months() day-clamping edge case.
"""

import os
import sqlite3
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
    """counts_by_tenant: {tenant_id: device_count}"""
    names_by_tenant = names_by_tenant or {}
    tenants = [
        {"id": tid, "device_count": n, "name": names_by_tenant.get(tid)}
        for tid, n in counts_by_tenant.items()
    ]
    monkeypatch.setattr(
        dashboard.http, "get",
        lambda *a, **kw: _FakeResp({"tenants": tenants}),
    )


def _iso_date(days_from_now):
    return (datetime.now(timezone.utc) + timedelta(days=days_from_now)).strftime("%Y-%m-%d")


# ── _add_months() ────────────────────────────────────────────────────────────

class TestAddMonths:
    def test_simple_addition(self):
        assert dashboard._add_months("2026-01-15", 12) == "2027-01-15"

    def test_clamps_day_when_target_month_is_shorter(self):
        # Jan 31 + 1 month -> Feb has no 31st -> clamp to Feb 28 (2026 not a leap year).
        assert dashboard._add_months("2026-01-31", 1) == "2026-02-28"

    def test_clamps_to_leap_day(self):
        assert dashboard._add_months("2028-01-31", 1) == "2028-02-29"  # 2028 IS a leap year

    def test_crosses_year_boundary(self):
        assert dashboard._add_months("2026-11-01", 3) == "2027-02-01"


# ── Table-name collision (real production incident) ────────────────────────
#
# The first PAT-1101 deploy crashed on patched-prod-01: dashboard.db is
# shared with the unrelated Jarvis Job Scout bot, which already owns a table
# literally named `contracts` (job-application tracking — role_id, client,
# agency, day_rate...). `CREATE TABLE IF NOT EXISTS contracts (...)` silently
# no-op'd against that pre-existing, differently-shaped table, then
# `CREATE INDEX ...(tenant_id)` crashed with "no such column: tenant_id" —
# init_db() raised, the app failed to start, and the deploy auto-rolled-back.
# No local test caught this because every local test DB starts empty. This
# test reproduces the exact production precondition: a pre-existing,
# differently-shaped `contracts` table already present before init_db() runs.

class TestBillingContractsDoesNotCollideWithUnrelatedContractsTable:
    def test_init_db_survives_a_pre_existing_unrelated_contracts_table(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(shared, "DB_PATH", db_path)
        monkeypatch.setattr(dashboard, "DB_PATH", db_path)

        # Simulate Jarvis's pre-existing table shape (abbreviated — the exact
        # columns don't matter, only that `tenant_id` is absent, which is
        # what crashed the real deploy).
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE contracts (
                role_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                client TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Pending'
            )
        """)
        conn.commit()
        conn.close()

        # Must not raise — this is the literal call that crashed in prod.
        dashboard.init_db()

        with dashboard.get_db() as db:
            # The unrelated table is untouched.
            jarvis_cols = {r[1] for r in db.execute("PRAGMA table_info(contracts)").fetchall()}
            assert "role_id" in jarvis_cols
            assert "tenant_id" not in jarvis_cols
            # Our table exists under its own name, unaffected by the collision.
            billing_cols = {r[1] for r in db.execute("PRAGMA table_info(billing_contracts)").fetchall()}
            assert "tenant_id" in billing_cols
            assert "monthly_at_signature" in billing_cols

    def test_contract_creation_works_alongside_the_unrelated_contracts_table(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(shared, "DB_PATH", db_path)
        monkeypatch.setattr(dashboard, "DB_PATH", db_path)
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE contracts (role_id TEXT PRIMARY KEY, title TEXT NOT NULL)")
        conn.commit()
        conn.close()
        dashboard.init_db()

        with TestClient(dashboard.app) as test_client:
            _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
            _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})
            r = test_client.post(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
                json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
                headers=BEARER,
            )
            assert r.status_code == 200


# ── Contract creation freezes correct figures ───────────────────────────────

class TestContractCreation:
    def test_rejects_nonexistent_tenant(self, client, monkeypatch):
        # Non-author review finding: without this check a typo'd tenant_id
        # would still succeed and freeze phantom figures onto a contract row.
        _mock_devices(monkeypatch, {"24cc09de-1433-5b6d-b73e-e300523fea98": 20})
        r = client.post(
            "/admin/tenants/24cc09de-1433-5b6d-b73e-e300523fea98/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r.status_code == 404

    def test_freezes_band_figures_from_current_table(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})  # patch band for 20 -> £500, 2h
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"
        assert body["tier_at_signature"] == "patch"
        assert body["band_endpoints_at_signature"] == 20
        assert body["monthly_at_signature"] == 500.0
        assert body["advisory_hours_at_signature"] == 2
        assert body["billing_frequency"] == "monthly"
        assert body["annual_discount_at_signature"] is None
        assert body["status"] == "active"
        assert body["term_length_months"] == 12
        assert body["term_start"]
        assert body["renewal_date"] == dashboard._add_months(body["term_start"], 12)

    def test_annual_frequency_applies_discount_and_records_it(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "annual"},
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["monthly_at_signature"] == round(500.0 * 0.92, 2)
        assert body["annual_discount_at_signature"] == 0.92

    def test_custom_term_length_computes_renewal_date(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "full")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={
                "tier_at_signature": "full", "billing_frequency": "monthly",
                "term_start": "2026-01-31", "term_length_months": 1,
            },
            headers=BEARER,
        )
        assert r.status_code == 200
        assert r.json()["renewal_date"] == "2026-02-28"

    def test_tail_territory_advisory_hours_is_zero_not_invented(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 300})  # beyond top band -> tail territory
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["advisory_hours_at_signature"] == 0.0
        assert body["monthly_at_signature"] == round(300 * 8.0, 2)

    def test_rejects_report_tier(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "report")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "report", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_bad_billing_frequency(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "quarterly"},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_non_positive_term_length(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly", "term_length_months": 0},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_malformed_term_start(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly", "term_start": "31/01/2026"},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_stores_named_specialist_and_customer_contact_and_note(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={
                "tier_at_signature": "patch", "billing_frequency": "monthly",
                "named_specialist": "Andy", "named_customer_contact": "Jo Bloggs",
                "note": "Negotiated off-model discount pending",
            },
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["named_specialist"] == "Andy"
        assert body["named_customer_contact"] == "Jo Bloggs"
        assert body["note"] == "Negotiated off-model discount pending"

    def test_stores_assessment_credit_fields(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={
                "tier_at_signature": "patch", "billing_frequency": "monthly",
                "assessment_credit_applies": True, "assessment_credit_value": 250.0,
                "assessment_credit_expires_at": "2026-11-01",
            },
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["assessment_credit_applies"] == 1
        assert body["assessment_credit_value"] == 250.0
        assert body["assessment_credit_expires_at"] == "2026-11-01"


# ── One-active-contract-per-tenant ───────────────────────────────────────────

class TestOneActiveContractPerTenant:
    def test_second_create_without_supersede_is_rejected(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r1 = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r1.status_code == 200
        r2 = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "full", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r2.status_code == 400
        assert "supersede" in r2.json()["error"]
        # And the original contract is untouched.
        active = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts/active", headers=BEARER).json()
        assert active["tier_at_signature"] == "patch"

    def test_supersede_flag_atomically_replaces_active_contract(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        r1 = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        old_id = r1.json()["id"]
        r2 = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts?supersede=true",
            json={"tier_at_signature": "full", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r2.status_code == 200
        new_id = r2.json()["id"]
        assert new_id != old_id

        history = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts", headers=BEARER).json()["contracts"]
        assert len(history) == 2
        by_id = {c["id"]: c for c in history}
        assert by_id[old_id]["status"] == "superseded"
        assert by_id[new_id]["status"] == "active"

        active = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts/active", headers=BEARER).json()
        assert active["id"] == new_id
        assert active["tier_at_signature"] == "full"

    def test_active_returns_404_when_none_exists(self, client):
        r = client.get("/admin/tenants/24cc09de-1433-5b6d-b73e-e300523fea98/contracts/active", headers=BEARER)
        assert r.status_code == 404

    def test_list_returns_most_recent_first(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 10})
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts?supersede=true",
            json={"tier_at_signature": "full", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        history = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts", headers=BEARER).json()["contracts"]
        assert history[0]["tier_at_signature"] == "full"
        assert history[1]["tier_at_signature"] == "patch"


# ── THE core regression: band-table changes never reprice a contracted tenant ─

class TestContractIsSourceOfTruthForBilling:
    def test_band_table_change_does_not_alter_existing_contracted_tenant(self, client, monkeypatch):
        _insert_client("4b63b717-865f-5ad1-b34a-534a51b473c4", "patch")
        _mock_devices(monkeypatch, {"4b63b717-865f-5ad1-b34a-534a51b473c4": 20})  # patch band for 20 -> £500

        r = client.post(
            "/admin/tenants/4b63b717-865f-5ad1-b34a-534a51b473c4/contracts",
            json={"tier_at_signature": "patch", "billing_frequency": "monthly"},
            headers=BEARER,
        )
        assert r.status_code == 200
        contracted_monthly = r.json()["monthly_at_signature"]
        assert contracted_monthly == 500.0

        # Sanity check that this test is actually meaningful: a NEW live
        # quote for the same endpoint count is currently identical...
        pre_change_summary = client.get("/admin/billing/summary", headers=BEARER)
        row = [x for x in pre_change_summary.json()["rows"] if x["tenant_id"] == "4b63b717-865f-5ad1-b34a-534a51b473c4"][0]
        assert row["monthly"] == 500.0
        assert row["has_contract"] is True

        # ...now change the stored band table so a LIVE lookup for 20
        # endpoints would produce a very different figure.
        rp = client.patch(
            "/admin/billing/rates",
            json={"bands": {"patch": [
                {"max_endpoints": 25, "monthly": 9999.0, "advisory_hours": 2},
                {"max_endpoints": 60, "monthly": 12000.0, "advisory_hours": 3},
            ]}},
            headers=BEARER,
        )
        assert rp.status_code == 200
        # Confirm the live band lookup really would now differ (proves the
        # test is exercising the real defect, not a no-op).
        rates = dashboard._billing_rates()
        assert dashboard._compute_monthly(20, "patch", "monthly", rates) == 9999.0

        # THE acceptance criterion: the contracted tenant's billed figure in
        # api_billing_summary is UNCHANGED.
        post_change_summary = client.get("/admin/billing/summary", headers=BEARER)
        row2 = [x for x in post_change_summary.json()["rows"] if x["tenant_id"] == "4b63b717-865f-5ad1-b34a-534a51b473c4"][0]
        assert row2["monthly"] == 500.0
        assert row2["monthly"] != 9999.0

    def test_tenant_without_a_contract_still_uses_live_band_lookup(self, client, monkeypatch):
        # No contract for this tenant -> pre-sale/quoting path -> _compute_monthly() live.
        _insert_client("654783f2-d124-5081-b813-9cefd6c2f65d", "patch", billing_frequency="monthly")
        _mock_devices(monkeypatch, {"654783f2-d124-5081-b813-9cefd6c2f65d": 20})
        r = client.get("/admin/billing/summary", headers=BEARER)
        row = [x for x in r.json()["rows"] if x["tenant_id"] == "654783f2-d124-5081-b813-9cefd6c2f65d"][0]
        assert row["monthly"] == 500.0
        assert row["has_contract"] is False

        client.patch(
            "/admin/billing/rates",
            json={"bands": {"patch": [{"max_endpoints": 25, "monthly": 750.0, "advisory_hours": 2}]}},
            headers=BEARER,
        )
        r2 = client.get("/admin/billing/summary", headers=BEARER)
        row2 = [x for x in r2.json()["rows"] if x["tenant_id"] == "654783f2-d124-5081-b813-9cefd6c2f65d"][0]
        # Unsigned tenant DOES track the live band table — that's the correct
        # pre-sale/quoting behaviour, the opposite of the contracted case above.
        assert row2["monthly"] == 750.0


# ── GET /admin/billing/renewals: 60-day window ──────────────────────────────

class TestRenewalsWindow:
    def _make_contract(self, client, monkeypatch, tenant_id, renewal_days_from_now, endpoints=20, tier="patch"):
        _insert_client(tenant_id, tier)
        _mock_devices(monkeypatch, {tenant_id: endpoints})
        # Back-date term_start so renewal_date lands where we want it, using
        # a 12-month term: term_start = renewal_date - 12 months.
        renewal_date = _iso_date(renewal_days_from_now)
        term_start = dashboard._add_months(renewal_date, -12)
        r = client.post(
            f"/admin/tenants/{tenant_id}/contracts",
            json={
                "tier_at_signature": tier, "billing_frequency": "monthly",
                "term_start": term_start, "term_length_months": 12,
            },
            headers=BEARER,
        )
        assert r.status_code == 200
        assert r.json()["renewal_date"] == renewal_date
        return r.json()

    def test_just_inside_the_window_is_included(self, client, monkeypatch):
        self._make_contract(client, monkeypatch, "0e2ace2a-6a4d-57d9-b6f6-0164176c5f5d", 30)
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        assert any(r["tenant_id"] == "0e2ace2a-6a4d-57d9-b6f6-0164176c5f5d" for r in rows)

    def test_exactly_60_days_is_included(self, client, monkeypatch):
        self._make_contract(client, monkeypatch, "cf1ae51b-d9da-5b87-aca2-a5dac18dd0cd", 60)
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        assert any(r["tenant_id"] == "cf1ae51b-d9da-5b87-aca2-a5dac18dd0cd" for r in rows)

    def test_just_outside_the_window_is_excluded(self, client, monkeypatch):
        self._make_contract(client, monkeypatch, "76f5ced3-0356-5ba0-b15e-bd6ca807104c", 90)
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        assert not any(r["tenant_id"] == "76f5ced3-0356-5ba0-b15e-bd6ca807104c" for r in rows)

    def test_overdue_renewal_is_included_not_filtered(self, client, monkeypatch):
        self._make_contract(client, monkeypatch, "10ee472d-f0a3-5ef7-a5c4-4340d4fac196", -10)
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "10ee472d-f0a3-5ef7-a5c4-4340d4fac196"][0]
        assert row["days_until_renewal"] < 0

    def test_future_term_start_excluded_even_if_renewal_date_in_window(self, client, monkeypatch):
        # Non-author review finding: a contract whose term hasn't even
        # started yet must not appear as "due for renewal" just because a
        # short term_length_months happens to land renewal_date inside the
        # 60-day window. A 1-month term starting 30 days from now has a
        # renewal_date ~60 days out, but the term itself hasn't begun.
        tenant_id = "c918878b-f4a9-554b-a8ce-3ea03deb8630"
        _insert_client(tenant_id, "patch")
        _mock_devices(monkeypatch, {tenant_id: 20})
        future_term_start = _iso_date(30)
        r = client.post(
            f"/admin/tenants/{tenant_id}/contracts",
            json={
                "tier_at_signature": "patch", "billing_frequency": "monthly",
                "term_start": future_term_start, "term_length_months": 1,
            },
            headers=BEARER,
        )
        assert r.status_code == 200
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        assert not any(r["tenant_id"] == tenant_id for r in rows)

    def test_rows_sorted_soonest_or_most_overdue_first(self, client, monkeypatch):
        self._make_contract(client, monkeypatch, "a7e9b2a1-7944-572c-9df3-faa7d595ba83", 45)
        self._make_contract(client, monkeypatch, "79194fab-aee4-5046-ac32-9d2cda220b7d", -5)
        self._make_contract(client, monkeypatch, "bbee5c94-0643-5393-86d9-825b577d49b2", 10)
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        order = [r["tenant_id"] for r in rows]
        assert order == ["79194fab-aee4-5046-ac32-9d2cda220b7d", "bbee5c94-0643-5393-86d9-825b577d49b2", "a7e9b2a1-7944-572c-9df3-faa7d595ba83"]


# ── GET /admin/billing/renewals: delta + consumption stats ─────────────────

class TestRenewalsDeltaAndConsumption:
    def test_delta_reflects_current_band_minus_contracted(self, client, monkeypatch):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31", "patch")
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 20})
        renewal_date = _iso_date(30)
        term_start = dashboard._add_months(renewal_date, -12)
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/contracts",
            json={
                "tier_at_signature": "patch", "billing_frequency": "monthly",
                "term_start": term_start, "term_length_months": 12,
            },
            headers=BEARER,
        )
        # Endpoint count has drifted upward since signature -> the tenant is
        # now in a higher band under the SAME rate table.
        _mock_devices(monkeypatch, {"0a4c2c91-7412-575c-b544-dea3a596dd31": 61})  # patch band for 61 -> £1200
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["contracted_monthly"] == 500.0
        assert row["current_band_monthly"] == 1200.0
        assert row["delta"] == 700.0

    def test_delta_is_zero_when_nothing_has_drifted(self, client, monkeypatch):
        renewal_date = _iso_date(30)
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
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["delta"] == 0.0

    def _seed_ledger(self, tenant_id, entries):
        """entries: list of (entry_date, duration_minutes, class)"""
        with dashboard.get_db() as db:
            for entry_date, minutes, cls in entries:
                db.execute(
                    "INSERT INTO time_ledger (id, tenant_id, entry_date, duration_minutes, note, class, "
                    "created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (f"tl-{entry_date}-{minutes}-{cls}", tenant_id, entry_date, minutes, None, cls,
                     "tester", "2026-01-01T00:00:00Z"),
                )

    def _anchor_term(self):
        """A term_start that is always a full year before the 1st of the
        current month, with renewal 12 months later landing on the 1st of
        the current month — always inside [today-31, today], so always
        within the renewals window regardless of when this test runs, and
        always using day=1 (safe in every month, no clamping ambiguity when
        deriving the three consecutive ledger-entry months below)."""
        today = datetime.now(timezone.utc).date()
        term_start = today.replace(year=today.year - 1, day=1).isoformat()
        return term_start

    def test_mean_peak_and_over_allowance_count(self, client, monkeypatch):
        # Advisory allowance for a 20-endpoint patch tenant is 2h = 120 min.
        term_start = self._anchor_term()
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
        # Three distinct months of advisory consumption: 60, 150, 90 minutes.
        m0 = term_start
        m1 = dashboard._add_months(term_start, 1)
        m2 = dashboard._add_months(term_start, 2)
        self._seed_ledger("0a4c2c91-7412-575c-b544-dea3a596dd31", [
            (m0, 60, "advisory"),
            (m1, 150, "advisory"),
            (m2, 90, "advisory"),
        ])
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["contracted_advisory_hours"] == 2
        assert row["consumption_months_counted"] == 3
        assert row["consumption_mean_minutes"] == round((60 + 150 + 90) / 3, 1)
        assert row["consumption_peak_minutes"] == 150
        # Allowance is 120 min; only the 150-min month exceeded it.
        assert row["consumption_months_over_allowance"] == 1

    def test_service_integrity_entries_excluded_from_consumption_stats(self, client, monkeypatch):
        term_start = self._anchor_term()
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
        # A huge service_integrity entry that must NEVER enter the advisory
        # consumption stats (same safety property PAT-1100 established for
        # the time-ledger balance endpoint).
        self._seed_ledger("0a4c2c91-7412-575c-b544-dea3a596dd31", [
            (term_start, 30, "advisory"),
            (term_start, 999999, "service_integrity"),
        ])
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["consumption_mean_minutes"] == 30.0
        assert row["consumption_peak_minutes"] == 30
        assert row["consumption_months_over_allowance"] == 0

    def test_no_ledger_activity_yields_zero_stats_not_an_error(self, client, monkeypatch):
        renewal_date = _iso_date(30)
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
        rows = client.get("/admin/billing/renewals", headers=BEARER).json()["rows"]
        row = [r for r in rows if r["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"][0]
        assert row["consumption_mean_minutes"] == 0.0
        assert row["consumption_peak_minutes"] == 0
        assert row["consumption_months_over_allowance"] == 0
        assert row["consumption_months_counted"] == 0

    def test_empty_renewals_response_shape(self, client, monkeypatch):
        _mock_devices(monkeypatch, {})
        r = client.get("/admin/billing/renewals", headers=BEARER)
        assert r.status_code == 200
        assert r.json() == {"rows": [], "window_days": 60}
