"""
Tests for PAT-1102 — one-off charges + assessment-credit tracking.

Covers:
  - Charge creation for all four charge_type values, and validation of
    charge_type / amount / date_raised / tenant-existence.
  - credit_expires_at is computed server-side (date_raised + 90 days) for
    assessment charges only, and is NEVER client-overridable.
  - The net figure (gross - credits) on create, list, patch and apply-credit.
  - GET .../charges ordering (most recent date_raised first).
  - PATCH .../charges/{id}: status/xero_invoice_reference/note updates,
    status validation, tenant-scoping (404 for a charge that belongs to a
    different tenant_id).
  - GET .../available-assessment-credit: none / expired / available.
  - POST .../charges/{id}/apply-credit: success path, rejecting an
    already-consumed source charge, warning-but-allowing an expired credit
    via ?override_expired=true (and refusing without it), and the "credited
    in full by default, operator can override the amount" policy.
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


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(shared, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def _insert_client(tenant_id, billing_tier="patch", company="Acme Corp"):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, tenant_id, company, billing_tier, created_at) VALUES (?,?,?,?,?)",
            (tenant_id, tenant_id, company, billing_tier, "2026-01-01T00:00:00Z"),
        )


def _iso_date(days_from_now=0):
    return (datetime.now(timezone.utc) + timedelta(days=days_from_now)).strftime("%Y-%m-%d")


def _create_charge(client, tenant_id, charge_type="audit_pack", amount=500.0, date_raised=None, **extra):
    body = {"charge_type": charge_type, "amount": amount}
    if date_raised is not None:
        body["date_raised"] = date_raised
    body.update(extra)
    return client.post(f"/admin/tenants/{tenant_id}/charges", json=body, headers=BEARER)


# ── Table-name collision check (PAT-1101 precedent) ─────────────────────────

class TestBillingChargesTableNames:
    def test_billing_charges_and_credits_tables_exist_after_init_db(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(shared, "DB_PATH", db_path)
        monkeypatch.setattr(dashboard, "DB_PATH", db_path)
        dashboard.init_db()
        with dashboard.get_db() as db:
            charge_cols = {r[1] for r in db.execute("PRAGMA table_info(billing_charges)").fetchall()}
            assert "tenant_id" in charge_cols
            assert "credit_expires_at" in charge_cols
            credit_cols = {r[1] for r in db.execute("PRAGMA table_info(billing_charge_credits)").fetchall()}
            assert "charge_id" in credit_cols
            assert "source_charge_id" in credit_cols


# ── Charge creation ──────────────────────────────────────────────────────────

class TestChargeCreation:
    @pytest.mark.parametrize("charge_type", ["assessment", "onboarding", "audit_pack", "advisory_overflow"])
    def test_creates_each_charge_type(self, client, charge_type):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type=charge_type, amount=300.0, date_raised="2026-01-01")
        assert r.status_code == 200
        body = r.json()
        assert body["charge_type"] == charge_type
        assert body["tenant_id"] == "0a4c2c91-7412-575c-b544-dea3a596dd31"
        assert body["amount"] == 300.0
        assert body["status"] == "draft"
        assert body["gross"] == 300.0
        assert body["credits"] == 0.0
        assert body["net"] == 300.0

    def test_rejects_invalid_charge_type(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="consulting")
        assert r.status_code == 400

    def test_rejects_non_positive_amount(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", amount=0)
        assert r.status_code == 400
        r2 = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", amount=-50)
        assert r2.status_code == 400

    def test_rejects_non_numeric_amount(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges",
            json={"charge_type": "audit_pack", "amount": "lots"},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_malformed_date_raised(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", date_raised="01/02/2026")
        assert r.status_code == 400

    def test_defaults_date_raised_to_today(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", date_raised=None)
        assert r.status_code == 200
        assert r.json()["date_raised"] == _iso_date(0)

    def test_rejects_nonexistent_tenant(self, client):
        r = _create_charge(client, "24cc09de-1433-5b6d-b73e-e300523fea98")
        assert r.status_code == 404


# ── credit_expires_at auto-computation (assessment only, never client-set) ──

class TestAssessmentCreditExpiry:
    def test_assessment_charge_gets_90_day_expiry_from_date_raised(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised="2026-01-01")
        assert r.status_code == 200
        body = r.json()
        assert body["credit_expires_at"] == "2026-04-01"
        assert body["credit_consumed"] == 0

    def test_client_supplied_credit_expires_at_is_ignored(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(
            client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised="2026-01-01",
            credit_expires_at="2099-01-01",
        )
        assert r.status_code == 200
        # The server-computed value wins, never the client-supplied one.
        assert r.json()["credit_expires_at"] == "2026-04-01"

    def test_non_assessment_types_have_null_credit_fields(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", date_raised="2026-01-01")
        assert r.status_code == 200
        body = r.json()
        assert body["credit_expires_at"] is None
        assert body["credit_consumed"] == 0


# ── GET list ──────────────────────────────────────────────────────────────

class TestChargesList:
    def test_list_orders_most_recent_date_raised_first(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", date_raised="2026-01-01", note="oldest")
        _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", date_raised="2026-03-01", note="newest")
        _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", date_raised="2026-02-01", note="middle")
        rows = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges", headers=BEARER).json()["charges"]
        assert [r["note"] for r in rows] == ["newest", "middle", "oldest"]

    def test_list_exposes_gross_credits_net_on_every_row(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", amount=123.45, date_raised="2026-01-01")
        rows = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges", headers=BEARER).json()["charges"]
        assert rows[0]["gross"] == 123.45
        assert rows[0]["credits"] == 0.0
        assert rows[0]["net"] == 123.45

    def test_list_only_returns_charges_for_the_requested_tenant(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        _insert_client("b27fb783-0526-5455-85dc-ffc0082795e1")
        _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", note="mine")
        _create_charge(client, "b27fb783-0526-5455-85dc-ffc0082795e1", note="not mine")
        rows = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges", headers=BEARER).json()["charges"]
        assert len(rows) == 1
        assert rows[0]["note"] == "mine"

    def test_empty_list_for_tenant_with_no_charges(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        rows = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges", headers=BEARER).json()["charges"]
        assert rows == []


# ── PATCH update ──────────────────────────────────────────────────────────

class TestChargeUpdate:
    def test_updates_status(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        charge_id = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31").json()["id"]
        r = client.patch(f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{charge_id}", json={"status": "invoiced"}, headers=BEARER)
        assert r.status_code == 200
        assert r.json()["status"] == "invoiced"

    def test_updates_xero_invoice_reference_and_note(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        charge_id = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31").json()["id"]
        r = client.patch(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{charge_id}",
            json={"xero_invoice_reference": "INV-042", "note": "chased 2026-08-01"},
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["xero_invoice_reference"] == "INV-042"
        assert body["note"] == "chased 2026-08-01"

    def test_rejects_invalid_status(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        charge_id = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31").json()["id"]
        r = client.patch(f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{charge_id}", json={"status": "cancelled"}, headers=BEARER)
        assert r.status_code == 400

    def test_404_for_charge_belonging_to_a_different_tenant(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        _insert_client("b27fb783-0526-5455-85dc-ffc0082795e1")
        charge_id = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31").json()["id"]
        r = client.patch(f"/admin/tenants/b27fb783-0526-5455-85dc-ffc0082795e1/charges/{charge_id}", json={"status": "paid"}, headers=BEARER)
        assert r.status_code == 404

    def test_404_for_nonexistent_charge(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = client.patch("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/does-not-exist", json={"status": "paid"}, headers=BEARER)
        assert r.status_code == 404

    def test_rejects_empty_body(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        charge_id = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31").json()["id"]
        r = client.patch(f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{charge_id}", json={}, headers=BEARER)
        assert r.status_code == 400


# ── GET available-assessment-credit: three-state response ──────────────────

class TestAvailableAssessmentCredit:
    def test_no_assessment_charge_at_all(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is False
        assert body["expired"] is False
        assert body["charge_id"] is None

    def test_unexpired_unconsumed_credit_is_available(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        charge = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER)
        body = r.json()
        assert body["available"] is True
        assert body["expired"] is False
        assert body["charge_id"] == charge["id"]
        assert body["amount"] == 400.0
        assert body["credit_expires_at"] == charge["credit_expires_at"]

    def test_expired_credit_is_visibly_expired_not_absent(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        # Raised well over 90 days ago -> credit_expires_at is in the past.
        old_date = _iso_date(-200)
        charge = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=old_date, amount=250.0).json()
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER)
        body = r.json()
        assert body["available"] is False
        assert body["expired"] is True
        # Not omitted — still identifies exactly which charge expired.
        assert body["charge_id"] == charge["id"]
        assert body["amount"] == 250.0

    def test_consumed_credit_is_not_returned(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", date_raised=today, amount=1000.0).json()
        client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit",
            json={"source_charge_id": assessment["id"]},
            headers=BEARER,
        )
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER)
        body = r.json()
        assert body["available"] is False
        assert body["expired"] is False
        assert body["charge_id"] is None

    def test_most_recent_unconsumed_assessment_charge_wins(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised="2026-01-01", amount=100.0)
        newer = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised="2026-06-01", amount=200.0).json()
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER)
        assert r.json()["charge_id"] == newer["id"]

    def test_written_off_assessment_charge_never_surfaces_as_available(self, client):
        # Non-author review finding: status and credit_consumed are
        # independent dimensions. An operator who explicitly writes off an
        # assessment charge (e.g. it will never be paid) must not have it
        # resurface as an applicable credit just because credit_consumed is
        # still separately 0.
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        charge = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        r = client.patch(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{charge['id']}", json={"status": "written_off"}, headers=BEARER
        )
        assert r.status_code == 200
        body = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER).json()
        assert body["available"] is False
        assert body["charge_id"] is None

    def test_null_credit_expires_at_is_not_available_not_expired(self, client, monkeypatch):
        # Non-author review finding: bool(None) is False, so a naive
        # `expired = bool(credit_expires_at) and ...` check would present a
        # null-expiry assessment charge as a never-expiring "available"
        # credit. api_charge_create always computes credit_expires_at for
        # assessment charges, so simulate the invariant being broken by a
        # hypothetical future code path by writing a NULL directly.
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        charge = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        with dashboard.get_db() as db:
            db.execute(
                "UPDATE billing_charges SET credit_expires_at=NULL WHERE id=?", (charge["id"],)
            )
        body = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER).json()
        assert body["available"] is False
        assert body["expired"] is False
        assert body["charge_id"] == charge["id"]
        assert body["credit_expires_at"] is None


# ── POST apply-credit ────────────────────────────────────────────────────

class TestApplyCredit:
    def test_success_path_inserts_credit_and_consumes_source(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", date_raised=today, amount=1000.0).json()

        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit",
            json={"source_charge_id": assessment["id"], "reason": "retainer signed in window"},
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["credits"] == 400.0
        assert body["net"] == 600.0
        assert body["credit_applied"]["source_charge_id"] == assessment["id"]
        assert body["credit_applied"]["amount"] == 400.0

        # Source charge is now consumed and drops out of the credit-available check.
        avail = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER).json()
        assert avail["available"] is False
        assert avail["charge_id"] is None

        # The net figure is reconstructable from the list endpoint too.
        rows = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges", headers=BEARER).json()["charges"]
        onboarding_row = [c for c in rows if c["id"] == onboarding["id"]][0]
        assert onboarding_row["gross"] == 1000.0
        assert onboarding_row["credits"] == 400.0
        assert onboarding_row["net"] == 600.0

    def test_operator_can_override_the_credited_amount(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", date_raised=today, amount=1000.0).json()

        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit",
            json={"source_charge_id": assessment["id"], "amount": 150.0},
            headers=BEARER,
        )
        assert r.status_code == 200
        assert r.json()["credits"] == 150.0
        assert r.json()["net"] == 850.0

    def test_rejects_already_consumed_source_charge(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        onboarding1 = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", date_raised=today, amount=1000.0).json()
        onboarding2 = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", date_raised=today, amount=800.0).json()

        r1 = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding1['id']}/apply-credit",
            json={"source_charge_id": assessment["id"]},
            headers=BEARER,
        )
        assert r1.status_code == 200

        r2 = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding2['id']}/apply-credit",
            json={"source_charge_id": assessment["id"]},
            headers=BEARER,
        )
        assert r2.status_code == 400
        assert "already consumed" in r2.json()["error"]
        # Second onboarding charge is untouched.
        rows = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges", headers=BEARER).json()["charges"]
        row2 = [c for c in rows if c["id"] == onboarding2["id"]][0]
        assert row2["credits"] == 0.0

    def test_expired_credit_is_refused_without_override(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        old_date = _iso_date(-200)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=old_date, amount=400.0).json()
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", amount=1000.0).json()

        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit",
            json={"source_charge_id": assessment["id"]},
            headers=BEARER,
        )
        assert r.status_code == 400
        assert r.json()["expired"] is True
        # Nothing applied — source charge remains unconsumed.
        avail_check = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/available-assessment-credit", headers=BEARER).json()
        assert avail_check["expired"] is True
        assert avail_check["charge_id"] == assessment["id"]

    def test_expired_credit_is_allowed_with_override_flag(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        old_date = _iso_date(-200)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=old_date, amount=400.0).json()
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", amount=1000.0).json()

        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit?override_expired=true",
            json={"source_charge_id": assessment["id"]},
            headers=BEARER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["credits"] == 400.0
        assert body["credit_applied"]["applied_despite_expired"] is True

    def test_rejects_nonexistent_target_charge(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        assessment = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="assessment", date_raised=today, amount=400.0).json()
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/does-not-exist/apply-credit",
            json={"source_charge_id": assessment["id"]},
            headers=BEARER,
        )
        assert r.status_code == 404

    def test_rejects_source_charge_from_a_different_tenant(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        _insert_client("b27fb783-0526-5455-85dc-ffc0082795e1")
        today = _iso_date(0)
        assessment_t2 = _create_charge(client, "b27fb783-0526-5455-85dc-ffc0082795e1", charge_type="assessment", date_raised=today, amount=400.0).json()
        onboarding_t1 = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", amount=1000.0).json()
        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding_t1['id']}/apply-credit",
            json={"source_charge_id": assessment_t2["id"]},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_rejects_non_assessment_source_charge(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        today = _iso_date(0)
        audit_pack = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="audit_pack", date_raised=today, amount=200.0).json()
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", amount=1000.0).json()
        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit",
            json={"source_charge_id": audit_pack["id"]},
            headers=BEARER,
        )
        assert r.status_code == 400

    def test_requires_source_charge_id(self, client):
        _insert_client("0a4c2c91-7412-575c-b544-dea3a596dd31")
        onboarding = _create_charge(client, "0a4c2c91-7412-575c-b544-dea3a596dd31", charge_type="onboarding", amount=1000.0).json()
        r = client.post(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/charges/{onboarding['id']}/apply-credit",
            json={},
            headers=BEARER,
        )
        assert r.status_code == 400
