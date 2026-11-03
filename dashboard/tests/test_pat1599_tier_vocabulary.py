"""
PAT-1599 (dashboard half) — collapse the tier vocabulary from
report/patch/full_endpoint to assurance/managed.

Console.html ships one hash-routed SPA with no JS test runner inside pytest
(see AGENTS.md), so — same convention as test_pat1741_console_defects.py and
test_pat1356_account_workspace.py — the client-side wiring is asserted
structurally (markup + function-source presence) here. Backend behaviour
(_SUBSCRIPTION_TIERS, _SUB_TIER_TO_BILLING, the subscription-tier PUT route,
and the account GET's billing_tier fallback) is exercised for real against
the FastAPI app.

Also covers the negative space this ticket had to get right: the numeric
CIS-collection tenants.tier column (rendered via the separate 1/2/3
tierLabels map) and the unrelated App Policy Drift enforcement_tier
vocabulary must NOT be touched by the assurance/managed collapse, and the
local billing_tier pricing-band vocabulary (report/patch/full) is a
genuinely distinct, out-of-scope concept that _BILL_TIER_LABELS still
serves.

Run with: pytest tests/test_pat1599_tier_vocabulary.py -v
"""

import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")

BEARER = {"Authorization": "Bearer test-key"}


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


def _extract_var(text, name):
    start = text.index("var " + name + " =")
    end = text.index(";", start)
    return text[start:end + 1]


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "dashboard.db"
    monkeypatch.setattr(shared, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    dashboard.init_db()
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, billing_tier, agent_config_tier, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "Acme", "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "patch", "managed", "2026-08-15T00:00:00Z"),
        )
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, billing_tier, agent_config_tier, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("c2", "Beta Ltd", "3f4dc3a2-72e2-5925-8f7b-eb94559ee8db", "report", "assurance", "2026-08-15T00:00:00Z"),
        )
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, billing_tier, agent_config_tier, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("c3", "Gamma Inc", "cfe85d9c-7278-55da-9ebc-891188476ec6", "full", "managed", "2026-08-15T00:00:00Z"),
        )
    with TestClient(dashboard.app) as test_client:
        yield test_client


# ── Backend: _SUBSCRIPTION_TIERS / _SUB_TIER_TO_BILLING ────────────────────


def test_subscription_tiers_are_exactly_assurance_and_managed():
    assert dashboard._SUBSCRIPTION_TIERS == {"assurance", "managed"}


def test_sub_tier_to_billing_maps_both_values_into_the_untouched_billing_vocab():
    assert dashboard._SUB_TIER_TO_BILLING == {"assurance": "report", "managed": "full"}


def test_subscription_tier_put_rejects_retired_values(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.http, "put",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not reach go-service")),
    )
    for retired in ("report", "patch", "full_endpoint"):
        r = client.put(
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/subscription-tier",
            headers=BEARER, json={"subscription_tier": retired},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "subscription_tier must be assurance or managed"


def test_subscription_tier_put_accepts_new_values_and_mirrors_billing_tier(client, monkeypatch):
    captured = {}

    def fake_put(url, **kwargs):
        captured["json"] = kwargs.get("json")
        class R:
            status_code = 200
            def json(self):
                return {"agent_config_tier": "managed", "agent_config_version": 3, "app_control_enabled": True}
        return R()

    monkeypatch.setattr(dashboard.http, "put", fake_put)
    r = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/subscription-tier",
        headers=BEARER, json={"subscription_tier": "managed"},
    )
    assert r.status_code == 200
    assert captured["json"]["subscription_tier"] == "managed"
    with dashboard.get_db() as db:
        row = db.execute("SELECT billing_tier FROM clients WHERE tenant_id=?", ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac",)).fetchone()
    assert row["billing_tier"] == "full"


# ── Backend: account GET derives subscription_tier from billing_tier ───────


def test_account_get_derives_assurance_from_report_billing_tier(client):
    r = client.get("/admin/tenants/3f4dc3a2-72e2-5925-8f7b-eb94559ee8db/account", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["subscription_tier"] == "assurance"


@pytest.mark.parametrize("tenant_id,expected", [
    ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "managed"),   # billing_tier="patch" -> managed (patch already implies actuation)
    ("cfe85d9c-7278-55da-9ebc-891188476ec6", "managed"),   # billing_tier="full" -> managed
])
def test_account_get_derives_managed_from_patch_or_full_billing_tier(client, tenant_id, expected):
    r = client.get(f"/admin/tenants/{tenant_id}/account", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["subscription_tier"] == expected


# ── Frontend: Account-tab tier <select> ─────────────────────────────────────


def test_acct_tier_select_has_exactly_two_options():
    select = HTML[HTML.index('id="acct-tier" class="acct-input"'):HTML.index("</select>", HTML.index('id="acct-tier" class="acct-input"'))]
    assert 'value="assurance"' in select
    assert 'value="managed"' in select
    assert select.count("<option") == 2
    assert "report" not in select
    assert "patch" not in select
    assert "full_endpoint" not in select


# ── Frontend: tier label maps collapsed to assurance/managed ───────────────


def test_tier_label_function_only_knows_assurance_and_managed():
    fn = _extract_fn(HTML, "_tierLabel")
    assert "'assurance': 'Assurance'" in fn
    assert "'managed':   'Managed'" in fn
    for retired in ("report'", "patch'", "full_endpoint", "report_deploy", "full_endpoint_mgmt"):
        assert retired not in fn


def test_tier_confirm_labels_collapsed():
    var = _extract_var(HTML, "_TIER_CONFIRM_LABELS")
    assert var == "var _TIER_CONFIRM_LABELS = { assurance: 'Assurance', managed: 'Managed' };"


def test_acct_populate_no_longer_reconciles_legacy_tier_vocabularies():
    fn = _extract_fn(HTML, "_acctPopulate")
    assert "_acbtMap" not in fn
    assert "_billingMap" not in fn
    assert "data.subscription_tier || 'assurance'" in fn


# ── Frontend: billing_tier pricing-band vocabulary stays untouched ─────────


def test_bill_tier_labels_keeps_the_distinct_billing_pricing_vocabulary():
    var = _extract_var(HTML, "_BILL_TIER_LABELS")
    assert "report: 'Report & Deploy'" in var
    assert "patch: 'Report, Deploy & Patch'" in var
    assert "full: 'Full Management'" in var
    # the dead subscription_tier-shaped synonym is gone; billing_tier values
    # are never 'full_endpoint'
    assert "full_endpoint" not in var


def test_bill_band_tiers_still_the_local_pricing_bands_not_assurance_managed():
    assert "var _BILL_BAND_TIERS = ['patch', 'full'];" in HTML


# ── Negative space: the numeric CIS tier and enforcement_tier must survive ─


def test_numeric_cis_tier_select_and_labels_untouched():
    # tenants.tier (smallint CIS-collection tier) is a completely different
    # column from subscription_tier and must keep its 1/2/3 vocabulary.
    assert '<option value="1">Tier 1 — Report &amp; Deploy</option>' in HTML
    assert '<option value="2">Tier 2 — Report, Deploy &amp; Patch</option>' in HTML
    assert '<option value="3">Tier 3 — Full Management</option>' in HTML
    assert "var tierLabels = { 1: 'Tier 1 — Report & Deploy', 2: 'Tier 2 — Report, Deploy & Patch', 3: 'Tier 3 — Full Management' };" in HTML


def test_app_policy_drift_enforcement_tier_untouched():
    fn = _extract_fn(HTML, "_apoTierLabel")
    assert "report:         'Report'" in fn
    assert "app_management: 'App Management'" in fn
    assert "managed:        'Managed / Intune'" in fn
