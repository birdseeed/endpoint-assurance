"""PAT-2389: uploaded public certificates share expiry assurance, never device provenance."""

import copy
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")
import main as dashboard  # noqa: E402
from certs import compute_days_until_expiry  # noqa: E402

TENANT = "1318655a-e600-5312-8611-eb336cec91b8"
NOW = datetime.now(timezone.utc)


def uploaded(label="Renewal certificate", days=3, **changes):
    cert = {
        "id": "manual-public-cert", "source": "uploaded", "label": label,
        "fingerprint_sha256": "a" * 64, "subject_cn": "Public subject",
        "issuer_cn": "Synthetic CA", "not_before": (NOW - timedelta(days=365)).isoformat(),
        "not_after": (NOW + timedelta(days=days, hours=12)).isoformat(),
        "ext_key_usage": ["1.3.6.1.5.5.7.3.3"],
        "basic_constraints_ca": False, "is_self_signed": False,
    }
    cert.update(changes)
    return cert


def agent(days=3):
    cert = uploaded("", days)
    for field in ("source", "id", "label", "fingerprint_sha256"):
        cert.pop(field)
    cert.update(device_id="endpoint-123456789", sha1="b" * 40,
                collected_at=NOW.isoformat(), days_until_expiry_at_collection=900)
    return cert


class Response:
    status_code = 200
    content = b"stub"

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return copy.deepcopy(self.payload)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "dashboard.db")
    monkeypatch.setattr(dashboard, "DASHBOARD_API_KEY", "pat2389-test-key")
    dashboard.init_db()
    state = {"rows": [], "requests": [], "emails": [], "send_ok": True, "delivery": "live"}

    def fake_get(url, **kwargs):
        state["requests"].append((url, kwargs))
        if url.endswith(f"/admin/tenant/{TENANT}/certs"):
            return Response(state["rows"])
        if url.endswith("/admin/tenants"):
            return Response({"tenants": [{"id": TENANT, "name": "Synthetic estate"}]})
        raise AssertionError(f"Unexpected HTTP stub request: {url}")

    def fake_sender(recipient, subject, html, text):
        state["emails"].append((recipient, subject, html, text))
        return state["send_ok"]

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard, "_send_email", fake_sender)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: state["delivery"])
    return state


def seed_client(enabled=1, recipient="nobody@example.invalid", severity="expired_plus_critical",
                frequency="daily", last=None):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id,company,tenant_id,created_at,cert_digest_enabled,"
            "cert_digest_recipient,cert_digest_severity,cert_digest_frequency,last_cert_digest_sent_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("synthetic-client", "Synthetic estate", TENANT, NOW.isoformat(), enabled,
             recipient, severity, frequency, last),
        )


def last_sent():
    with dashboard.get_db() as db:
        return db.execute("SELECT last_cert_digest_sent_at FROM clients WHERE tenant_id=?",
                          (TENANT,)).fetchone()[0]


def get_api():
    with TestClient(dashboard.app, raise_server_exceptions=False) as client:
        return client.get(f"/api/tenant/{TENANT}/certs",
                          headers={"Authorization": "Bearer pat2389-test-key"})


def test_api_preserves_union_metadata_and_distinguishes_agent_source(isolated):
    manual, legacy = uploaded(), agent()
    isolated["rows"] = [manual, legacy]
    response = get_api()
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(result) == 2
    for key, value in manual.items():
        assert result[0][key] == value
    assert "device_id" not in result[0]
    for key, value in legacy.items():
        assert result[1][key] == value
    assert result[1]["source"] == "agent"
    assert result[0]["type"] == "code_signing"
    assert result[0]["days_until_expiry"] == 3
    assert result[1]["days_until_expiry"] == 3


@pytest.mark.parametrize("date", [None, "", "not-a-date", "2027-01-01T00:00:00", 42])
def test_invalid_expiry_is_unknown_in_helper(date):
    assert compute_days_until_expiry(uploaded(not_after=date)) is None


@pytest.mark.parametrize("date", [None, "", "not-a-date", "2027-01-01T00:00:00", 42])
def test_invalid_expiry_is_unknown_in_api(isolated, date):
    row = uploaded(not_after=date)
    isolated["rows"] = [row, agent()]
    response = get_api()
    assert response.status_code == 200, response.text
    assert response.json()[0]["days_until_expiry"] is None
    assert response.json()[0]["status"] == "unknown"
    assert response.json()[1]["days_until_expiry"] == 3


def test_missing_expiry_is_unknown(isolated):
    row = uploaded()
    row.pop("not_after")
    assert compute_days_until_expiry(row) is None


def test_missing_expiry_api_processes_valid_rows(isolated):
    row = uploaded()
    row.pop("not_after")
    isolated["rows"] = [row, agent()]
    response = get_api()
    assert response.status_code == 200, response.text
    assert response.json()[0]["status"] == "unknown"
    assert response.json()[0]["days_until_expiry"] is None
    assert response.json()[1]["days_until_expiry"] == 3


@pytest.mark.parametrize("days,status", [(-2, "expired"), (3, "critical"), (20, "warning"), (50, "healthy")])
def test_live_api_status_uses_existing_expiry_bands(isolated, days, status):
    isolated["rows"] = [uploaded(days=days)]
    response = get_api()
    assert response.status_code == 200, response.text
    assert response.json()[0]["days_until_expiry"] == days
    assert response.json()[0]["status"] == status


@pytest.mark.parametrize("severity,expected", [
    ("expired_only", {"Expired public"}),
    ("expired_plus_critical", {"Expired public", "Critical public"}),
    ("expired_plus_warning", {"Expired public", "Critical public", "Warning public"}),
])
def test_real_tick_includes_uploads_under_current_severity(isolated, severity, expected):
    seed_client(severity=severity)
    labels = {"Expired public": -2, "Critical public": 3, "Warning public": 20, "Healthy public": 50}
    isolated["rows"] = [uploaded(label, days, id=label) for label, days in labels.items()] + [agent()]
    dashboard._run_cert_digest_tick(NOW)
    assert len(isolated["emails"]) == 1
    recipient, _, html, text = isolated["emails"][0]
    assert recipient == "nobody@example.invalid"
    for body in (html, text):
        assert "Uploaded certificate" in body
        for label in labels:
            assert (label in body) == (label in expected)
        assert "None..." not in body
        if severity != "expired_only":
            assert "endpoint" in body
    assert last_sent() == NOW.isoformat()


@pytest.mark.parametrize("severity", ["expired_only", "expired_plus_critical", "expired_plus_warning", "all_categorised"])
def test_mixed_invalid_evidence_does_not_abort_or_count_healthy(isolated, monkeypatch, severity):
    seed_client(severity=severity)
    isolated["rows"] = [uploaded("Unknown public", not_after=None), uploaded("Expired public", -2), agent(50)]
    captured = {}
    original = dashboard.render_report_email

    def render(*args, **kwargs):
        captured.update(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(dashboard, "render_report_email", render)
    dashboard._run_cert_digest_tick(NOW)
    assert len(isolated["emails"]) == 1
    assert captured["counts"]["expired"] == 1
    assert captured["counts"]["healthy"] == (1 if severity == "all_categorised" else 0)
    for body in isolated["emails"][0][2:]:
        assert "Expired public" in body
        if severity == "all_categorised":
            assert "Unknown public" in body
            assert "unknown" in body.lower()
            assert captured["counts"]["unknown"] == 1
        else:
            assert "Unknown public" not in body


@pytest.mark.parametrize("guard", ["disabled", "no_recipient", "cadence", "dry_run", "failed_send"])
def test_existing_digest_delivery_guards_with_uploaded_source(isolated, guard):
    seed_client(enabled=0 if guard == "disabled" else 1,
                recipient=None if guard == "no_recipient" else "nobody@example.invalid",
                frequency="weekly", last=NOW.isoformat() if guard == "cadence" else None)
    isolated["rows"] = [uploaded("Expired public", -2)]
    isolated["delivery"] = "dry_run" if guard == "dry_run" else "live"
    isolated["send_ok"] = guard != "failed_send"
    dashboard._run_cert_digest_tick(NOW)
    assert len(isolated["emails"]) == (1 if guard in {"dry_run", "failed_send"} else 0)
    assert last_sent() == (NOW.isoformat() if guard == "cadence" else None)
    if guard in {"disabled", "cadence"}:
        assert not isolated["requests"]


def test_manual_digest_has_no_fabricated_device_and_escapes_admin_label(isolated):
    seed_client()
    isolated["rows"] = [uploaded("<script>label</script>", -2)]
    dashboard._run_cert_digest_tick(NOW)
    assert len(isolated["emails"]) == 1
    html, text = isolated["emails"][0][2:]
    assert "&lt;script&gt;label&lt;/script&gt;" in html
    assert "<script>label</script>" not in html
    assert "<script>label</script>" in text
    assert "Uploaded certificate" in html and "Uploaded certificate" in text
    assert "Device" not in text
    assert "None" not in text
    assert "..." not in text


def test_reading_uploaded_certificate_api_preserves_disabled_preferences(isolated):
    seed_client(enabled=0, recipient=None, severity="expired_only", frequency="monthly")
    isolated["rows"] = [uploaded()]
    with dashboard.get_db() as db:
        before = dict(db.execute("SELECT * FROM clients WHERE tenant_id=?", (TENANT,)).fetchone())
    assert get_api().status_code == 200
    dashboard._run_cert_digest_tick(NOW)
    with dashboard.get_db() as db:
        after = dict(db.execute("SELECT * FROM clients WHERE tenant_id=?", (TENANT,)).fetchone())
    assert after == before
    assert not isolated["emails"]


def test_authenticated_staff_certificate_page_is_useful_and_escaped(isolated):
    seed_client(enabled=0)
    isolated["rows"] = [uploaded("<script>uploaded label</script>", not_after=None), agent()]
    token = dashboard._session_encode("staff@example.invalid", int(time.time()) + 3600)
    with TestClient(dashboard.app, raise_server_exceptions=False) as client:
        client.cookies.set(dashboard.SESSION_COOKIE, token)
        response = client.get(f"/certs?tenant_id={TENANT}")
    assert response.status_code == 200, response.text
    body = response.text
    assert "Uploaded certificate" in body
    assert "endpoint" in body
    assert "unknown" in body.lower()
    assert "&lt;script&gt;uploaded label&lt;/script&gt;" in body
    assert "<script>uploaded label</script>" not in body
    assert "theme.css" in body
    assert "/console" in body
    assert "pat2389-test-key" not in body
    assert last_sent() is None
    assert not isolated["emails"]
