"""
Tests for PAT-218 cert helpers and API.

Covers:
  - classify_cert_type — one test per type + precedence test
  - compute_days_until_expiry — expired, future, UTC-correct
  - GET /api/tenant/{id}/certs — classification + ?type= filter (integration)
  - Snapshot tests for cert digest email render (HTML + text)
"""

import os
import sys
import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

from certs import classify_cert_type, compute_days_until_expiry


# ── classify_cert_type ────────────────────────────────────────────────────────

def _cert(**kw) -> dict:
    base = {
        "device_id": "dev-uuid",
        "subject_cn": "Test",
        "issuer_cn": "",
        "sha1": "abc123",
        "not_after": "2027-01-01T00:00:00Z",
        "days_until_expiry_at_collection": 365,
        "ext_key_usage": [],
        "basic_constraints_ca": False,
        "is_self_signed": False,
        "collected_at": "2026-12-01T00:00:00Z",
    }
    base.update(kw)
    return base


class TestClassifyCertType:
    def test_code_signing(self):
        c = _cert(ext_key_usage=["1.3.6.1.5.5.7.3.3"], basic_constraints_ca=False, is_self_signed=False)
        assert classify_cert_type(c) == "code_signing"

    def test_mdm_issued_mdm(self):
        c = _cert(issuer_cn="MDM Certificate Authority")
        assert classify_cert_type(c) == "mdm_issued"

    def test_mdm_issued_apns(self):
        c = _cert(issuer_cn="Apple Push Services: com.example")
        assert classify_cert_type(c) == "mdm_issued"

    def test_mdm_issued_mobile_device_management(self):
        c = _cert(issuer_cn="Mobile Device Management Authority")
        assert classify_cert_type(c) == "mdm_issued"

    def test_apple_pki(self):
        c = _cert(issuer_cn="Apple Root CA")
        assert classify_cert_type(c) == "apple_pki"

    def test_apple_pki_case_insensitive(self):
        c = _cert(issuer_cn="APPLE WORLDWIDE DEVELOPER RELATIONS")
        assert classify_cert_type(c) == "apple_pki"

    def test_ca_root(self):
        c = _cert(basic_constraints_ca=True, is_self_signed=True)
        assert classify_cert_type(c) == "ca_root"

    def test_intermediate(self):
        c = _cert(basic_constraints_ca=True, is_self_signed=False)
        assert classify_cert_type(c) == "intermediate"

    def test_leaf(self):
        c = _cert(basic_constraints_ca=False, is_self_signed=False)
        assert classify_cert_type(c) == "leaf"

    def test_precedence_code_signing_beats_leaf(self):
        # A cert with code_signing EKU that would otherwise classify as leaf
        c = _cert(ext_key_usage=["1.3.6.1.5.5.7.3.3"], basic_constraints_ca=False, is_self_signed=False)
        assert classify_cert_type(c) == "code_signing"

    def test_precedence_code_signing_beats_apple_pki(self):
        # Code signing beats apple_pki
        c = _cert(ext_key_usage=["1.3.6.1.5.5.7.3.3"], issuer_cn="Apple Certification Authority")
        assert classify_cert_type(c) == "code_signing"

    def test_missing_fields_returns_leaf(self):
        # Minimal cert with no CA flag
        c = {"device_id": "x", "ext_key_usage": None, "issuer_cn": None,
             "basic_constraints_ca": False, "is_self_signed": False,
             "not_after": "2027-07-01T00:00:00Z", "collected_at": "2026-07-01T00:00:00Z"}
        assert classify_cert_type(c) == "leaf"


# ── compute_days_until_expiry ─────────────────────────────────────────────────

class TestComputeDaysUntilExpiry:
    def test_future_returns_positive(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = _cert(not_after=future)
        result = compute_days_until_expiry(c)
        assert result >= 29  # allow for second boundaries
        assert result <= 30

    def test_expired_returns_negative(self):
        past = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = _cert(not_after=past)
        result = compute_days_until_expiry(c)
        assert result < 0

    def test_utc_handling_zulu(self):
        # Zulu notation parsed correctly
        future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = _cert(not_after=future)
        result = compute_days_until_expiry(c)
        assert 9 <= result <= 10

    def test_zero_at_boundary(self):
        # A cert expiring within the next 24 hours but not yet expired
        soon = (datetime.now(timezone.utc) + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = _cert(not_after=soon)
        result = compute_days_until_expiry(c)
        assert result == 0

    def test_floor_division(self):
        # 1 day + 23 hours = 1 whole day
        future = (datetime.now(timezone.utc) + timedelta(days=1, hours=23)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = _cert(not_after=future)
        result = compute_days_until_expiry(c)
        assert result == 1


# ── Integration: GET /api/tenant/{id}/certs with classification + filter ──────

import main as dashboard
from fastapi.testclient import TestClient

MOCK_CERT_ROWS = [
    {
        "device_id": "dev-1",
        "subject_cn": "CodeSigning Cert",
        "issuer_cn": "Test CA",
        "sha1": "aaa",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_until_expiry_at_collection": 200,
        "ext_key_usage": ["1.3.6.1.5.5.7.3.3"],
        "basic_constraints_ca": False,
        "is_self_signed": False,
        "collected_at": "2026-12-01T00:00:00Z",
    },
    {
        "device_id": "dev-2",
        "subject_cn": "MDM Leaf",
        "issuer_cn": "MDM Certificate Authority",
        "sha1": "bbb",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=50)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_until_expiry_at_collection": 50,
        "ext_key_usage": [],
        "basic_constraints_ca": False,
        "is_self_signed": False,
        "collected_at": "2026-12-01T00:00:00Z",
    },
    {
        "device_id": "dev-3",
        "subject_cn": "Root CA",
        "issuer_cn": "Self-Signed Root",
        "sha1": "ccc",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=3650)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_until_expiry_at_collection": 3650,
        "ext_key_usage": [],
        "basic_constraints_ca": True,
        "is_self_signed": True,
        "collected_at": "2026-12-01T00:00:00Z",
    },
]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _auth_headers():
    return {"Authorization": "Bearer test-key"}


def test_certs_endpoint_classifies_all(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = MOCK_CERT_ROWS

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get("/api/tenant/0fdfec2c-b3ee-5306-bcf1-0fc1294aa236/certs", headers=_auth_headers())

    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 3
    types = {row["subject_cn"]: row["type"] for row in rows}
    assert types["CodeSigning Cert"] == "code_signing"
    assert types["MDM Leaf"] == "mdm_issued"
    assert types["Root CA"] == "ca_root"


def test_certs_endpoint_type_filter(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = MOCK_CERT_ROWS

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get("/api/tenant/0fdfec2c-b3ee-5306-bcf1-0fc1294aa236/certs?type=code_signing", headers=_auth_headers())

    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["type"] == "code_signing"


def test_certs_endpoint_multi_type_filter(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = MOCK_CERT_ROWS

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get("/api/tenant/0fdfec2c-b3ee-5306-bcf1-0fc1294aa236/certs?type=code_signing,ca_root", headers=_auth_headers())

    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2
    returned_types = {row["type"] for row in rows}
    assert returned_types == {"code_signing", "ca_root"}


def test_certs_endpoint_upstream_404_passthrough(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {"error": "tenant not found"}

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get("/api/tenant/2bbd50ac-5eb7-5977-b56a-742b62c69604/certs", headers=_auth_headers())

    assert r.status_code == 404


def test_certs_endpoint_requires_auth(client):
    r = client.get("/api/tenant/0fdfec2c-b3ee-5306-bcf1-0fc1294aa236/certs")
    assert r.status_code == 401


def test_certs_endpoint_days_until_expiry_computed_live(client):
    # days_until_expiry_at_collection is 200 but actual not_after is 10 days from now
    ten_days = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = dict(MOCK_CERT_ROWS[0], not_after=ten_days, days_until_expiry_at_collection=200)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [row]

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get("/api/tenant/0fdfec2c-b3ee-5306-bcf1-0fc1294aa236/certs", headers=_auth_headers())

    result = r.json()[0]
    # Live computation should give ~10, NOT the audit value 200
    assert result["days_until_expiry"] <= 10
    assert result["days_until_expiry"] >= 9


# ── Snapshot tests for cert digest email render ───────────────────────────────

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def _email_env():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )


FIXTURE_CERTS_ALL = [
    {
        "subject_cn": "Expired Code Sign",
        "issuer_cn": "Test CA",
        "type": "code_signing",
        "days_until_expiry": -3,
        "not_after": "2026-12-08T00:00:00Z",
        "device_id": "dev-1",
    },
    {
        "subject_cn": "Critical MDM Cert",
        "issuer_cn": "MDM CA",
        "type": "mdm_issued",
        "days_until_expiry": 5,
        "not_after": "2026-12-16T00:00:00Z",
        "device_id": "dev-2",
    },
    {
        "subject_cn": "Warning Leaf",
        "issuer_cn": "Apple Root CA",
        "type": "apple_pki",
        "days_until_expiry": 22,
        "not_after": "2026-07-03T00:00:00Z",
        "device_id": "dev-3",
    },
    {
        "subject_cn": "Healthy Root",
        "issuer_cn": "Self-Signed",
        "type": "ca_root",
        "days_until_expiry": 365,
        "not_after": "2027-06-11T00:00:00Z",
        "device_id": "dev-4",
    },
]


def test_cert_digest_email_html_renders(tmp_path):
    env = _email_env()
    template = env.get_template("cert_digest_email.html")
    html = template.render(
        tenant_name="Acme Corp",
        certs=FIXTURE_CERTS_ALL,
        band="all_categorised",
        severity_label="All Categorised",
        cert_view_url="https://dashboard.patched.im/certs?tenant_id=test-uuid",
        counts={"expired": 1, "critical": 1, "warning": 1, "healthy": 1},
    )
    assert "Acme Corp" in html
    assert "Expired Code Sign" in html
    assert "Critical MDM Cert" in html
    assert "cert_digest_email" not in html  # template name must not leak


def test_cert_digest_email_txt_renders(tmp_path):
    env = _email_env()
    template = env.get_template("cert_digest_email.txt")
    text = template.render(
        tenant_name="Acme Corp",
        certs=FIXTURE_CERTS_ALL,
        band="all_categorised",
        severity_label="All Categorised",
        cert_view_url="https://dashboard.patched.im/certs?tenant_id=test-uuid",
        counts={"expired": 1, "critical": 1, "warning": 1, "healthy": 1},
    )
    assert "Acme Corp" in text
    assert "Expired Code Sign" in text


def test_cert_digest_email_html_expired_only_renders(tmp_path):
    env = _email_env()
    template = env.get_template("cert_digest_email.html")
    expired = [c for c in FIXTURE_CERTS_ALL if c["days_until_expiry"] < 0]
    html = template.render(
        tenant_name="Acme Corp",
        certs=expired,
        band="expired_only",
        severity_label="Expired Only",
        cert_view_url="https://dashboard.patched.im/certs?tenant_id=test-uuid",
        counts={"expired": 1, "critical": 0, "warning": 0, "healthy": 0},
    )
    assert "Expired Code Sign" in html
    assert "Critical MDM Cert" not in html
