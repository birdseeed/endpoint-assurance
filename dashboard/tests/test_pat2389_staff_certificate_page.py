"""The staff certificate view fails closed without exposing upstream details."""
import time
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import main as dashboard


@pytest.fixture
def staff_page(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "staff-page.db")
    monkeypatch.setattr(dashboard, "DASHBOARD_API_KEY", "test-key")
    fetch = Mock()
    monkeypatch.setattr(dashboard.http, "get", fetch)
    with TestClient(dashboard.app, raise_server_exceptions=False) as client:
        yield client, fetch


def sign_in(client):
    token = dashboard._session_encode("staff@example.invalid", int(time.time()) + 3600)
    client.cookies.set(dashboard.SESSION_COOKIE, token)


def test_staff_page_requires_session_before_reading_upstream(staff_page, verified_access_headers):
    client, fetch = staff_page
    response = client.get("/certs?tenant_id=56a0c11e-f3a4-5828-bd81-8a0701466473", headers=verified_access_headers("staff@example.invalid"))
    assert response.status_code == 401
    fetch.assert_not_called()


@pytest.mark.parametrize("tenant", ["", "../other", "estate/certs", "estate?device_id=other"])
def test_invalid_estate_selector_never_becomes_an_upstream_path(staff_page, tenant):
    client, fetch = staff_page
    sign_in(client)
    response = client.get("/certs", params={"tenant_id": tenant})
    assert response.status_code == 400
    assert "Select an estate" in response.text
    assert response.headers["cache-control"] == "no-store"
    fetch.assert_not_called()


@pytest.mark.parametrize("failure", ["unavailable", "invalid_json", "wrong_shape", "exception"])
def test_staff_page_upstream_failure_is_safe_and_retryable(staff_page, failure):
    client, fetch = staff_page
    sign_in(client)
    fetch.return_value = Mock(status_code=503 if failure == "unavailable" else 200)
    if failure == "exception":
        fetch.side_effect = RuntimeError("upstream-secret-detail")
    elif failure == "invalid_json":
        fetch.return_value.json.side_effect = ValueError("upstream-secret-detail")
    else:
        fetch.return_value.json.return_value = {"detail": "upstream-secret-detail"}
    response = client.get("/certs?tenant_id=56a0c11e-f3a4-5828-bd81-8a0701466473")
    assert response.status_code == 503
    assert "Certificate inventory is unavailable" in response.text
    assert "upstream-secret-detail" not in response.text
    assert "test-key" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_staff_page_empty_inventory_is_not_an_error(staff_page):
    client, fetch = staff_page
    sign_in(client)
    fetch.return_value = Mock(status_code=200, json=lambda: [])
    response = client.get("/certs?tenant_id=56a0c11e-f3a4-5828-bd81-8a0701466473")
    assert response.status_code == 200
    assert "No certificates are recorded" in response.text
    assert response.headers["cache-control"] == "no-store"
