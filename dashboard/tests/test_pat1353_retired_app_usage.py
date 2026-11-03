"""PAT-1353: retire the unused duplicate app_usage telemetry surface."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


AUTH = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/admin/tenants/43882d91-77e2-5cbc-a276-ec2a61d20db4/app-usage"),
        ("GET", "/admin/tenants/43882d91-77e2-5cbc-a276-ec2a61d20db4/app-usage/App/devices"),
        ("PUT", "/admin/tenants/43882d91-77e2-5cbc-a276-ec2a61d20db4/usage-tracking"),
    ],
)
def test_duplicate_app_usage_proxy_routes_are_retired(client, method, path):
    response = client.request(method, path, headers=AUTH)
    assert response.status_code == 404


def test_authoritative_metering_proxy_remains(client, monkeypatch):
    class Response:
        status_code = 200
        content = b'{"apps":[]}'

        @staticmethod
        def json():
            return {"apps": []}

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Response())
    response = client.get("/admin/tenants/43882d91-77e2-5cbc-a276-ec2a61d20db4/metering", headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {"apps": []}
