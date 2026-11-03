"""
Tests for PAT-456 hardening fixes.

Covers:
  - _safe_filename — path traversal prevention
  - Bearer middleware on /admin/* — 401 without token, pass-through with token
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient


# ── _safe_filename ────────────────────────────────────────────────────────────

class TestSafeFilename:
    def test_path_traversal_dotdot_slash(self):
        assert dashboard._safe_filename("../../etc/passwd", "default.csv") == "passwd"

    def test_path_traversal_backslash(self):
        # Windows-style traversal: ..\etc\passwd → basename after normalisation
        assert dashboard._safe_filename("..\\etc\\passwd", "default.csv") == "passwd"

    def test_empty_string_returns_default(self):
        assert dashboard._safe_filename("", "default.csv") == "default.csv"

    def test_none_like_empty_returns_default(self):
        # None is cast to "" via `(name or "")`
        assert dashboard._safe_filename(None, "default.csv") == "default.csv"

    def test_bare_dotdot_returns_default(self):
        assert dashboard._safe_filename("..", "default.csv") == "default.csv"

    def test_bare_dot_returns_default(self):
        assert dashboard._safe_filename(".", "default.csv") == "default.csv"

    def test_normal_name_passes_through(self):
        assert dashboard._safe_filename("devices.csv", "default.csv") == "devices.csv"

    def test_leading_dots_stripped(self):
        # ".hidden" → "hidden" (lstrip(". "))
        result = dashboard._safe_filename(".hidden_file.csv", "default.csv")
        assert not result.startswith(".")

    def test_length_capped_at_128(self):
        long_name = "a" * 200 + ".csv"
        result = dashboard._safe_filename(long_name, "default.csv")
        assert len(result) <= 128

    def test_composed_path_stays_inside_scan_dir(self, tmp_path):
        # C1 regression: a traversal filename must resolve to a path *inside*
        # the scan dir, never escape it.
        scan_dir = tmp_path / "scan123"
        scan_dir.mkdir()
        for attack in ("../../main.py", "..\\..\\main.py", "/etc/passwd", ".."):
            p = scan_dir / dashboard._safe_filename(attack, "devices.csv")
            # Must not raise — resolved path is under scan_dir.
            p.resolve().relative_to(scan_dir.resolve())


# ── /admin/* bearer middleware ────────────────────────────────────────────────

def _auth_headers():
    return {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


class TestAdminBearerAuth:
    def test_get_tenants_no_token_is_401(self, client):
        r = client.get("/admin/tenants")
        assert r.status_code == 401
        assert r.json()["error"] == "Unauthorized"

    def test_get_tenants_wrong_token_is_401(self, client):
        r = client.get("/admin/tenants", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_get_tenants_with_token_proxies_upstream(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"tenants": []}
        with patch.object(dashboard.http, "get", return_value=mock_resp):
            r = client.get("/admin/tenants", headers=_auth_headers())
        assert r.status_code == 200
        assert r.json() == {"tenants": []}

    def test_post_tenants_no_token_is_401(self, client):
        r = client.post("/admin/tenants", json={"name": "Acme"})
        assert r.status_code == 401

    def test_post_tenants_with_token_proxies_upstream(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"tenant_id":"t-1","token":"tok"}'
        mock_resp.json.return_value = {"tenant_id": "t-1", "token": "tok"}
        with patch.object(dashboard.http, "post", return_value=mock_resp):
            r = client.post(
                "/admin/tenants",
                json={"name": "Acme"},
                headers={**_auth_headers(), "Content-Type": "application/json"},
            )
        assert r.status_code == 200
