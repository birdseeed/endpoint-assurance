"""
Tests for PAT-696 — Dashboard Phase 1: reusable danger-confirmation modal,
real environment banner, and the sidebar role indicator.

Focus is the server-side template context console_ui newly provides
(env, api_backend, role, actor_email) and how the rendered console.html reacts:

  - production env  → slim red strip + "PRODUCTION · <api-backend>" tag
  - dev/local env   → full-width amber "<ENV> — backend: <host>" banner
  - role chip text matches _role_for_email's decision for the session
  - window.__ROLE / __ENV / __ACTOR are injected for the client-side role gate
  - the env indicator is no longer hidden on tenant entry (regression guard)
  - the template still leaks no DASHBOARD_TOKEN (Phase 0 invariant holds)
"""

import os
import re
import sys
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


# The banner shows the host of PATCHED_API_INTERNAL. The suite pins that to an
# unroutable address (tests/conftest.py, PAT-2306), so derive the expected host
# from the value the app is actually using rather than hardcoding the prod one.
API_HOST = urlparse(dashboard.PATCHED_API_INTERNAL).hostname


# ── Environment banner ────────────────────────────────────────────────────────

class TestEnvironmentBanner:
    def test_production_shows_prod_tag_and_red_strip(self, client, monkeypatch):
        # DASHBOARD_ENV unset → env defaults to "production".
        monkeypatch.setattr(dashboard, "DASHBOARD_ENV", "")
        monkeypatch.setattr(dashboard, "_DEV_ENV", False)
        r = client.get("/console")
        assert r.status_code == 200
        assert ">Production</span>" in r.text
        assert "env-strip--prod" in r.text
        # The amber dev banner must NOT render in production.
        assert "env-banner--dev" not in r.text
        assert re.search(r'window\.__ENV\s*=\s*"production"', r.text)

    def test_dev_shows_amber_banner_with_backend_host(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_ENV", "dev")
        monkeypatch.setattr(dashboard, "_DEV_ENV", True)
        r = client.get("/console")
        assert r.status_code == 200
        assert "env-banner--dev" in r.text
        assert API_HOST
        assert "backend: " + API_HOST in r.text
        # No production strip/tag in a dev environment.
        assert "env-strip--prod" not in r.text
        assert "PRODUCTION · " not in r.text
        assert re.search(r'window\.__ENV\s*=\s*"dev"', r.text)

    def test_local_env_is_non_prod(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_ENV", "local")
        monkeypatch.setattr(dashboard, "_DEV_ENV", True)
        r = client.get("/console")
        assert "env-banner--dev" in r.text
        assert "env-strip--prod" not in r.text


# ── Role indicator ────────────────────────────────────────────────────────────

class TestRoleIndicator:
    def test_consultant_chip_when_operators_unset(self, client, monkeypatch):
        # No operators configured grants no session owner privileges.
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset())
        r = client.get("/console")
        assert r.status_code == 200
        assert "si-role-consultant" in r.text
        assert ">Consultant<" in r.text
        assert re.search(r'window\.__ROLE\s*=\s*"consultant"', r.text)

    def test_consultant_chip_for_non_operator_email(self, client, monkeypatch, verified_access_headers):
        monkeypatch.setattr(
            dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.get(
            "/console",
            headers=verified_access_headers("helper@partner.com"),
        )
        assert r.status_code == 200
        assert "si-role-consultant" in r.text
        assert ">Consultant<" in r.text
        assert re.search(r'window\.__ROLE\s*=\s*"consultant"', r.text)
        # The signed-in email is shown in the sidebar footer.
        assert "helper@partner.com" in r.text
        assert re.search(r'window\.__ACTOR\s*=\s*"helper@partner.com"', r.text)

    def test_owner_chip_for_operator_email(self, client, monkeypatch, verified_access_headers):
        monkeypatch.setattr(
            dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.get(
            "/console",
            headers=verified_access_headers("owner@patched.im"),
        )
        assert "si-role-owner" in r.text
        assert re.search(r'window\.__ROLE\s*=\s*"owner"', r.text)

    def test_role_matches_middleware_decision(self, client, monkeypatch, verified_access_headers):
        # The chip must reflect _role_for_email on the same identity the cookie
        # carries — the exact input the api_bearer_auth middleware uses.
        monkeypatch.setattr(
            dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        for email, expected in [
            ("owner@patched.im", "owner"),
            ("someone@else.com", "consultant"),
        ]:
            assert dashboard._role_for_email(email) == expected
            r = client.get(
                "/console",
                headers=verified_access_headers(email),
            )
            assert re.search(r'window\.__ROLE\s*=\s*"%s"' % expected, r.text)


# ── Danger-confirm modal + danger zone are present in markup ──────────────────

class TestDangerSurfaces:
    def test_danger_confirm_helper_present(self, client):
        r = client.get("/console")
        assert "function dangerConfirm(" in r.text

    def test_danger_zone_block_on_account_tab(self, client):
        r = client.get("/console")
        assert 'class="danger-zone owner-only"' in r.text
        assert "Danger zone" in r.text

    def test_no_bare_confirm_on_converted_destructive_paths(self, client):
        # The four flagship flows plus the delete operations now route through
        # dangerConfirm — none of their old bare confirm() strings survive.
        r = client.get("/console")
        for gone in [
            "This removes the device and all its compliance data. This cannot be undone.",
            "Delete this webhook? Delivery history will also be removed.",
            'Delete schedule "',
        ]:
            assert gone not in r.text


# ── Regression guards ─────────────────────────────────────────────────────────

class TestRegressionGuards:
    def test_env_indicator_not_hidden_on_tenant_entry(self, client):
        # PAT-696 removed the code that hid the env badge inside tenant
        # workspaces. The old querySelector must be gone.
        r = client.get("/console")
        assert ".sidebar .env-badge" not in r.text

    def test_console_still_has_no_embedded_token(self, client):
        r = client.get("/console")
        assert r.status_code == 200
        assert "DASHBOARD_TOKEN" not in r.text
        assert "test-key" not in r.text
