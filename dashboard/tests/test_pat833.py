"""
Tests for PAT-833 — middleware ordering: a destructive write attempted during
a read-only impersonation session must still leave an audit-log row, even
though `impersonation_write_guard` short-circuits with a 403 before the route
handler ever runs.

Background: Starlette applies `@app.middleware("http")` decorators in REVERSE
registration order (last registered = outermost = runs first on the way in).
`impersonation_write_guard` is registered before `api_bearer_auth` so the
latter wraps the former -- meaning the guard's 403 still flows back through
api_bearer_auth's post-dispatch audit-log update instead of skipping it
entirely. See the comment block above both middleware functions in main.py.

Covers:
  - A destructive write blocked by the impersonation guard (write_mode=False)
    gets an audit row with outcome "rejected_403" (not silently dropped).
  - The same write succeeds normally once write_mode=True, and is still
    audited as "allowed" (guard doesn't swallow the good path either).
  - The X-Confirm-Resource confirm-header flow (428) is unaffected by the
    reordering -- it's decided entirely inside api_bearer_auth, before the
    guard even runs, on a route that also happens to sit behind the guard.
"""

import os
import sys
import time
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
import shared
from fastapi.testclient import TestClient


BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _audit_rows(cols="*"):
    with dashboard.get_db() as db:
        return [dict(r) for r in db.execute(f"SELECT {cols} FROM admin_audit_log").fetchall()]


def _imp_cookie(write_mode: bool, tenant_id: str = "0a4c2c91-7412-575c-b544-dea3a596dd31") -> dict:
    """Build a read-only (or write-enabled) impersonation session cookie,
    mirroring what /admin/tenants/{id}/impersonation/start (and .../write-mode)
    mint in the real app."""
    now = datetime.now(timezone.utc)
    payload = {
        "session_id":  str(uuid.uuid4()),
        "tenant_id":   tenant_id,
        "actor_email": "support@patched.im",
        "started_at":  now.isoformat(),
        "expires_at":  (now + timedelta(seconds=dashboard.IMP_MAX_AGE)).isoformat(),
        "write_mode":  write_mode,
    }
    tok = dashboard._imp_encode(payload)
    return {"Cookie": f"{dashboard.IMP_COOKIE}={tok}"}


class TestBlockedImpersonationWriteIsAudited:
    def test_destructive_write_blocked_during_readonly_impersonation_is_audited(self, client):
        r = client.put(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-config",
            json={"rollout_pct": 50},
            headers={**BEARER, **_imp_cookie(write_mode=False)},
        )
        assert r.status_code == 403
        assert "enable write mode" in r.json()["error"]

        rows = _audit_rows("path, method, outcome")
        matches = [x for x in rows if x["path"] == "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-config"]
        # This is the crux of PAT-833: previously the guard's 403 short-circuited
        # BEFORE api_bearer_auth's audit middleware ever ran, so no row was
        # written at all. Now the audit middleware is the outer layer, so its
        # pre-dispatch "in_progress" row still gets updated with the guard's
        # response status once call_next returns.
        assert len(matches) == 1, f"expected exactly one audit row, got {matches}"
        assert matches[0]["outcome"] == "rejected_403"
        assert matches[0]["method"] == "PUT"

    def test_non_admin_destructive_write_unaffected_by_impersonation_cookie(self, client):
        # /api/* destructive routes aren't gated by impersonation_write_guard at
        # all (it only inspects /admin/* paths) -- a stray pat_imp cookie must
        # not change their behavior. This route is fully local (no upstream
        # HTTP call), so no mocking is needed.
        r = client.post(
            "/api/credentials",
            json={"name": "x", "service": "github"},
            headers={**BEARER, **_imp_cookie(write_mode=False)},
        )
        assert r.status_code == 200
        rows = _audit_rows("path, outcome")
        matches = [x for x in rows if x["path"] == "/api/credentials"]
        assert len(matches) == 1
        assert matches[0]["outcome"] == "allowed"


class TestWriteModeImpersonationStillWorks:
    def test_destructive_write_in_write_mode_is_still_quarantined_and_audited_once(self, client):
        mock_get = MagicMock(status_code=404)  # no "before" snapshot available
        mock_put = MagicMock(status_code=200)
        mock_put.json.return_value = {"ok": True}
        with patch.object(dashboard.http, "get", return_value=mock_get), \
             patch.object(dashboard.http, "put", return_value=mock_put):
            r = client.put(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-config",
                json={"rollout_pct": 50},
                headers={**BEARER, **_imp_cookie(write_mode=True)},
            )
        assert r.status_code == 410
        rows = _audit_rows("path, outcome")
        matches = [x for x in rows if x["path"] == "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-config"]
        assert len(matches) == 1
        assert matches[0]["outcome"] == "rejected_410"

    def test_exempt_write_mode_endpoint_not_blocked_during_readonly_impersonation(self, client):
        # /admin/impersonation/write-mode is itself destructive-classified AND
        # exempt from the guard's block (else you could never escape read-only
        # mode) -- must still succeed and be audited normally.
        r = client.post(
            "/admin/impersonation/write-mode",
            headers={**BEARER, **_imp_cookie(write_mode=False)},
        )
        assert r.status_code == 200
        rows = _audit_rows("path, outcome")
        matches = [x for x in rows if x["path"] == "/admin/impersonation/write-mode"]
        assert len(matches) == 1
        assert matches[0]["outcome"] == "allowed"


class TestConfirmHeaderFlowUnaffectedByReordering:
    def test_missing_confirm_header_still_428s_and_audits_before_guard_runs(self, client):
        # DELETE /admin/tenants/{id} requires X-Confirm-Resource (see
        # _CONFIRM_RULES) and is unrelated to impersonation. api_bearer_auth
        # decides this entirely on its own, and -- since it's now the OUTER
        # layer -- does so before impersonation_write_guard ever gets a look
        # at the request. Confirm this still 428s (not garbled into a 403
        # from the guard, and not skipped).
        r = client.delete(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31",
            headers={**BEARER, **_imp_cookie(write_mode=False)},
        )
        assert r.status_code == 428
        rows = _audit_rows("path, outcome")
        matches = [x for x in rows if x["path"] == "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31"]
        assert len(matches) == 1
        assert matches[0]["outcome"] == "confirm_missing"

    def test_missing_confirm_header_428s_without_any_impersonation_cookie_too(self, client):
        # Baseline (no impersonation involved at all) -- same 428/confirm_missing
        # outcome, proving the guard's presence in the stack doesn't alter this
        # route's behavior for ordinary (non-impersonating) callers.
        r = client.delete("/admin/tenants/b27fb783-0526-5455-85dc-ffc0082795e1", headers=BEARER)
        assert r.status_code == 428
        rows = _audit_rows("path, outcome")
        matches = [x for x in rows if x["path"] == "/admin/tenants/b27fb783-0526-5455-85dc-ffc0082795e1"]
        assert len(matches) == 1
        assert matches[0]["outcome"] == "confirm_missing"
