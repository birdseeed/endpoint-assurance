"""PAT-1111: dashboard half of the PAT-1108 agent-decommission contract."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


def _response(status, payload):
    response = MagicMock(status_code=status)
    response.content = json.dumps(payload).encode()
    response.text = json.dumps(payload)
    response.json.return_value = payload
    return response


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at) VALUES (?, ?, ?, ?)",
            ("client-1", "Acme Ltd", "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "2026-08-10T00:00:00Z"),
        )
    with TestClient(dashboard.app) as test_client:
        yield test_client


class TestProxyContract:
    def test_reads_current_directive_and_every_device_state(self, client):
        directive = {
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
            "mode": "expiry",
            "expires_at": "2026-09-01T00:00:00Z",
            "purge": True,
            "reason": "assessment complete",
            "set_by": "admin_shared_token",
            "set_at": "2026-08-10T10:00:00Z",
        }
        devices = {
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
            "total": 1,
            "devices": [{
                "device_id": "device-1",
                "hostname": "mac-01",
                "status": "pending",
                "last_reported_outcome": "",
                "last_reported_at": None,
                "terminal_without_acknowledgement": False,
            }],
        }

        def fake_get(url, **_kwargs):
            if url.endswith("/decommission/devices"):
                return _response(200, devices)
            return _response(200, directive)

        with patch.object(dashboard.http, "get", side_effect=fake_get) as mocked:
            current = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission", headers=BEARER)
            status = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission/devices", headers=BEARER)

        assert current.status_code == 200
        assert current.json() == directive
        assert status.status_code == 200
        assert status.json() == devices
        assert mocked.call_args_list[0].args[0].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission")
        assert mocked.call_args_list[1].args[0].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission/devices")

    def test_decommission_proxy_refuses_special_tenant_ids_before_any_upstream_call(self, client):
        """PAT-2408: a tenant id that is not a canonical UUID (here one that would
        once have been percent-encoded into the upstream path) is refused at the
        console's edge, so no upstream request is made for any of the three
        decommission routes."""
        with patch.object(dashboard.http, "get") as get, \
             patch.object(dashboard.http, "put") as put:
            current = client.get(
                "/admin/tenants/tenant%20special/decommission", headers=BEARER
            )
            status = client.get(
                "/admin/tenants/tenant%20special/decommission/devices", headers=BEARER
            )
            write = client.put(
                "/admin/tenants/tenant%20special/decommission",
                json={"mode": "none"},
                headers=BEARER,
            )

        assert current.status_code == status.status_code == write.status_code == 400
        get.assert_not_called()
        put.assert_not_called()

    def test_expiry_write_injects_authenticated_actor_and_is_locally_audited(self, client):
        before = {
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none", "expires_at": None,
            "purge": False, "reason": None, "set_by": "", "set_at": "",
        }
        after = {
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "expiry",
            "expires_at": "2099-09-01T00:00:00Z", "purge": True,
            "reason": "assessment complete", "set_by": "admin_shared_token",
            "set_at": "2026-08-10T10:00:00Z",
        }
        with patch.object(dashboard.http, "get", return_value=_response(200, before)), \
             patch.object(dashboard.http, "put", return_value=_response(200, after)) as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={
                    "mode": "expiry",
                    "expires_at": "2099-09-01T00:00:00Z",
                    "purge": True,
                    "reason": "assessment complete",
                    "actor": "spoofed@example.com",
                    "ignored": "not forwarded",
                },
                headers=BEARER,
            )

        assert response.status_code == 200
        forwarded = put.call_args.kwargs["json"]
        assert forwarded == {
            "mode": "expiry",
            "expires_at": "2099-09-01T00:00:00Z",
            "purge": True,
            "reason": "assessment complete",
            "actor": "bearer-token",
        }
        with dashboard.get_db() as db:
            audit = dict(db.execute(
                "SELECT path, outcome, before_value, after_value FROM admin_audit_log "
                "WHERE path=?", ("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",),
            ).fetchone())
        assert audit["outcome"] == "allowed"
        assert json.loads(audit["before_value"])["mode"] == "none"
        assert json.loads(audit["after_value"])["mode"] == "expiry"

    @pytest.mark.parametrize(
        "expires_at",
        [None, "", "   ", "2026-09-01", "2026-09-01T00:00:00", "not-a-timestamp"],
    )
    def test_expiry_rejects_missing_or_invalid_rfc3339_before_upstream(self, client, expires_at):
        body = {"mode": "expiry"}
        if expires_at is not None:
            body["expires_at"] = expires_at
        with patch.object(dashboard.http, "get") as get, \
             patch.object(dashboard.http, "put") as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json=body,
                headers=BEARER,
            )
        assert response.status_code == 400
        assert "RFC3339" in response.json()["error"]
        get.assert_not_called()
        put.assert_not_called()

    def test_expiry_rejects_past_timestamp_and_requires_immediate_mode(self, client):
        with patch.object(dashboard.http, "get") as get, \
             patch.object(dashboard.http, "put") as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "expiry", "expires_at": "2020-01-01T00:00:00Z"},
                headers=BEARER,
            )
        assert response.status_code == 400
        assert "future" in response.json()["error"]
        assert "immediate mode" in response.json()["error"]
        get.assert_not_called()
        put.assert_not_called()

    @pytest.mark.parametrize("reason", [{"nested": "value"}, ["value"], 123, "x" * 501])
    def test_reason_must_be_a_bounded_string_or_null(self, client, reason):
        with patch.object(dashboard.http, "get") as get, \
             patch.object(dashboard.http, "put") as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "none", "reason": reason},
                headers=BEARER,
            )
        assert response.status_code == 400
        assert "reason" in response.json()["error"]
        get.assert_not_called()
        put.assert_not_called()

    @pytest.mark.parametrize(
        ("before_payload", "expected_marker"),
        [
            ({"tenant_id": "another-tenant", "mode": "none"}, "tenant_mismatch"),
            (["not", "an", "object"], "unavailable"),
        ],
    )
    def test_before_audit_snapshot_rejects_unbound_upstream_data(
        self, client, before_payload, expected_marker
    ):
        after = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none"}
        with patch.object(dashboard.http, "get", return_value=_response(200, before_payload)), \
             patch.object(dashboard.http, "put", return_value=_response(200, after)):
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "none"},
                headers=BEARER,
            )
        assert response.status_code == 200
        with dashboard.get_db() as db:
            audit = db.execute(
                "SELECT before_value FROM admin_audit_log WHERE path=?",
                ("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",),
            ).fetchone()
        assert json.loads(audit["before_value"]) == {"read_error": expected_marker}

    def test_before_audit_snapshot_marks_read_failure_without_error_detail(self, client):
        after = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none"}
        with patch.object(dashboard.http, "get", side_effect=RuntimeError("sensitive upstream body")), \
             patch.object(dashboard.http, "put", return_value=_response(200, after)):
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "none"},
                headers=BEARER,
            )
        assert response.status_code == 200
        with dashboard.get_db() as db:
            audit = db.execute(
                "SELECT before_value FROM admin_audit_log WHERE path=?",
                ("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",),
            ).fetchone()
        assert json.loads(audit["before_value"]) == {"read_error": "unavailable"}
        assert "sensitive" not in audit["before_value"]

    @pytest.mark.parametrize(
        "after_payload",
        [
            {"tenant_id": "another-tenant", "mode": "none"},
            ["not", "an", "object"],
        ],
    )
    def test_success_audit_snapshot_rejects_invalid_upstream_response(self, client, after_payload):
        before = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none"}
        with patch.object(dashboard.http, "get", return_value=_response(200, before)), \
             patch.object(dashboard.http, "put", return_value=_response(200, after_payload)):
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "none", "reason": "must not become audit_after"},
                headers=BEARER,
            )
        assert response.status_code == 200
        with dashboard.get_db() as db:
            audit = db.execute(
                "SELECT after_value FROM admin_audit_log WHERE path=?",
                ("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",),
            ).fetchone()
        assert json.loads(audit["after_value"]) == {"read_error": "invalid_upstream_response"}
        assert "must not become audit_after" not in audit["after_value"]

    def test_failed_put_audit_records_bounded_attempt_without_actor_or_upstream_body(self, client):
        before = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none"}
        failed = _response(503, {"error": "sensitive upstream failure detail"})
        with patch.object(dashboard.http, "get", return_value=_response(200, before)), \
             patch.object(dashboard.http, "put", return_value=failed):
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={
                    "mode": "expiry",
                    "expires_at": "2099-09-01T00:00:00Z",
                    "purge": True,
                    "reason": "assessment complete",
                    "actor": "spoofed@example.com",
                },
                headers=BEARER,
            )
        assert response.status_code == 503
        with dashboard.get_db() as db:
            audit = db.execute(
                "SELECT outcome, after_value FROM admin_audit_log WHERE path=?",
                ("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",),
            ).fetchone()
        assert audit["outcome"] == "rejected_503"
        assert json.loads(audit["after_value"]) == {
            "write_error": "upstream_write_failed",
            "status_code": 503,
            "attempted": {
                "mode": "expiry",
                "expires_at": "2099-09-01T00:00:00Z",
                "purge": True,
                "reason": "assessment complete",
            },
        }
        assert "spoofed" not in audit["after_value"]
        assert "sensitive upstream" not in audit["after_value"]

    def test_put_connection_failure_retains_bounded_attempted_audit(self, client):
        before = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none"}
        with patch.object(dashboard.http, "get", return_value=_response(200, before)), \
             patch.object(dashboard.http, "put", side_effect=TimeoutError("secret connection detail")):
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "none", "reason": "cancel schedule"},
                headers=BEARER,
            )
        assert response.status_code == 502
        assert response.json() == {"error": "Platform decommission write unavailable"}
        with dashboard.get_db() as db:
            audit = db.execute(
                "SELECT outcome, before_value, after_value FROM admin_audit_log WHERE path=?",
                ("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",),
            ).fetchone()
        assert audit["outcome"] == "rejected_502"
        assert json.loads(audit["before_value"])["tenant_id"] == "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"
        assert json.loads(audit["after_value"]) == {
            "write_state": "attempted",
            "attempted": {
                "mode": "none",
                "expires_at": None,
                "purge": False,
                "reason": "cancel schedule",
            },
        }
        assert "secret connection" not in audit["after_value"]

    def test_immediate_write_requires_typed_tenant_name(self, client):
        response = client.put(
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
            json={"mode": "immediate", "purge": True},
            headers=BEARER,
        )
        assert response.status_code == 428
        assert "type the tenant name" in response.json()["error"]

        with patch.object(dashboard.http, "get", return_value=_response(200, {"tenants": []})):
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "immediate", "purge": True},
                headers={**BEARER, "X-Confirm-Resource": "Wrong tenant"},
            )
        assert response.status_code == 409

    def test_immediate_confirmation_rejects_tenant_id_even_when_name_is_resolved(self, client):
        with patch.object(dashboard.http, "get", return_value=_response(200, {"tenants": []})), \
             patch.object(dashboard.http, "put") as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "immediate"},
                headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
            )
        assert response.status_code == 409
        put.assert_not_called()

    def test_immediate_confirmation_fails_closed_when_local_tenant_has_no_name(self, client):
        with dashboard.get_db() as db:
            db.execute("UPDATE clients SET company='' WHERE tenant_id=?", ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac",))
        with patch.object(dashboard.http, "get", return_value=_response(200, {"tenants": []})), \
             patch.object(dashboard.http, "put") as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "immediate"},
                headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
            )
        assert response.status_code == 502
        put.assert_not_called()

    def test_immediate_confirmation_unions_local_and_current_platform_names(self, client):
        with dashboard.get_db() as db:
            db.execute(
                "UPDATE clients SET company=? WHERE tenant_id=?",
                ("Acme Legacy", "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"),
            )
        before = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "none"}
        after = {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "immediate"}

        def fake_get(url, **_kwargs):
            if url.endswith("/admin/tenants"):
                return _response(200, {
                    "tenants": [{"id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "name": "Acme Current"}],
                })
            if url.endswith("/admin/tenants/revoked"):
                return _response(200, {"tenants": []})
            return _response(200, before)

        with patch.object(dashboard.http, "get", side_effect=fake_get), \
             patch.object(dashboard.http, "put", return_value=_response(200, after)) as put:
            values, resolution = dashboard._resolve_decommission_tenant("fd46eac4-17e8-51ae-bb80-aba4a343c3ac")
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "immediate"},
                headers={**BEARER, "X-Confirm-Resource": "Acme Current"},
            )

        assert resolution == "resolved"
        assert values == {"acme legacy", "acme current"}
        assert "fd46eac4-17e8-51ae-bb80-aba4a343c3ac" not in values
        assert response.status_code == 200
        put.assert_called_once()

    @pytest.mark.parametrize(("upstream_status", "expected_status"), [(200, 404), (502, 502)])
    def test_immediate_write_distinguishes_missing_tenant_from_resolution_failure(
        self, client, upstream_status, expected_status
    ):
        with dashboard.get_db() as db:
            db.execute("DELETE FROM clients WHERE tenant_id=?", ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac",))
        with patch.object(
            dashboard.http, "get",
            return_value=_response(upstream_status, {"tenants": []}),
        ), patch.object(dashboard.http, "put") as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "immediate"},
                headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
            )
        assert response.status_code == expected_status
        put.assert_not_called()

    def test_purge_defaults_off_when_operator_does_not_select_it(self, client):
        before = {"mode": "none", "expires_at": None, "purge": False, "reason": None}
        after = {
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "expiry",
            "expires_at": "2099-09-01T00:00:00Z", "purge": False,
            "reason": None, "set_by": "admin_shared_token",
            "set_at": "2026-08-10T10:00:00Z",
        }
        with patch.object(dashboard.http, "get", return_value=_response(200, before)), \
             patch.object(dashboard.http, "put", return_value=_response(200, after)) as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={"mode": "expiry", "expires_at": "2099-09-01T00:00:00Z"},
                headers=BEARER,
            )

        assert response.status_code == 200
        assert put.call_args.kwargs["json"]["purge"] is False

    def test_immediate_write_forwards_exact_purge_contract_after_confirmation(self, client):
        before = {"mode": "none", "expires_at": None, "purge": False, "reason": None}
        after = {
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "mode": "immediate", "expires_at": None,
            "purge": True, "reason": "assessment complete",
            "set_by": "admin_shared_token", "set_at": "2026-08-10T10:00:00Z",
        }

        def fake_get(url, **_kwargs):
            if url.endswith("/admin/tenants") or url.endswith("/admin/tenants/revoked"):
                return _response(200, {"tenants": []})
            return _response(200, before)

        with patch.object(dashboard.http, "get", side_effect=fake_get), \
             patch.object(dashboard.http, "put", return_value=_response(200, after)) as put:
            response = client.put(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission",
                json={
                    "mode": "immediate", "expires_at": "ignored",
                    "purge": True, "reason": "assessment complete",
                },
                headers={**BEARER, "X-Confirm-Resource": "Acme Ltd"},
            )

        assert response.status_code == 200
        assert put.call_args.kwargs["json"] == {
            "mode": "immediate",
            "expires_at": None,
            "purge": True,
            "reason": "assessment complete",
            "actor": "bearer-token",
        }

    def test_customer_offboarding_does_not_issue_agent_removal(self, client):
        with patch.object(dashboard.http, "delete", return_value=_response(204, {})) as delete, \
             patch.object(dashboard.http, "get", return_value=_response(200, {"tenants": []})), \
             patch.object(dashboard.http, "put") as put:
            response = client.delete(
                "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
                headers={**BEARER, "X-Confirm-Resource": "Acme Ltd"},
            )
        assert response.status_code == 204
        assert delete.call_args.args[0].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac")
        put.assert_not_called()


class TestConsoleContract:
    def test_decommission_write_is_owner_only_and_audited(self):
        path = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/decommission"
        assert dashboard._consultant_write_allowed("PUT", path) is False
        assert dashboard._is_destructive("PUT", path) is True

    def test_console_exposes_separate_offboard_and_agent_removal_controls(self, client):
        response = client.get("/console")
        assert response.status_code == 200
        html = response.text
        assert "This does not remove Patched agents" in html
        assert "Remove Patched agents" in html
        assert "Review agent removal first" in html
        assert "dc-confirm-count" in html
        assert '<input id="dc-expiry-purge" type="checkbox">' in html
        assert '<input id="dc-confirm-purge" type="checkbox">' in html
        assert "purge: purge" in html
        assert "purge: true" not in html
        assert "terminal_without_acknowledgement" not in html  # helper owns wire normalisation
        assert "View devices" in html
        assert "Machine inventory and individual state live in Devices." in html
        assert "dc-device-tbody" not in html
        assert 'maxlength="500"' in html
        assert "/static/js/console-decommission.js?v=" + dashboard.CONSOLE_BUILD_ID in html

    def test_console_lifecycle_uses_aggregate_platform_status_without_duplicate_device_table(self, client):
        response = client.get("/console")
        assert response.status_code == 200
        html = response.text
        assert "'/decommission/devices'" in html
        assert "No removal directive is currently scheduled." in html
        assert "dc-table-wrap" not in html

    def test_console_separates_write_failure_from_readback_failure_and_hides_stale_content(self, client):
        response = client.get("/console")
        assert response.status_code == 200
        html = response.text
        assert "Directive write failed:" in html
        assert "Directive accepted, but read-back failed. Do not retry blindly" in html
        assert "loading.style.display = 'block';\n  content.style.display = 'none';\n  error.style.display = 'none';" in html
        assert "loading.style.display = 'none';\n    content.style.display = 'none';\n    error.textContent = 'Failed to load agent lifecycle:" in html
