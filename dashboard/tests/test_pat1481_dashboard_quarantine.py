"""PAT-1481: Dashboard exposes assurance and governance, not legacy execution."""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}
ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


# Every actual FastAPI mutation selected by the quarantine rules. Keep this in
# lock-step with the route table, not just the regex count: a single broad
# regex can cover several handlers, each of which must be blocked before it
# can contact an execution-capable upstream or write locally.
QUARANTINE_CASES = [
    ("POST", "/admin/automations/installomator_sync/trigger"),
    ("POST", "/admin/devices/device-1/removals"),
    ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-config"),
    ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-devices/device-1"),
    # PAT-2299 removed the rollout-create proxy and its rule; see
    # test_pat2249_catalogue_pipeline_retired.py.
    ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-rollouts/rollout-1/resume"),
    ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-rollouts/rollout-1/skip"),
    ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-rollouts/rollout-1/emergency"),
    ("PATCH", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/app-rings/com.example.app"),
    # PAT-2249 removed the local catalogue, hosting-outreach and catalogue
    # review routes, and their quarantine rules with them; see
    # test_pat2249_catalogue_pipeline_retired.py.
]


def _audit_rows(path):
    with dashboard.get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT method, path, outcome FROM admin_audit_log WHERE path=?", (path,)
        ).fetchall()]


def _imp_cookie(write_mode=False):
    now = datetime.now(timezone.utc)
    token = dashboard._imp_encode({
        "session_id": str(uuid.uuid4()), "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
        "actor_email": "owner@patched.im", "started_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=dashboard.IMP_MAX_AGE)).isoformat(),
        "write_mode": write_mode,
    })
    return {"Cookie": f"{dashboard.IMP_COOKIE}={token}"}


@pytest.mark.parametrize(("method", "path"), QUARANTINE_CASES)
def test_every_legacy_execution_rule_rejects_before_handler_and_audits_once(client, monkeypatch, method, path):
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: pytest.fail("upstream POST called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    monkeypatch.setattr(dashboard.http, "patch", lambda *_args, **_kwargs: pytest.fail("upstream PATCH called"))
    monkeypatch.setattr(dashboard.http, "delete", lambda *_args, **_kwargs: pytest.fail("upstream DELETE called"))

    response = client.request(method, path, json={}, headers=BEARER)

    assert response.status_code == 410
    assert response.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": "rejected_410"}]


def test_quarantine_rules_select_exactly_the_documented_fastapi_mutations():
    """No dead regex and no mutation route that is only incidentally untested."""
    actual = {(method, path) for method, path in QUARANTINE_CASES}
    assert len(actual) == len(QUARANTINE_CASES)
    assert {method for method, _path in actual} <= {"POST", "PUT", "PATCH"}
    # Keep the test inputs tied to a real route as well as the rule matcher.
    for method, path in actual:
        assert dashboard._is_legacy_execution_quarantined(method, path)
        assert any(
            method in getattr(route, "methods", set()) and route.path_regex.match(path)
            for route in dashboard.app.routes
        )
    # Conversely, every configured regex must select at least one actual
    # handler represented above, so an obsolete rule cannot claim protection.
    for method, rule in dashboard._LEGACY_EXECUTION_QUARANTINE_RULES:
        assert any(method == case_method and rule.match(path) for case_method, path in actual)


def test_cancellation_routes_are_not_quarantined(client):
    # New-app review records a tenant policy decision. It is not a package,
    # Self Service or app-removal request.
    assert not dashboard._is_legacy_execution_quarantined("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/new-apps/app-1")
    assert not dashboard._is_legacy_execution_quarantined("DELETE", "/admin/devices/device-1/removals/task-1")
    assert not dashboard._is_legacy_execution_quarantined("DELETE", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/extension-removals/request-1")
    assert not dashboard._is_legacy_execution_quarantined("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-rollouts/rollout-1/pause")
    assert not dashboard._is_legacy_execution_quarantined("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/extension-removals")


@pytest.mark.parametrize(
    ("payload", "status"),
    [({}, 400), ({"decision": "approve_no_patch"}, 410), ({"decision": "install"}, 410)],
)
def test_new_app_route_rejects_non_governance_decisions_before_upstream(
    client, monkeypatch, payload, status,
):
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    response = client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/new-apps/app-1", json=payload, headers=BEARER)
    assert response.status_code == status
    if status == 410:
        assert response.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY


@pytest.mark.parametrize(
    "body",
    [
        b'{"decision":"approve","Decision":"remove"}',
        b'{"decision":"approve","decision":"remove"}',
        b'{"Decision":"approve"}',
        b'{"decision":null}',
        b'{"decision":true}',
        b'{"decision":1}',
        b'{"decision":NaN}',
        b'{"decision":[]}',
        b'{"decision":{}}',
        b'{"decision":"approve"}{"decision":"remove"}',
        b'{malformed',
    ],
)
def test_new_app_route_rejects_ambiguous_or_malformed_decisions_before_upstream(
    client, monkeypatch, body,
):
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))

    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/new-apps/app-1",
        content=body,
        headers={**BEARER, "Content-Type": "application/json"},
    )

    assert response.status_code == 400


def test_new_app_route_rejects_body_over_bounded_put_limit_before_upstream(client, monkeypatch):
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    prefix = b'{"decision":"approve","padding":"'
    body = prefix + (b"a" * (4097 - len(prefix) - 2)) + b'"}'
    assert len(body) == 4097

    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/new-apps/app-1",
        content=body,
        headers={**BEARER, "Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_new_app_remove_value_records_policy_without_requesting_endpoint_removal(client, monkeypatch):
    upstream = dashboard.requests.Response()
    upstream.status_code = 200
    upstream.encoding = "utf-8"
    upstream._content = b'{"ok":true}'
    seen = {}

    def fake_put(url, **kwargs):
        seen.update(url=url, body=kwargs.get("data"))
        return upstream

    monkeypatch.setattr(dashboard.http, "put", fake_put)
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/new-apps/app-1",
        json={"decision": "remove"},
        headers=BEARER,
    )

    assert response.status_code == 200
    assert seen["url"].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/new-apps/app-1")
    assert b'"decision":"remove"' in seen["body"]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist"),
        ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7"),
    ],
)
def test_allowlist_rejects_legacy_uninstall_enforcement_before_upstream(client, monkeypatch, method, path):
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: pytest.fail("upstream POST called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))

    response = client.request(method, path, json={"enforcement": "marked_for_uninstall"}, headers=BEARER)

    assert response.status_code == 410
    assert response.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": "rejected_410"}]


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", b'{"EnFoRcEmEnT":"marked_for_uninstall"}', 410),
        ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7", b'{"ENFORCEMENT":"marked_for_uninstall"}', 410),
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", b'{"enforcement":"allowed","Enforcement":"allowed"}', 400),
        ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7", b'{"enforcement":"allowed","ENFORCEMENT":"marked_for_uninstall"}', 410),
    ],
)
def test_allowlist_rejects_case_insensitive_or_ambiguous_uninstall_enforcement_before_upstream(
    client, monkeypatch, method, path, body, status,
):
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: pytest.fail("upstream POST called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))

    response = client.request(
        method, path, content=body, headers={**BEARER, "Content-Type": "application/json"},
    )

    assert response.status_code == status
    if status == 410:
        assert response.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": f"rejected_{status}"}]


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", b'{"enforcement":"allowed"}{"enforcement":"marked_for_uninstall"}'),
        ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7", b'{"enforcement":"allowed"} trailing'),
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", b'{"Enforcement":"allowed"}'),
        ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7", b'{"enforcement":"allowed","enforcement":"allowed"}'),
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", b'{malformed'),
    ],
)
def test_allowlist_rejects_noncanonical_json_before_upstream(client, monkeypatch, method, path, body):
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: pytest.fail("upstream POST called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))

    response = client.request(
        method, path, content=body, headers={**BEARER, "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": "rejected_400"}]


@pytest.mark.parametrize(
    ("method", "path", "limit", "valid_prefix"),
    [
        (
            "POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", 8192,
            b'{"name":"Boundary App","platform":"macos","enforcement":"allowed"}',
        ),
        (
            "PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7", 4096,
            b'{"enforcement":"allowed","notes":"boundary"}',
        ),
    ],
)
def test_allowlist_rejects_exact_upstream_limit_prefix_with_trailing_attack(
    client, monkeypatch, method, path, limit, valid_prefix,
):
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: pytest.fail("upstream POST called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    prefix = valid_prefix + (b" " * (limit - len(valid_prefix)))
    body = prefix + b'{"enforcement":"marked_for_uninstall"}'

    # This is the exact split the old Go LimitReader contract created: the
    # prefix alone is valid and exactly fills its read, while trailing bytes
    # carry a conflicting execution value it would never inspect.
    assert len(prefix) == limit
    assert json.loads(prefix)["enforcement"] == "allowed"

    response = client.request(
        method, path, content=body, headers={**BEARER, "Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": "rejected_413"}]


@pytest.mark.parametrize(
    ("method", "path", "limit", "valid_prefix", "upstream_status"),
    [
        (
            "POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", 8192,
            b'{"name":"Boundary App","platform":"macos","enforcement":"allowed"}', 201,
        ),
        (
            "PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7", 4096,
            b'{"enforcement":"allowed","notes":"boundary"}', 204,
        ),
    ],
)
def test_allowlist_accepts_valid_json_ending_at_exact_route_limit(
    client, monkeypatch, method, path, limit, valid_prefix, upstream_status,
):
    upstream = dashboard.requests.Response()
    upstream.status_code = upstream_status
    upstream.encoding = "utf-8"
    upstream._content = b'{"ok":true}' if upstream_status != 204 else b""
    seen = []

    def forward(_url, **kwargs):
        seen.append(kwargs["data"])
        return upstream

    monkeypatch.setattr(dashboard.http, method.lower(), forward)
    body = valid_prefix + (b" " * (limit - len(valid_prefix)))

    response = client.request(
        method, path, content=body, headers={**BEARER, "Content-Type": "application/json"},
    )

    assert response.status_code == upstream_status
    assert seen == [body]
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": "allowed"}]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist"),
        ("PUT", "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist/7"),
    ],
)
def test_allowlist_uninstall_auth_rbac_and_terminal_audit_order(client, monkeypatch, method, path):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard.http, "post", lambda *_args, **_kwargs: pytest.fail("upstream POST called"))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    body = {"enforcement": "marked_for_uninstall"}

    unauthenticated = client.request(method, path, json=body)
    assert unauthenticated.status_code == 401
    assert _audit_rows(path) == []

    token = dashboard._session_encode("consultant@patched.im", int(time.time()) + 600)
    consultant = client.request(
        method, path, json=body, headers={"Cookie": f"{dashboard.SESSION_COOKIE}={token}"},
    )
    assert consultant.status_code == 403
    assert _audit_rows(path) == [{"method": method, "path": path, "outcome": "denied_rbac"}]

    owner = client.request(method, path, json=body, headers=BEARER)
    assert owner.status_code == 410
    assert owner.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert _audit_rows(path) == [
        {"method": method, "path": path, "outcome": "denied_rbac"},
        {"method": method, "path": path, "outcome": "rejected_410"},
    ]


def test_allowlist_governance_enforcement_still_reaches_upstream(client, monkeypatch):
    upstream = dashboard.requests.Response()
    upstream.status_code = 201
    upstream.encoding = "utf-8"
    upstream._content = b'{"enforcement":"allowed"}'
    seen = {}

    def fake_post(url, **kwargs):
        seen.update(url=url, body=kwargs.get("data"))
        return upstream

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    response = client.post(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist",
        json={"name": "Example", "platform": "macos", "enforcement": "allowed"},
        headers=BEARER,
    )

    assert response.status_code == 201
    assert seen["url"].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist")
    assert b'"enforcement":"allowed"' in seen["body"]
    assert _audit_rows("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist") == [
        {"method": "POST", "path": "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/allowlist", "outcome": "allowed"}
    ]


def test_installed_policy_ui_requires_explicit_platform_identity_contract():
    assert "installedAppPolicyIdentity(a)" in HTML
    assert "findInstalledPolicy(_apoData, a)" in HTML
    assert 'data-app-identity="' in HTML
    assert 'data-team-id="' in HTML
    assert 'data-bundle-id="' in HTML
    assert 'data-winget-id="' in HTML
    assert 'data-identifier-kind="' in HTML
    assert "Identity unresolved" in HTML


def test_installed_clear_policy_can_remove_retained_allowlist_approval():
    manage = HTML[HTML.index("function _scInstalledManage"):HTML.index("function _scCatalogueManage")]
    click = HTML[HTML.index("function _scInstalledAppPolicyClick"):HTML.index("function _scNewAppApproveClick")]
    assert "data-entry-id=" in manage
    assert "target === 'unmanaged' && entryId" in click
    assert "_asStage(app.name, app.platform, entryId, 'remove')" in click


def test_save_refreshes_committed_state_while_restoring_newer_pending_work():
    save = HTML[HTML.index("function _scSave"):HTML.index("function _scDiscard", HTML.index("function _scSave"))]
    assert "var remainingAllowlist = _asPending" in save
    assert "var remainingPolicies = _cpPending" in save
    assert save.index("_scReload();") < save.index("_asPending = remainingAllowlist")
    assert save.index("_scReload();") < save.index("_cpPending = remainingPolicies")


def test_policy_mutations_require_successful_current_tenant_fetch():
    governance = (ROOT / "static/js/console-governance.js").read_text()

    assert "state.status === 'ready'" in governance
    assert "state.tenantId === String(tenantId || '')" in governance
    assert "requestId !== _apoPolicyRequest" in HTML
    assert "String(_consoleState.tenantId || '') !== String(tid)" in HTML
    assert "_apoPolicyFetch = PatchedConsoleGovernance.policyFetchState(tid, 'failed')" in HTML
    assert "if (!_scPolicyMutationsReady(tid)) return Promise.reject" in HTML
    assert "if (!_scRequirePolicyMutationsReady(tid)) return;" in HTML


def test_download_suffix_does_not_exempt_app_ring_mutation_from_auth_or_quarantine(client):
    path = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/app-rings/download"

    unauthenticated = client.patch(path, json={"ring": "pilot"})
    assert unauthenticated.status_code == 401
    with dashboard.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM app_deploy_rings").fetchone()[0] == 0

    owner = client.patch(path, json={"ring": "pilot"}, headers=BEARER)
    assert owner.status_code == 410
    assert owner.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert _audit_rows(path) == [{"method": "PATCH", "path": path, "outcome": "rejected_410"}]
    with dashboard.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM app_deploy_rings").fetchone()[0] == 0


def test_empty_app_ring_identifier_is_quarantined_before_local_write(client):
    path = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/app-rings/"

    assert dashboard._is_legacy_execution_quarantined("PATCH", path)
    response = client.patch(path, json={"ring": "pilot"}, headers=BEARER)

    assert response.status_code == 410
    assert _audit_rows(path) == [{"method": "PATCH", "path": path, "outcome": "rejected_410"}]
    with dashboard.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM app_deploy_rings").fetchone()[0] == 0


def test_quarantine_authenticates_and_audits_consultant_denial_once_before_410(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard.http, "put", lambda *_args, **_kwargs: pytest.fail("upstream PUT called"))
    # A quarantined route that is also in _DESTRUCTIVE_RULES and needs no
    # confirmation header. This used POST .../ring-rollouts until PAT-2299
    # removed that route.
    path = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/ring-devices/device-1"
    assert dashboard._is_legacy_execution_quarantined("PUT", path)
    assert dashboard._is_destructive("PUT", path)
    assert dashboard._confirm_rule("PUT", path) is None

    unauthenticated = client.put(path, json={})
    assert unauthenticated.status_code == 401

    token = dashboard._session_encode("consultant@patched.im", int(time.time()) + 600)
    consultant = client.put(path, json={}, headers={"Cookie": f"{dashboard.SESSION_COOKIE}={token}"})
    assert consultant.status_code == 403
    assert _audit_rows(path) == [{"method": "PUT", "path": path, "outcome": "denied_rbac"}]

    owner = client.put(path, json={}, headers=BEARER)
    assert owner.status_code == 410
    assert owner.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert _audit_rows(path) == [
        {"method": "PUT", "path": path, "outcome": "denied_rbac"},
        {"method": "PUT", "path": path, "outcome": "rejected_410"},
    ]


def test_non_destructive_quarantine_consultant_and_impersonation_denials_audit_once(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    # A quarantined route that is not also in _DESTRUCTIVE_RULES. This used
    # POST /admin/catalogue/refresh until PAT-2249 removed that route.
    path = "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/app-rings/com.example.app"
    assert dashboard._is_legacy_execution_quarantined("PATCH", path)
    assert not dashboard._is_destructive("PATCH", path)
    token = dashboard._session_encode("consultant@patched.im", int(time.time()) + 600)

    consultant = client.patch(path, json={}, headers={"Cookie": f"{dashboard.SESSION_COOKIE}={token}"})
    assert consultant.status_code == 403
    assert _audit_rows(path) == [{"method": "PATCH", "path": path, "outcome": "denied_rbac"}]

    impersonated = client.patch(path, json={}, headers={**BEARER, **_imp_cookie()})
    assert impersonated.status_code == 403
    assert _audit_rows(path) == [
        {"method": "PATCH", "path": path, "outcome": "denied_rbac"},
        {"method": "PATCH", "path": path, "outcome": "rejected_403"},
    ]


def test_scheduler_registers_only_retained_assurance_ticks(client, monkeypatch):
    """Exercise one loop iteration so a retired hosting sync cannot hide behind a renamed helper."""
    labels = []

    class SchedulerIterationComplete(Exception):
        pass

    class FixedClock:
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 8, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(dashboard, "datetime", FixedClock)
    monkeypatch.setattr(dashboard, "_run_tick", lambda label, _fn, _now: labels.append(label))
    monkeypatch.setattr(dashboard.time, "sleep", lambda _seconds: (_ for _ in ()).throw(SchedulerIterationComplete()))

    with pytest.raises(SchedulerIterationComplete):
        dashboard.scheduler_loop()

    assert labels == [
        "cert-digest",
        "stale-digest",
        "report-tick",
        "automation-alerts",
        "nightly-uninstall-checks",
        "rbac-operators",
        "email-delivery-check",
        "deploy-drift-check",
        "maintenance-drift-check",
        "automation-digest",
        "health-alerts",
        "portal-auth-check",
        "calendly-followup",
        "band-drift-check",
    ]


def test_init_db_removes_retired_catalogue_orphan_statuses(client):
    """Covers both PAT-1481 (catalogue-orphan monitor) and PAT-1640 (GitHub
    Actions org budget check) retirements: init_db must delete each retired
    check's check_statuses/check_status_alerts_sent rows so a stale
    degraded/unconfigured result cannot keep appearing in Service Health or
    the daily digest after its producer is gone, while leaving a still-live
    check (deploy_drift) untouched."""
    evaluated_at = datetime(2026, 9, 7, tzinfo=timezone.utc).isoformat()
    with dashboard.get_db() as db:
        for name in (
            "catalogue_orphan",
            "tick_catalogue_orphan_check",
            "tick_catalogue_replies",
            "github-budget-check",
            "tick_github_budget_check",
            "deploy_drift",
        ):
            db.execute(
                "INSERT INTO check_statuses(name, state, reason, evaluated_at) VALUES(?, 'degraded', 'old', ?)",
                (name, evaluated_at),
            )
            db.execute(
                "INSERT INTO check_status_alerts_sent(name, last_state, alerted_at, alert_delivered) VALUES(?, 'degraded', ?, 1)",
                (name, evaluated_at),
            )

    dashboard.init_db()

    with dashboard.get_db() as db:
        status_names = {row["name"] for row in db.execute("SELECT name FROM check_statuses")}
        alert_names = {row["name"] for row in db.execute("SELECT name FROM check_status_alerts_sent")}
    assert status_names == {"deploy_drift"}
    assert alert_names == {"deploy_drift"}


def test_github_budget_check_removed_from_codebase():
    """PAT-1640: the GitHub Actions org budget check was retired outright
    (Andy's call: remove cleanly rather than provision the scoped token it
    needed) rather than left unconfigured forever. Its tick function, helper
    and constants must no longer exist -- GITHUB_TOKEN itself, and its other
    consumer (truth.collect_github_workflow_observation), are untouched."""
    for attr in (
        "_run_github_budget_check_tick",
        "_fetch_all_github_budgets",
        "_github_api_get",
        "_GITHUB_BUDGET_ORG",
        "_GITHUB_BUDGET_SKU",
        "_GITHUB_BUDGET_DEGRADED_PCT",
        "_GITHUB_BUDGET_URGENT_PCT",
        "_GITHUB_BUDGET_MAX_PAGES",
    ):
        assert not hasattr(dashboard, attr), f"{attr} should have been removed with the github-budget-check"

    assert hasattr(dashboard, "GITHUB_TOKEN")


def test_legacy_workflow_truth_entries_keep_retired_and_quarantined_history_distinct():
    manifest = dashboard.truth.load_manifest(ROOT / "truth_manifest.yaml")
    by_id = {entry["id"]: entry for entry in manifest}
    retired_ids = {
        "updater-installomator-upstream-review",
        "updater-daily-vendor-verify",
        "updater-upstream-label-diff",
    }

    assert retired_ids <= by_id.keys()
    for entry_id in retired_ids:
        entry = by_id[entry_id]
        observation = None
        if entry_id == "updater-installomator-upstream-review":
            prerequisite = entry["retired"]["requires_github_commit"]
            assert prerequisite == {
                "repo": "Patched-LTD/updater",
                "sha": "efc910994cdd05c60f946eb0836955f109d2a8fb",
                "branch": "main",
            }
            pending_state, pending_reason = dashboard.truth.evaluate_entry(
                entry,
                None,
                datetime(2026, 9, 8, tzinfo=timezone.utc),
            )
            assert pending_state == "amber"
            assert "retirement pending" in pending_reason
            observation = dashboard.truth.Observation(
                datetime(2026, 9, 8, tzinfo=timezone.utc),
                True,
                "release prerequisite verified",
            )
        state, reason = dashboard.truth.evaluate_entry(
            entry,
            observation,
            datetime(2026, 9, 8, tzinfo=timezone.utc),
        )
        assert state == "retired"
        assert "PAT-14" in reason

    for entry_id in {"updater-mirror-pipeline-windows", "updater-mirror-pipeline"}:
        entry = by_id[entry_id]
        state, reason = dashboard.truth.evaluate_entry(
            entry,
            None,
            datetime(2026, 9, 8, tzinfo=timezone.utc),
        )
        assert state == "quarantined"
        assert "manual" in entry["notes"].lower()
        assert "schedule, trigger or execution UI" in reason


def test_legacy_execution_destinations_are_absent_but_software_governance_is_retained():
    # PAT-1609 gave Devices its own nested <nav class="cwf-subnav"> ahead of
    # Software governance's, so the FIRST </nav> after id="cwf-nav" now
    # closes that nested subnav rather than the whole cwf-nav block -- find
    # the outer nav's own close (the last </nav> before <!-- MAIN -->) instead.
    nav_start = HTML.index('id="cwf-nav"')
    nav_end = HTML.rindex('</nav>', nav_start, HTML.index('<!-- MAIN -->'))
    nav = HTML[nav_start:nav_end]
    assert 'data-tab="patch-deploy"' not in nav
    assert 'data-tab="software-catalogue"' in nav
    assert 'id="nav-catalogue"' not in HTML
    assert 'onclick="_draOpen()"' not in HTML
    assert 'onclick="_bxRemoveOpen(' in HTML
    software_policy = HTML[HTML.index('id="tab-software-catalogue"'):HTML.index('<!-- /#tab-software-catalogue -->')]
    assert 'Uninstall from estate' not in software_policy
    assert 'Require on estate' not in software_policy
    assert 'Approve, no patch' not in software_policy


def test_live_home_and_customer_controls_target_retained_assurance_tabs():
    active_regions = [
        HTML[HTML.index("function _renderHomeInspector"):HTML.index("function _clSortBy")],
        HTML[HTML.index("function _renderClientTable"):HTML.index("function _loadCustomerDetail")],
        HTML[HTML.index("function _ov2Load("):HTML.index("function _ov2LoadRecentActivity")],
        HTML[HTML.index("function _sitRowHtml"):HTML.index("function _sitDetailHtml")],
    ]
    active_controls = "\n".join(active_regions)
    assert "patch-deploy" not in active_controls
    for retained_tab in ("cve-findings", "device-health", "software-catalogue"):
        assert retained_tab in active_controls


def test_stale_governance_links_keep_the_tenant_policy_workflow():
    routing = HTML[HTML.index("function enterTenant"):HTML.index("function _applyTenantTab")]
    assert "PatchedConsoleGovernance.canonicalTenantTab(tab, tenant)" in routing
    assert "PatchedConsoleGovernance.canonicalTenantTab(tab, _consoleState.tenantData)" in routing
    assert "'software-catalogue': 'software-catalogue'" in (ROOT / "static/js/console-governance.js").read_text()
