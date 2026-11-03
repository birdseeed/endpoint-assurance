"""
PAT-2408 (items 3 and 4 of the PAT-2367 boundary matrix): the staff console's
edge.

  3. /docs, /redoc and /openapi.json are not served (they carried no staff
     identity). A development-only switch can turn them back on; production
     needs no variable set.
  4. Tenant ids are canonical lowercase UUIDs at the console's edge, and every
     caller-influenced segment placed into an upstream admin-API path is
     percent-encoded (dot-segments refused), so nothing a caller supplies can
     change which upstream path carries the admin bearer.

Run with: pytest tests/test_pat2408_console_boundary.py -v
"""

import json
import os
import re
import sys
from unittest.mock import MagicMock

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

BEARER = {"Authorization": "Bearer test-key"}
TENANT = "11111111-1111-4111-8111-111111111111"
LETTERED = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"  # has hex letters, so .upper() differs
API = dashboard.PATCHED_API_INTERNAL


@pytest.fixture
def upstream(monkeypatch):
    """Record every request that reaches the upstream session. Replaces the
    session's request method, so nothing leaves the process."""
    calls = []

    def fake(method, url, *args, **kwargs):
        calls.append((method, url))
        r = MagicMock(status_code=200, content=b"{}")
        r.json.return_value = {}
        r.headers = {"content-type": "application/json"}
        return r

    monkeypatch.setattr(dashboard.http, "request", fake)
    return calls


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app, raise_server_exceptions=False) as c:
        yield c


# ── 3. docs routes ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_routes_are_not_served_by_default(client, path):
    assert client.get(path).status_code == 404
    assert client.get(path, headers=BEARER).status_code == 404


def test_openapi_still_builds_in_process():
    schema = dashboard.app.openapi()
    assert schema["paths"], "in-process app.openapi() must keep working"


@pytest.mark.parametrize(
    "env,flag,on",
    [
        ("", "", False),
        ("", "1", False),          # flag alone never enables it (production)
        ("production", "1", False),
        ("dev", "", False),         # dev alone does not enable it
        ("dev", "1", True),
        ("local", "1", True),
    ],
)
def test_docs_urls_only_enabled_by_explicit_dev_setting(env, flag, on):
    urls = dashboard._docs_urls(env, flag)
    if on:
        assert urls == {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}
    else:
        assert urls == {"docs_url": None, "redoc_url": None, "openapi_url": None}


# ── 4a. tenant ids are canonical UUIDs at the edge ─────────────────────────

BAD_TENANT_IDS = [
    "%2e%2e",                       # the reported dot-segment form
    "a%3Fx%3D1",                    # the reported query-injection form
    "..",
    "%2e%2e%2f",
    "%2e%2e%2fadmin",
    "not-a-uuid",
    TENANT + "%2fx",                # valid UUID with a trailing /x
    TENANT + "x",
    LETTERED.upper(),               # upper case is refused, not normalised
    LETTERED.replace("-", ""),      # un-hyphenated
    "%7B" + LETTERED + "%7D",       # braces
    "urn:uuid:" + LETTERED,
    "a%23b",
    "a%2Fb",
    "%20",
]


@pytest.mark.parametrize("bad", BAD_TENANT_IDS)
def test_bad_tenant_id_never_reaches_upstream(client, upstream, bad):
    r = client.get(f"/admin/tenants/{bad}/agent-health", headers=BEARER)
    assert r.status_code in (400, 404, 422), (bad, r.status_code, r.text[:200])
    assert upstream == [], f"upstream was called for {bad!r}: {upstream}"


def test_reported_forms_do_not_change_the_upstream_path(client, upstream):
    client.get("/admin/tenants/%2e%2e/agent-health", headers=BEARER)
    client.get("/admin/tenants/a%3Fx%3D1/agent-health", headers=BEARER)
    assert upstream == []


def test_valid_uuid_still_works(client, upstream):
    r = client.get(f"/admin/tenants/{TENANT}/agent-health", headers=BEARER)
    assert r.status_code == 200
    assert upstream == [("GET", f"{API}/admin/tenants/{TENANT}/agent-health")]


def _tenant_routes():
    out = []
    for route in dashboard.app.routes:
        if isinstance(route, APIRoute) and "{tenant_id}" in route.path:
            out.append(route)
    return out


def test_route_enumeration_finds_tenant_routes():
    # Guard against the enumeration silently matching nothing.
    assert len(_tenant_routes()) > 100


@pytest.mark.parametrize(
    "route", _tenant_routes(), ids=lambda r: f"{sorted(r.methods)[0]} {r.path}"
)
def test_every_tenant_id_route_has_the_shared_validator(route):
    """Allowlist-style guard: a route taking a tenant id path parameter must
    carry the shared validator, so a new route cannot forget it."""
    attached = []

    def walk(dep):
        for d in dep.dependencies:
            attached.append(d.call)
            walk(d)

    walk(route.dependant)
    assert dashboard._require_canonical_tenant_id in attached, (
        f"{sorted(route.methods)} {route.path} takes a tenant id but does not "
        "carry _require_canonical_tenant_id"
    )


def test_no_route_names_a_tenant_id_parameter_differently():
    """Every path parameter that carries a tenant id is called tenant_id, so
    the guard above sees it. A route that names one tid/tenant/etc. must be
    added to this list deliberately."""
    allowed = {"tenant_id"}
    for route in dashboard.app.routes:
        if not isinstance(route, APIRoute):
            continue
        for name in re.findall(r"\{(\w+)\}", route.path):
            if "tenant" in name.lower():
                assert name in allowed, f"{route.path}: parameter {name}"


def _fill(path, tenant):
    return re.sub(r"\{(\w+)(?::\w+)?\}", lambda m: tenant if m.group(1) == "tenant_id" else "x1", path)


@pytest.mark.parametrize(
    "route", _tenant_routes(), ids=lambda r: f"{sorted(r.methods)[0]} {r.path}"
)
def test_non_uuid_tenant_id_is_rejected_on_every_route(client, upstream, route):
    method = sorted(route.methods - {"HEAD", "OPTIONS"})[0]
    path = _fill(route.path, "not-a-uuid")
    r = client.request(
        method, path, headers={**BEARER, "X-Confirm-Resource": "x1"}, json={}
    )
    # 410 is the legacy-execution quarantine, answered by the auth middleware
    # before any handler or upstream call.
    assert r.status_code in (400, 404, 410, 422), (method, path, r.status_code)
    assert upstream == [], f"{method} {path} reached upstream: {upstream}"


# ── 4b. caller-influenced segments are encoded in upstream URLs ─────────────

def test_seg_encodes_reserved_characters():
    assert dashboard._seg("abc-123") == "abc-123"
    assert dashboard._seg("a/b") == "a%2Fb"
    assert dashboard._seg("a?x=1") == "a%3Fx%3D1"
    assert dashboard._seg("a#b") == "a%23b"
    assert dashboard._seg("a b") == "a%20b"
    assert dashboard._seg("%2e%2e") == "%252e%252e"
    assert dashboard._seg("a.b") == "a.b"


@pytest.mark.parametrize("bad", ["", ".", "..", "\x00"])
def test_seg_refuses_empty_and_dot_segments(bad):
    with pytest.raises(dashboard.UnsafePathSegment):
        dashboard._seg(bad)


@pytest.mark.parametrize(
    "raw,encoded",
    [
        ("a%3Fx%3D1", "a%3Fx%3D1"),
        ("a%23b", "a%23b"),
    ],
)
def test_device_id_is_encoded_into_the_upstream_path(client, upstream, raw, encoded):
    r = client.get(f"/admin/devices/{raw}", headers=BEARER)
    assert r.status_code == 200
    assert upstream == [("GET", f"{API}/admin/devices/{encoded}")]


@pytest.mark.parametrize("seg", ["%2e%2e", ".."])
@pytest.mark.parametrize(
    "path",
    [
        "/admin/devices/{s}",
        "/admin/devices/{s}/apps",
        "/admin/automations/{s}/runs",
        f"/admin/tenants/{TENANT}/metering/{{s}}",
        f"/admin/tenants/{TENANT}/allowlist/{{s}}",
        f"/admin/tenants/{TENANT}/webhooks/{{s}}",
        f"/admin/tenants/{TENANT}/devices/{{s}}",
    ],
)
def test_dot_segments_in_other_ids_never_reach_upstream(client, upstream, path, seg):
    r = client.get(path.format(s=seg), headers=BEARER)
    assert upstream == [], upstream
    assert r.status_code in (400, 404, 405, 422)


def test_app_name_with_reserved_characters_is_encoded(client, upstream):
    r = client.get(f"/admin/tenants/{TENANT}/metering/a%3Fb%23c%20d", headers=BEARER)
    assert r.status_code == 200
    assert upstream == [("GET", f"{API}/admin/tenants/{TENANT}/metering/a%3Fb%23c%20d")]


def test_encoded_slash_cannot_add_a_segment(client, upstream):
    """An encoded slash is decoded by the ASGI layer into a different route
    shape, so it never matches the one-segment route; either way nothing is
    forwarded."""
    r = client.get(f"/admin/tenants/{TENANT}/metering/a%2Fb", headers=BEARER)
    assert r.status_code in (400, 404)
    assert upstream == []


def test_session_refuses_dot_segment_urls_even_if_a_caller_forgets(monkeypatch):
    """Defence in depth at the one choke point: a dot-segment in the upstream
    path is refused before the request is made, with the bearer attached."""
    sent = []
    monkeypatch.setattr(
        requests.Session, "request", lambda self, *a, **k: sent.append(a) or MagicMock()
    )
    session = dashboard._ApiSession()
    for url in (
        f"{API}/admin/tenants/../agent-health",
        f"{API}/admin/tenants/%2e%2e/agent-health",
        f"{API}/admin/tenants/%2E%2E/agent-health",
        f"{API}/admin/tenants/./x",
    ):
        resp = session.request("GET", url)
        assert resp.status_code == 400, url
    assert sent == []
    # A normal URL still goes through.
    session.request("GET", f"{API}/admin/tenants/{TENANT}/devices")
    assert len(sent) == 1
